#include "config.h"
#include "internal.h"
#include "descriptor_int.h"
#include <stdint.h>

static size_t witness_weight(const ms_witness *w)
{
    if (w->kind != MS_WITNESS_STACK)
        return SIZE_MAX;
    size_t total = 0;
    for (size_t i = 0; i < w->num_items; i++)
        total += w->items[i].data_len + 1;
    return total;
}

/* Weight delta (sat - dissat) for sorting thresh candidates.
 * Returns INT64_MAX when sat is unavailable/impossible (avoid choosing).
 * Returns INT64_MIN when dissat is unavailable/impossible (prefer choosing). */
static int64_t thresh_weight_delta(const ms_satisfaction *sat, const ms_satisfaction *dsat)
{
    if (sat->witness.kind == MS_WITNESS_IMPOSSIBLE ||
        sat->witness.kind == MS_WITNESS_UNAVAILABLE)
        return INT64_MAX;
    if (dsat->witness.kind == MS_WITNESS_IMPOSSIBLE ||
        dsat->witness.kind == MS_WITNESS_UNAVAILABLE)
        return INT64_MIN;
    return (int64_t)witness_weight(&sat->witness) -
           (int64_t)witness_weight(&dsat->witness);
}

/* Non-malleable sort key: (is_impossible, has_sig, weight_delta) ascending */
static int thresh_cmp_full(size_t ia, size_t ib,
                           const ms_satisfaction *sats,
                           const ms_satisfaction *dissats)
{
    int imp_a = (sats[ia].witness.kind == MS_WITNESS_IMPOSSIBLE) ? 1 : 0;
    int imp_b = (sats[ib].witness.kind == MS_WITNESS_IMPOSSIBLE) ? 1 : 0;
    if (imp_a != imp_b) return imp_a - imp_b;
    int sig_a = sats[ia].has_sig ? 1 : 0;
    int sig_b = sats[ib].has_sig ? 1 : 0;
    if (sig_a != sig_b) return sig_a - sig_b;
    int64_t wa = thresh_weight_delta(&sats[ia], &dissats[ia]);
    int64_t wb = thresh_weight_delta(&sats[ib], &dissats[ib]);
    return (wa > wb) - (wa < wb);
}

/* Malleable sort key: weight_delta only */
static int thresh_cmp_mall(size_t ia, size_t ib,
                           const ms_satisfaction *sats,
                           const ms_satisfaction *dissats)
{
    int64_t wa = thresh_weight_delta(&sats[ia], &dissats[ia]);
    int64_t wb = thresh_weight_delta(&sats[ib], &dissats[ib]);
    return (wa > wb) - (wa < wb);
}

/* Insertion sort on index array (ascending) */
static void thresh_sort(size_t *indices, size_t n,
                        const ms_satisfaction *sats,
                        const ms_satisfaction *dissats, int mall)
{
    for (size_t i = 1; i < n; i++) {
        size_t key = indices[i];
        size_t j = i;
        while (j > 0) {
            int cmp = mall ? thresh_cmp_mall(indices[j - 1], key, sats, dissats)
                           : thresh_cmp_full(indices[j - 1], key, sats, dissats);
            if (cmp <= 0) break;
            indices[j] = indices[j - 1];
            j--;
        }
        indices[j] = key;
    }
}

/*
 * Select the non-malleable minimum-weight satisfaction between a and b.
 * Both a and b are consumed by this call; the caller must not use them
 * afterwards. The caller owns the returned ms_satisfaction and must free
 * it with ms_satisfaction_free() when done.
 */
ms_satisfaction satisfaction_best(ms_satisfaction a, ms_satisfaction b)
{
    ms_satisfaction result;

    /* Impossible short-circuits: if one side is impossible, take the other */
    if (a.witness.kind == MS_WITNESS_IMPOSSIBLE)
        return b;
    if (b.witness.kind == MS_WITNESS_IMPOSSIBLE)
        return a;

    /* Neither has a sig: malleability vector, return unavailable */
    if (!a.has_sig && !b.has_sig) {
        ms_satisfaction_free(&a);
        ms_satisfaction_free(&b);
        ms_satisfaction_init(&result, MS_WITNESS_UNAVAILABLE);
        return result;
    }

    /* Only b has a sig: third party can't malleate a (no sig to remove) */
    if (!a.has_sig) {
        ms_satisfaction_free(&b);
        return a;
    }

    /* Only a has a sig: take b */
    if (!b.has_sig) {
        ms_satisfaction_free(&a);
        return b;
    }

    /* Both have sigs: choose the lighter witness */
    if (witness_weight(&a.witness) <= witness_weight(&b.witness)) {
        ms_satisfaction_free(&b);
        return a;
    }
    ms_satisfaction_free(&a);
    return b;
}

/* Clone a satisfaction, deep-copying witness item data. On OOM returns IMPOSSIBLE. */
ms_satisfaction ms_satisfaction_clone(const ms_satisfaction *src)
{
    ms_satisfaction result;
    ms_satisfaction_init(&result, src->witness.kind);
    result.has_sig = src->has_sig;
    result.absolute_timelock = src->absolute_timelock;
    result.relative_timelock = src->relative_timelock;

    if (src->witness.kind != MS_WITNESS_STACK || !src->witness.num_items)
        return result;

    result.witness.items = wally_malloc(src->witness.num_items * sizeof(ms_witness_item));
    if (!result.witness.items) {
        result.witness.kind = MS_WITNESS_IMPOSSIBLE;
        return result;
    }
    result.witness.items_allocation_len = src->witness.num_items;

    for (size_t i = 0; i < src->witness.num_items; i++) {
        const ms_witness_item *si = &src->witness.items[i];
        unsigned char *data = NULL;
        if (si->data_len) {
            data = wally_malloc(si->data_len);
            if (!data) {
                ms_satisfaction_free(&result);
                ms_satisfaction_init(&result, MS_WITNESS_IMPOSSIBLE);
                return result;
            }
            memcpy(data, si->data, si->data_len);
        }
        result.witness.items[i].data = data;
        result.witness.items[i].data_len = si->data_len;
        result.witness.num_items++;
    }
    return result;
}

/*
 * Concatenate two satisfactions: result has a's items followed by b's items.
 * Consumes a and b. On OOM returns IMPOSSIBLE.
 *
 * Mirrors rust-miniscript Witness::combine(b.stack, a.stack) called as
 * a.concatenate_rev(b) — the caller must pass args in (right, left) order
 * when building a witness where right-fragment items precede left-fragment
 * items (the common case for binary fragments).
 */
static ms_satisfaction satisfaction_concat(ms_satisfaction a, ms_satisfaction b)
{
    bool b_has_sig;
    uint32_t b_abs, b_rel;
    size_t new_count;
    ms_witness_item *new_items;

    if (a.witness.kind == MS_WITNESS_IMPOSSIBLE) {
        ms_satisfaction_free(&b);
        return a;
    }
    if (b.witness.kind == MS_WITNESS_IMPOSSIBLE) {
        ms_satisfaction_free(&a);
        return b;
    }
    if (a.witness.kind == MS_WITNESS_UNAVAILABLE) {
        ms_satisfaction_free(&b);
        return a;
    }
    if (b.witness.kind == MS_WITNESS_UNAVAILABLE) {
        ms_satisfaction_free(&a);
        return b;
    }

    /* Save b's scalar fields before it is freed */
    b_has_sig = b.has_sig;
    b_abs = b.absolute_timelock;
    b_rel = b.relative_timelock;

    new_count = a.witness.num_items + b.witness.num_items;

    if (new_count > a.witness.items_allocation_len) {
        new_items = wally_malloc(new_count * sizeof(ms_witness_item));
        if (!new_items) {
            ms_satisfaction_free(&a);
            ms_satisfaction_free(&b);
            ms_satisfaction_init(&a, MS_WITNESS_IMPOSSIBLE);
            return a;
        }
        if (a.witness.num_items)
            memcpy(new_items, a.witness.items, a.witness.num_items * sizeof(ms_witness_item));
        wally_free(a.witness.items);
        a.witness.items = new_items;
        a.witness.items_allocation_len = new_count;
    }

    /* Transfer ownership of b's item data pointers into a */
    for (size_t i = 0; i < b.witness.num_items; i++)
        a.witness.items[a.witness.num_items + i] = b.witness.items[i];
    a.witness.num_items = new_count;

    /* Prevent double-free: item data is now owned by a */
    b.witness.num_items = 0;
    ms_satisfaction_free(&b);

    a.has_sig |= b_has_sig;
    if (b_abs > a.absolute_timelock)
        a.absolute_timelock = b_abs;
    if (b_rel > a.relative_timelock)
        a.relative_timelock = b_rel;

    return a;
}

/*
 * Malleable minimum: pick the cheaper satisfaction without enforcing
 * non-malleability. Consumes a and b.
 *
 * Mirrors rust-miniscript Satisfaction::minimum_mall.
 */
static ms_satisfaction satisfaction_minimum_mall(ms_satisfaction a, ms_satisfaction b)
{
    bool has_sig;

    if (a.witness.kind == MS_WITNESS_IMPOSSIBLE || a.witness.kind == MS_WITNESS_UNAVAILABLE) {
        ms_satisfaction_free(&a);
        return b;
    }
    if (b.witness.kind == MS_WITNESS_IMPOSSIBLE || b.witness.kind == MS_WITNESS_UNAVAILABLE) {
        ms_satisfaction_free(&b);
        return a;
    }

    /* Both are stacks: take the lighter; has_sig only if both carry a sig */
    has_sig = a.has_sig && b.has_sig;

    if (witness_weight(&a.witness) <= witness_weight(&b.witness)) {
        ms_satisfaction_free(&b);
        a.has_sig = has_sig;
        return a;
    }
    ms_satisfaction_free(&a);
    b.has_sig = has_sig;
    return b;
}

/*
 * Append a single push item to a satisfaction's witness stack.
 * data == NULL / data_len == 0 pushes an empty item (OP_0 / false).
 * Consumes s; on OOM returns IMPOSSIBLE.
 *
 * Used by satisfaction_or_i to attach the IF/ELSE branch selector byte.
 */
static ms_satisfaction satisfaction_push_item(ms_satisfaction s,
                                              const unsigned char *data,
                                              size_t data_len)
{
    size_t n;
    ms_witness_item *new_items;
    unsigned char *item_data;

    if (s.witness.kind != MS_WITNESS_STACK)
        return s;

    n = s.witness.num_items;

    if (n + 1 > s.witness.items_allocation_len) {
        new_items = wally_malloc((n + 1) * sizeof(ms_witness_item));
        if (!new_items) {
            ms_satisfaction_free(&s);
            ms_satisfaction_init(&s, MS_WITNESS_IMPOSSIBLE);
            return s;
        }
        if (n)
            memcpy(new_items, s.witness.items, n * sizeof(ms_witness_item));
        wally_free(s.witness.items);
        s.witness.items = new_items;
        s.witness.items_allocation_len = n + 1;
    }

    item_data = NULL;
    if (data_len) {
        item_data = wally_malloc(data_len);
        if (!item_data) {
            ms_satisfaction_free(&s);
            ms_satisfaction_init(&s, MS_WITNESS_IMPOSSIBLE);
            return s;
        }
        memcpy(item_data, data, data_len);
    }
    s.witness.items[n].data = item_data;
    s.witness.items[n].data_len = data_len;
    s.witness.num_items = n + 1;
    return s;
}

/*
 * or_b(X, Y) satisfaction and dissatisfaction.
 *
 * Script: [X] [Y] BOOLOR
 * Witnesses (right/inner items precede left/outer in array):
 *   sat  = best( concat(r_sat, l_dis), concat(r_dis, l_sat) )
 *   dsat = concat(r_dis, l_dis)
 *
 * Mirrors rust-miniscript Terminal::OrB arm in sat_dissat.rs.
 */
void satisfaction_or_b(ms_satisfaction sat_l, ms_satisfaction dissat_l,
                       ms_satisfaction sat_r, ms_satisfaction dissat_r,
                       ms_satisfaction *sat_out, ms_satisfaction *dissat_out)
{
    ms_satisfaction dissat_l_clone = ms_satisfaction_clone(&dissat_l);
    ms_satisfaction dissat_r_clone = ms_satisfaction_clone(&dissat_r);

    *dissat_out = satisfaction_concat(dissat_r_clone, dissat_l_clone);

    *sat_out = satisfaction_best(
        satisfaction_concat(sat_r, dissat_l),
        satisfaction_concat(dissat_r, sat_l));
}

/*
 * or_c(X, Y) satisfaction and dissatisfaction.
 *
 * Script: [X] NOTIF [Y] ENDIF
 * Witnesses:
 *   sat  = best( sat_l, concat(r_sat, l_dis) )
 *   dsat = IMPOSSIBLE (or_c has no valid dissatisfaction)
 *
 * Mirrors rust-miniscript Terminal::OrC arm in sat_dissat.rs.
 */
void satisfaction_or_c(ms_satisfaction sat_l, ms_satisfaction dissat_l,
                       ms_satisfaction sat_r, ms_satisfaction dissat_r,
                       ms_satisfaction *sat_out, ms_satisfaction *dissat_out)
{
    ms_satisfaction_free(&dissat_r);
    ms_satisfaction_init(dissat_out, MS_WITNESS_IMPOSSIBLE);

    *sat_out = satisfaction_best(sat_l, satisfaction_concat(sat_r, dissat_l));
}

/*
 * or_d(X, Y) satisfaction and dissatisfaction.
 *
 * Script: [X] IFDUP NOTIF [Y] ENDIF
 * Witnesses:
 *   sat  = best( sat_l, concat(r_sat, l_dis) )
 *   dsat = concat(r_dis, l_dis)
 *
 * Mirrors rust-miniscript Terminal::OrD arm in sat_dissat.rs.
 */
void satisfaction_or_d(ms_satisfaction sat_l, ms_satisfaction dissat_l,
                       ms_satisfaction sat_r, ms_satisfaction dissat_r,
                       ms_satisfaction *sat_out, ms_satisfaction *dissat_out)
{
    ms_satisfaction dissat_l_clone = ms_satisfaction_clone(&dissat_l);

    *dissat_out = satisfaction_concat(dissat_r, dissat_l_clone);

    *sat_out = satisfaction_best(sat_l, satisfaction_concat(sat_r, dissat_l));
}

/*
 * or_i(X, Y) satisfaction and dissatisfaction.
 *
 * Script: IF [X] ELSE [Y] ENDIF
 * The branch selector byte (0x01 = left / empty = right) is appended to the
 * sub-satisfaction and sits on top of the witness stack when the script runs.
 * Witnesses:
 *   sat  = best( sat_l ++ [0x01], sat_r ++ [] )
 *   dsat = minimum_mall( dissat_l ++ [0x01], dissat_r ++ [] )
 *
 * Mirrors rust-miniscript Terminal::OrI arm in sat_dissat.rs.
 */
void satisfaction_or_i(ms_satisfaction sat_l, ms_satisfaction dissat_l,
                       ms_satisfaction sat_r, ms_satisfaction dissat_r,
                       ms_satisfaction *sat_out, ms_satisfaction *dissat_out)
{
    static const unsigned char push_1_data[] = {0x01};

    *sat_out = satisfaction_best(
        satisfaction_push_item(sat_l, push_1_data, 1),
        satisfaction_push_item(sat_r, NULL, 0));

    *dissat_out = satisfaction_minimum_mall(
        satisfaction_push_item(dissat_l, push_1_data, 1),
        satisfaction_push_item(dissat_r, NULL, 0));
}

/*
 * andor(X, Y, Z) satisfaction and dissatisfaction.
 *
 * Script: [X] NOTIF [Z] ELSE [Y] ENDIF
 * Witnesses:
 *   sat  = best( concat(sat_y, sat_x), concat(sat_z, dissat_x) )
 *   dsat = concat(dissat_z, dissat_x)
 *
 * (inner/Y-Z items precede outer/X in array)
 *
 * dissat_y is unused: the Y branch is only reached when X is satisfied,
 * so the overall dissatisfaction always takes the Z path (dissat_x + dissat_z).
 *
 * Mirrors rust-miniscript Terminal::AndOr arm in sat_dissat.rs.
 */
void satisfaction_andor(ms_satisfaction sat_x, ms_satisfaction dissat_x,
                        ms_satisfaction sat_y, ms_satisfaction dissat_y,
                        ms_satisfaction sat_z, ms_satisfaction dissat_z,
                        ms_satisfaction *sat_out, ms_satisfaction *dissat_out)
{
    ms_satisfaction dissat_x_clone = ms_satisfaction_clone(&dissat_x);

    ms_satisfaction_free(&dissat_y);

    *dissat_out = satisfaction_concat(dissat_z, dissat_x_clone);

    *sat_out = satisfaction_best(
        satisfaction_concat(sat_y, sat_x),
        satisfaction_concat(sat_z, dissat_x));
}

/*
 * thresh(k, X1, ..., Xn) malleable satisfaction and dissatisfaction.
 *
 * Consumes every element in sats[] and dissats[].
 * Mirrors rust-miniscript Satisfaction::thresh_mall.
 */
void satisfaction_thresh_mall(size_t k, size_t n,
                              ms_satisfaction *sats,
                              ms_satisfaction *dissats,
                              ms_satisfaction *sat_out,
                              ms_satisfaction *dissat_out)
{
    size_t i;

    /* 1. Compute dissat_out from clones of original dissats */
    ms_satisfaction dsat_acc;
    ms_satisfaction_init(&dsat_acc, MS_WITNESS_STACK);
    for (i = 0; i < n; i++) {
        ms_satisfaction cl = ms_satisfaction_clone(&dissats[i]);
        dsat_acc = satisfaction_concat(cl, dsat_acc);
    }
    *dissat_out = dsat_acc;

    /* 2. Build and sort index array by weight delta (malleable) */
    size_t *indices = wally_malloc(n * sizeof(size_t));
    if (!indices) {
        for (i = 0; i < n; i++) {
            ms_satisfaction_free(&sats[i]);
            ms_satisfaction_free(&dissats[i]);
        }
        ms_satisfaction_init(sat_out, MS_WITNESS_IMPOSSIBLE);
        return;
    }
    for (i = 0; i < n; i++) indices[i] = i;
    thresh_sort(indices, n, sats, dissats, 1);

    /* 3. Swap first k: dissats[indices[i]] gets the chosen sat */
    for (i = 0; i < k; i++) {
        ms_satisfaction tmp = dissats[indices[i]];
        dissats[indices[i]] = sats[indices[i]];
        sats[indices[i]] = tmp;
    }

    /* 4. Free the leftover sats[] entries (unchosen sats + swapped-out dissats) */
    for (i = 0; i < n; i++) ms_satisfaction_free(&sats[i]);

    /* 5. Fold dissats[] (now ret_stack) for sat_out */
    ms_satisfaction sat_acc;
    ms_satisfaction_init(&sat_acc, MS_WITNESS_STACK);
    for (i = 0; i < n; i++)
        sat_acc = satisfaction_concat(dissats[i], sat_acc);
    *sat_out = sat_acc;

    wally_free(indices);
}

/*
 * thresh(k, X1, ..., Xn) non-malleable satisfaction and dissatisfaction.
 *
 * Consumes every element in sats[] and dissats[].
 * Mirrors rust-miniscript Satisfaction::thresh.
 */
void satisfaction_thresh(size_t k, size_t n,
                         ms_satisfaction *sats,
                         ms_satisfaction *dissats,
                         ms_satisfaction *sat_out,
                         ms_satisfaction *dissat_out)
{
    size_t i;

    /* 1. Compute dissat_out from clones of original dissats */
    ms_satisfaction dsat_acc;
    ms_satisfaction_init(&dsat_acc, MS_WITNESS_STACK);
    for (i = 0; i < n; i++) {
        ms_satisfaction cl = ms_satisfaction_clone(&dissats[i]);
        dsat_acc = satisfaction_concat(cl, dsat_acc);
    }
    *dissat_out = dsat_acc;

    /* 2. Build and sort index array with non-malleable key */
    size_t *indices = wally_malloc(n * sizeof(size_t));
    if (!indices) {
        for (i = 0; i < n; i++) {
            ms_satisfaction_free(&sats[i]);
            ms_satisfaction_free(&dissats[i]);
        }
        ms_satisfaction_init(sat_out, MS_WITNESS_IMPOSSIBLE);
        return;
    }
    for (i = 0; i < n; i++) indices[i] = i;
    thresh_sort(indices, n, sats, dissats, 0);

    /* 3. Swap first k: dissats[indices[i]] gets the chosen sat */
    for (i = 0; i < k; i++) {
        ms_satisfaction tmp = dissats[indices[i]];
        dissats[indices[i]] = sats[indices[i]];
        sats[indices[i]] = tmp;
    }

    /* 4. Malleability check A: if k-th chosen's original dissat is Impossible,
     *    we could not find k non-impossible satisfactions — overall impossible. */
    if (sats[indices[k - 1]].witness.kind == MS_WITNESS_IMPOSSIBLE) {
        for (i = 0; i < n; i++) {
            ms_satisfaction_free(&sats[i]);
            ms_satisfaction_free(&dissats[i]);
        }
        wally_free(indices);
        ms_satisfaction_init(sat_out, MS_WITNESS_IMPOSSIBLE);
        return;
    }

    /* 5. Malleability check B: if the first unchosen element's original sat is
     *    not impossible and has no sig, a third party can malleate — unavailable. */
    if (k < n &&
        sats[indices[k]].witness.kind != MS_WITNESS_IMPOSSIBLE &&
        !sats[indices[k]].has_sig) {
        for (i = 0; i < n; i++) {
            ms_satisfaction_free(&sats[i]);
            ms_satisfaction_free(&dissats[i]);
        }
        wally_free(indices);
        ms_satisfaction_init(sat_out, MS_WITNESS_UNAVAILABLE);
        return;
    }

    /* 6. Free leftover sats[], fold dissats[] (ret_stack) for sat_out */
    for (i = 0; i < n; i++) ms_satisfaction_free(&sats[i]);
    ms_satisfaction sat_acc;
    ms_satisfaction_init(&sat_acc, MS_WITNESS_STACK);
    for (i = 0; i < n; i++)
        sat_acc = satisfaction_concat(dissats[i], sat_acc);
    *sat_out = sat_acc;

    wally_free(indices);
}

typedef struct {
    ms_satisfaction sat;
    ms_satisfaction dissat;
} sat_dissat_t;

static size_t ms_node_count(const ms_node *node)
{
    size_t n = 0;
    for (; node; node = node->next)
        n += 1 + ms_node_count(node->child);
    return n;
}

typedef struct {
    const ms_node *node;
    const ms_node *cur_child;
} trav_frame_t;

void satisfy_node(const ms_node *node, const ms_satisfier *stfr,
                  bool malleable,
                  ms_satisfaction *sat_out, ms_satisfaction *dissat_out)
{
    size_t cap = ms_node_count(node);
    if (!cap) {
        ms_satisfaction_init(sat_out,    MS_WITNESS_IMPOSSIBLE);
        ms_satisfaction_init(dissat_out, MS_WITNESS_IMPOSSIBLE);
        return;
    }

    trav_frame_t  *trav   = wally_malloc(cap * sizeof(trav_frame_t));
    sat_dissat_t  *result = wally_malloc(cap * sizeof(sat_dissat_t));
    if (!trav || !result) {
        wally_free(trav); wally_free(result);
        ms_satisfaction_init(sat_out,    MS_WITNESS_IMPOSSIBLE);
        ms_satisfaction_init(dissat_out, MS_WITNESS_IMPOSSIBLE);
        return;
    }

    size_t tsp = 0;
    size_t rsp = 0;

    trav[tsp++] = (trav_frame_t){ node, node->child };

    while (tsp > 0) {
        trav_frame_t *top = &trav[tsp - 1];

        if (top->cur_child) {
            const ms_node *child = top->cur_child;
            top->cur_child = child->next;
            trav[tsp++] = (trav_frame_t){ child, child->child };
            continue;
        }

        const ms_node *n = top->node;
        tsp--;

        sat_dissat_t entry;
        ms_satisfaction_init(&entry.sat,    MS_WITNESS_IMPOSSIBLE);
        ms_satisfaction_init(&entry.dissat, MS_WITNESS_IMPOSSIBLE);

        static const unsigned char push_1[] = {0x01};

        switch (n->kind) {

        case KIND_MINISCRIPT_JUST_0:
            ms_satisfaction_free(&entry.sat);
            ms_satisfaction_free(&entry.dissat);
            ms_satisfaction_init(&entry.sat,    MS_WITNESS_IMPOSSIBLE);
            ms_satisfaction_init(&entry.dissat, MS_WITNESS_STACK);
            break;

        case KIND_MINISCRIPT_JUST_1:
            ms_satisfaction_free(&entry.sat);
            ms_satisfaction_free(&entry.dissat);
            ms_satisfaction_init(&entry.sat,    MS_WITNESS_STACK);
            ms_satisfaction_init(&entry.dissat, MS_WITNESS_IMPOSSIBLE);
            break;

        case KIND_MINISCRIPT_PK_K:
        case KIND_MINISCRIPT_PK_H:
        case KIND_MINISCRIPT_PK:
        case KIND_MINISCRIPT_PKH:
        case KIND_MINISCRIPT_OLDER:
        case KIND_MINISCRIPT_AFTER:
        case KIND_MINISCRIPT_SHA256:
        case KIND_MINISCRIPT_HASH256:
        case KIND_MINISCRIPT_RIPEMD160:
        case KIND_MINISCRIPT_HASH160:
        case KIND_MINISCRIPT_MULTI:
        case KIND_MINISCRIPT_MULTI_A:
        case KIND_MINISCRIPT_MULTI_A_S:
            ms_satisfaction_free(&entry.sat);
            ms_satisfaction_free(&entry.dissat);
            ms_satisfaction_init(&entry.sat,    MS_WITNESS_UNAVAILABLE);
            ms_satisfaction_init(&entry.dissat, MS_WITNESS_UNAVAILABLE);
            break;

        case KIND_MINISCRIPT_ALT:
        case KIND_MINISCRIPT_SWAP:
        case KIND_MINISCRIPT_CHECK:
        case KIND_MINISCRIPT_ZERO_NOT_EQUAL: {
            sat_dissat_t child = result[--rsp];
            ms_satisfaction_free(&entry.sat);
            ms_satisfaction_free(&entry.dissat);
            entry = child;
            break;
        }

        case KIND_MINISCRIPT_DUP_IF: {
            sat_dissat_t child = result[--rsp];
            ms_satisfaction_free(&entry.sat);
            ms_satisfaction_free(&entry.dissat);
            ms_satisfaction_free(&child.dissat);
            ms_satisfaction_init(&child.dissat, MS_WITNESS_STACK);
            entry.dissat = satisfaction_push_item(child.dissat, NULL, 0);
            entry.sat    = satisfaction_push_item(child.sat, push_1, 1);
            break;
        }

        case KIND_MINISCRIPT_VERIFY: {
            sat_dissat_t child = result[--rsp];
            ms_satisfaction_free(&entry.sat);
            ms_satisfaction_free(&entry.dissat);
            ms_satisfaction_free(&child.dissat);
            ms_satisfaction_init(&entry.dissat, MS_WITNESS_IMPOSSIBLE);
            entry.sat = child.sat;
            break;
        }

        case KIND_MINISCRIPT_NON_ZERO: {
            sat_dissat_t child = result[--rsp];
            ms_satisfaction_free(&entry.sat);
            ms_satisfaction_free(&entry.dissat);
            ms_satisfaction_free(&child.dissat);
            ms_satisfaction_init(&entry.dissat, MS_WITNESS_IMPOSSIBLE);
            entry.sat = child.sat;
            break;
        }

        case KIND_MINISCRIPT_AND_B: {
            sat_dissat_t r = result[--rsp];
            sat_dissat_t l = result[--rsp];
            ms_satisfaction_free(&entry.sat);
            ms_satisfaction_free(&entry.dissat);
            entry.sat    = satisfaction_concat(r.sat,    l.sat);
            entry.dissat = satisfaction_concat(r.dissat, l.dissat);
            break;
        }

        case KIND_MINISCRIPT_AND_V: {
            sat_dissat_t r = result[--rsp];
            sat_dissat_t l = result[--rsp];
            ms_satisfaction l_sat_clone = ms_satisfaction_clone(&l.sat);
            ms_satisfaction_free(&l.dissat);
            ms_satisfaction_free(&entry.sat);
            ms_satisfaction_free(&entry.dissat);
            entry.sat    = satisfaction_concat(r.sat,    l.sat);
            entry.dissat = satisfaction_concat(r.dissat, l_sat_clone);
            break;
        }

        case KIND_MINISCRIPT_AND_N: {
            sat_dissat_t y = result[--rsp];
            sat_dissat_t x = result[--rsp];
            ms_satisfaction_free(&y.dissat);
            ms_satisfaction_free(&entry.sat);
            ms_satisfaction_free(&entry.dissat);
            entry.sat    = satisfaction_concat(y.sat, x.sat);
            entry.dissat = x.dissat;
            break;
        }

        case KIND_MINISCRIPT_ANDOR: {
            sat_dissat_t z = result[--rsp];
            sat_dissat_t y = result[--rsp];
            sat_dissat_t x = result[--rsp];
            ms_satisfaction_free(&entry.sat);
            ms_satisfaction_free(&entry.dissat);
            satisfaction_andor(x.sat, x.dissat, y.sat, y.dissat,
                               z.sat, z.dissat,
                               &entry.sat, &entry.dissat);
            break;
        }

        case KIND_MINISCRIPT_OR_B: {
            sat_dissat_t r = result[--rsp];
            sat_dissat_t l = result[--rsp];
            ms_satisfaction_free(&entry.sat);
            ms_satisfaction_free(&entry.dissat);
            satisfaction_or_b(l.sat, l.dissat, r.sat, r.dissat,
                              &entry.sat, &entry.dissat);
            break;
        }

        case KIND_MINISCRIPT_OR_C: {
            sat_dissat_t r = result[--rsp];
            sat_dissat_t l = result[--rsp];
            ms_satisfaction_free(&entry.sat);
            ms_satisfaction_free(&entry.dissat);
            satisfaction_or_c(l.sat, l.dissat, r.sat, r.dissat,
                              &entry.sat, &entry.dissat);
            break;
        }

        case KIND_MINISCRIPT_OR_D: {
            sat_dissat_t r = result[--rsp];
            sat_dissat_t l = result[--rsp];
            ms_satisfaction_free(&entry.sat);
            ms_satisfaction_free(&entry.dissat);
            satisfaction_or_d(l.sat, l.dissat, r.sat, r.dissat,
                              &entry.sat, &entry.dissat);
            break;
        }

        case KIND_MINISCRIPT_OR_I: {
            sat_dissat_t r = result[--rsp];
            sat_dissat_t l = result[--rsp];
            ms_satisfaction_free(&entry.sat);
            ms_satisfaction_free(&entry.dissat);
            satisfaction_or_i(l.sat, l.dissat, r.sat, r.dissat,
                              &entry.sat, &entry.dissat);
            break;
        }

        case KIND_MINISCRIPT_THRESH: {
            size_t child_n = 0;
            for (const ms_node *c = n->child; c; c = c->next) child_n++;
            size_t k = (size_t)n->number;

            ms_satisfaction *sats    = wally_malloc(child_n * sizeof(ms_satisfaction));
            ms_satisfaction *dissats = wally_malloc(child_n * sizeof(ms_satisfaction));
            if (!sats || !dissats) {
                wally_free(sats); wally_free(dissats);
                for (size_t i = 0; i < child_n; i++) {
                    rsp--;
                    ms_satisfaction_free(&result[rsp].sat);
                    ms_satisfaction_free(&result[rsp].dissat);
                }
                ms_satisfaction_free(&entry.sat);
                ms_satisfaction_free(&entry.dissat);
                ms_satisfaction_init(&entry.sat,    MS_WITNESS_IMPOSSIBLE);
                ms_satisfaction_init(&entry.dissat, MS_WITNESS_IMPOSSIBLE);
                break;
            }
            for (size_t i = child_n; i-- > 0; ) {
                sat_dissat_t sd = result[--rsp];
                sats[i]    = sd.sat;
                dissats[i] = sd.dissat;
            }
            ms_satisfaction_free(&entry.sat);
            ms_satisfaction_free(&entry.dissat);
            if (malleable)
                satisfaction_thresh_mall(k, child_n, sats, dissats, &entry.sat, &entry.dissat);
            else
                satisfaction_thresh(k, child_n, sats, dissats, &entry.sat, &entry.dissat);
            wally_free(sats);
            wally_free(dissats);
            break;
        }

        default:
            break;
        }

        result[rsp++] = entry;
    }

    *sat_out    = result[0].sat;
    *dissat_out = result[0].dissat;

    wally_free(trav);
    wally_free(result);
}
