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
static ms_satisfaction ms_satisfaction_clone(const ms_satisfaction *src)
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
