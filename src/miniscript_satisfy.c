#include "config.h"
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
