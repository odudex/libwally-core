#include "config.h"
#include "miniscript_decode.h"
#include <include/wally_core.h>
#include <include/wally_script.h>

int tokenize_script(const unsigned char *script, size_t script_len,
                    token_t *tokens, size_t max_tokens, size_t *out_count)
{
    size_t i, n = 0;

    for (i = 0; i < script_len; ++i) {
        unsigned char op = script[i];

        /* Push-data and numeric-push bytes — handled in phases 7-8 */
        if (op == OP_0 || op == OP_1NEGATE)
            return WALLY_EINVAL;
        if (op >= 0x01 && op <= OP_PUSHDATA4)
            return WALLY_EINVAL;
        if (op >= OP_1 && op <= OP_16)
            return WALLY_EINVAL;

        switch (op) {
        case OP_BOOLAND:
            if (n >= max_tokens) return WALLY_EINVAL;
            tokens[n++].kind = TK_BOOL_AND;
            break;
        case OP_BOOLOR:
            if (n >= max_tokens) return WALLY_EINVAL;
            tokens[n++].kind = TK_BOOL_OR;
            break;
        case OP_ADD:
            if (n >= max_tokens) return WALLY_EINVAL;
            tokens[n++].kind = TK_ADD;
            break;
        case OP_EQUAL:
            if (n >= max_tokens) return WALLY_EINVAL;
            tokens[n++].kind = TK_EQUAL;
            break;
        case OP_EQUALVERIFY:
            if (n >= max_tokens) return WALLY_EINVAL;
            tokens[n++].kind = TK_EQUAL;
            if (n >= max_tokens) return WALLY_EINVAL;
            tokens[n++].kind = TK_VERIFY;
            break;
        case OP_NUMEQUAL:
            if (n >= max_tokens) return WALLY_EINVAL;
            tokens[n++].kind = TK_NUM_EQUAL;
            break;
        case OP_NUMEQUALVERIFY:
            if (n >= max_tokens) return WALLY_EINVAL;
            tokens[n++].kind = TK_NUM_EQUAL;
            if (n >= max_tokens) return WALLY_EINVAL;
            tokens[n++].kind = TK_VERIFY;
            break;
        case OP_CHECKSIG:
            if (n >= max_tokens) return WALLY_EINVAL;
            tokens[n++].kind = TK_CHECK_SIG;
            break;
        case OP_CHECKSIGVERIFY:
            if (n >= max_tokens) return WALLY_EINVAL;
            tokens[n++].kind = TK_CHECK_SIG;
            if (n >= max_tokens) return WALLY_EINVAL;
            tokens[n++].kind = TK_VERIFY;
            break;
        case OP_CHECKSIGADD:
            if (n >= max_tokens) return WALLY_EINVAL;
            tokens[n++].kind = TK_CHECK_SIG_ADD;
            break;
        case OP_CHECKMULTISIG:
            if (n >= max_tokens) return WALLY_EINVAL;
            tokens[n++].kind = TK_CHECK_MULTI_SIG;
            break;
        case OP_CHECKMULTISIGVERIFY:
            if (n >= max_tokens) return WALLY_EINVAL;
            tokens[n++].kind = TK_CHECK_MULTI_SIG;
            if (n >= max_tokens) return WALLY_EINVAL;
            tokens[n++].kind = TK_VERIFY;
            break;
        case OP_CHECKSEQUENCEVERIFY:
            if (n >= max_tokens) return WALLY_EINVAL;
            tokens[n++].kind = TK_CHECK_SEQUENCE_VERIFY;
            break;
        case OP_CHECKLOCKTIMEVERIFY:
            if (n >= max_tokens) return WALLY_EINVAL;
            tokens[n++].kind = TK_CHECK_LOCK_TIME_VERIFY;
            break;
        case OP_FROMALTSTACK:
            if (n >= max_tokens) return WALLY_EINVAL;
            tokens[n++].kind = TK_FROM_ALT_STACK;
            break;
        case OP_TOALTSTACK:
            if (n >= max_tokens) return WALLY_EINVAL;
            tokens[n++].kind = TK_TO_ALT_STACK;
            break;
        case OP_DROP:
            if (n >= max_tokens) return WALLY_EINVAL;
            tokens[n++].kind = TK_DROP;
            break;
        case OP_DUP:
            if (n >= max_tokens) return WALLY_EINVAL;
            tokens[n++].kind = TK_DUP;
            break;
        case OP_IF:
            if (n >= max_tokens) return WALLY_EINVAL;
            tokens[n++].kind = TK_IF;
            break;
        case OP_IFDUP:
            if (n >= max_tokens) return WALLY_EINVAL;
            tokens[n++].kind = TK_IF_DUP;
            break;
        case OP_NOTIF:
            if (n >= max_tokens) return WALLY_EINVAL;
            tokens[n++].kind = TK_NOT_IF;
            break;
        case OP_ELSE:
            if (n >= max_tokens) return WALLY_EINVAL;
            tokens[n++].kind = TK_ELSE;
            break;
        case OP_ENDIF:
            if (n >= max_tokens) return WALLY_EINVAL;
            tokens[n++].kind = TK_END_IF;
            break;
        case OP_0NOTEQUAL:
            if (n >= max_tokens) return WALLY_EINVAL;
            tokens[n++].kind = TK_ZERO_NOT_EQUAL;
            break;
        case OP_SIZE:
            if (n >= max_tokens) return WALLY_EINVAL;
            tokens[n++].kind = TK_SIZE;
            break;
        case OP_SWAP:
            if (n >= max_tokens) return WALLY_EINVAL;
            tokens[n++].kind = TK_SWAP;
            break;
        case OP_VERIFY:
            /* NonMinimalVerify: standalone VERIFY after Equal/CheckSig/CheckMultiSig
             * is non-minimal — the combined opcode should have been used instead */
            if (n > 0) {
                tk_kind last = tokens[n - 1].kind;
                if (last == TK_EQUAL || last == TK_CHECK_SIG || last == TK_CHECK_MULTI_SIG)
                    return WALLY_EINVAL;
            }
            if (n >= max_tokens) return WALLY_EINVAL;
            tokens[n++].kind = TK_VERIFY;
            break;
        case OP_RIPEMD160:
            if (n >= max_tokens) return WALLY_EINVAL;
            tokens[n++].kind = TK_RIPEMD160;
            break;
        case OP_HASH160:
            if (n >= max_tokens) return WALLY_EINVAL;
            tokens[n++].kind = TK_HASH160;
            break;
        case OP_SHA256:
            if (n >= max_tokens) return WALLY_EINVAL;
            tokens[n++].kind = TK_SHA256;
            break;
        case OP_HASH256:
            if (n >= max_tokens) return WALLY_EINVAL;
            tokens[n++].kind = TK_HASH256;
            break;
        default:
            return WALLY_EINVAL;
        }
    }

    *out_count = n;
    return WALLY_OK;
}
