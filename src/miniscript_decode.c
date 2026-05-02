#include "config.h"
#include "miniscript_decode.h"
#include <include/wally_core.h>
#include <include/wally_script.h>
#include <string.h>
#include "script_int.h"

int tokenize_script(const unsigned char *script, size_t script_len,
                    token_t *tokens, size_t max_tokens, size_t *out_count)
{
    size_t i, n = 0;

    for (i = 0; i < script_len; ++i) {
        unsigned char op = script[i];

        if (op == OP_0) {
            if (n >= max_tokens) return WALLY_EINVAL;
            tokens[n].kind = TK_NUM;
            tokens[n++].data.num = 0;
            continue;
        }
        if (op == OP_1NEGATE)
            return WALLY_EINVAL;
        if (op >= OP_1 && op <= OP_16) {
            if (n >= max_tokens) return WALLY_EINVAL;
            tokens[n].kind = TK_NUM;
            tokens[n++].data.num = (uint32_t)(op - OP_1 + 1);
            continue;
        }
        if (op >= 0x01 && op <= OP_PUSHDATA4) {
            size_t data_len;
            const unsigned char *data;

            if (op < OP_PUSHDATA1) {
                data_len = op;
                if (i + 1 + data_len > script_len) return WALLY_EINVAL;
                data = script + i + 1;
                i += data_len;
            } else if (op == OP_PUSHDATA1) {
                if (i + 1 >= script_len) return WALLY_EINVAL;
                data_len = script[i + 1];
                if (i + 2 + data_len > script_len) return WALLY_EINVAL;
                data = script + i + 2;
                i += 1 + data_len;
            } else if (op == OP_PUSHDATA2) {
                if (i + 2 >= script_len) return WALLY_EINVAL;
                data_len = (size_t)script[i + 1] | ((size_t)script[i + 2] << 8);
                if (i + 3 + data_len > script_len) return WALLY_EINVAL;
                data = script + i + 3;
                i += 2 + data_len;
            } else { /* OP_PUSHDATA4 */
                if (i + 4 >= script_len) return WALLY_EINVAL;
                data_len = (size_t)script[i + 1] | ((size_t)script[i + 2] << 8) |
                           ((size_t)script[i + 3] << 16) | ((size_t)script[i + 4] << 24);
                if (i + 5 + data_len > script_len) return WALLY_EINVAL;
                data = script + i + 5;
                i += 4 + data_len;
            }

            if (n >= max_tokens) return WALLY_EINVAL;
            if (data_len == 20) {
                tokens[n].kind = TK_HASH20;
                memcpy(tokens[n].data.hash20, data, 20);
            } else if (data_len == 32) {
                tokens[n].kind = TK_BYTES32;
                memcpy(tokens[n].data.bytes32, data, 32);
            } else if (data_len == 33) {
                tokens[n].kind = TK_BYTES33;
                memcpy(tokens[n].data.bytes33, data, 33);
            } else if (data_len == 65) {
                tokens[n].kind = TK_BYTES65;
                memcpy(tokens[n].data.bytes65, data, 65);
            } else if (data_len >= 1 && data_len <= 4) {
                /* Script number (CScriptNum): 1–4 byte little-endian with sign bit */
                unsigned char sbuf[5];
                int64_t n64;
                sbuf[0] = (unsigned char)data_len;
                memcpy(sbuf + 1, data, data_len);
                if (scriptint_from_bytes(sbuf, data_len + 1, &n64) != WALLY_OK)
                    return WALLY_EINVAL;
                if (n64 < 0 || n64 > UINT32_MAX)
                    return WALLY_EINVAL;
                tokens[n].kind = TK_NUM;
                tokens[n].data.num = (uint32_t)n64;
            } else {
                return WALLY_EINVAL;
            }
            n++;
            continue;
        }

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
