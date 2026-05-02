#ifndef LIBWALLY_MINISCRIPT_DECODE_H
#define LIBWALLY_MINISCRIPT_DECODE_H

#include "config.h"
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    /* Opcode-only tokens */
    TK_BOOL_AND,
    TK_BOOL_OR,
    TK_ADD,
    TK_EQUAL,
    TK_NUM_EQUAL,
    TK_CHECK_SIG,
    TK_CHECK_SIG_ADD,
    TK_CHECK_MULTI_SIG,
    TK_CHECK_SEQUENCE_VERIFY,
    TK_CHECK_LOCK_TIME_VERIFY,
    TK_FROM_ALT_STACK,
    TK_TO_ALT_STACK,
    TK_DROP,
    TK_DUP,
    TK_IF,
    TK_IF_DUP,
    TK_NOT_IF,
    TK_ELSE,
    TK_END_IF,
    TK_ZERO_NOT_EQUAL,
    TK_SIZE,
    TK_SWAP,
    TK_VERIFY,
    TK_RIPEMD160,
    TK_HASH160,
    TK_SHA256,
    TK_HASH256,
    /* Data-carrying tokens */
    TK_NUM,      /* uint32_t */
    TK_HASH20,   /* 20-byte digest (RIPEMD160 / HASH160) */
    TK_BYTES32,  /* 32-byte digest (SHA256 / HASH256) or KEY32 */
    TK_BYTES33,  /* 33-byte compressed pubkey */
    TK_BYTES65,  /* 65-byte uncompressed pubkey */
} tk_kind;

typedef struct token_t {
    tk_kind kind;
    union {
        uint32_t num;           /* TK_NUM */
        uint8_t  hash20[20];   /* TK_HASH20 */
        uint8_t  bytes32[32];  /* TK_BYTES32 */
        uint8_t  bytes33[33];  /* TK_BYTES33 */
        uint8_t  bytes65[65];  /* TK_BYTES65 */
    } data;
} token_t;

/* Tokenize a Script into an array of tokens.
 * tokens must point to a caller-allocated array of at least max_tokens elements.
 * On success *out_count is set to the number of tokens written.
 */
int tokenize_script(const unsigned char *script, size_t script_len,
                    token_t *tokens, size_t max_tokens,
                    size_t *out_count);

#ifdef __cplusplus
}
#endif

#endif /* LIBWALLY_MINISCRIPT_DECODE_H */
