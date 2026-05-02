#include "config.h"
#include "miniscript_decode.h"
#include <wally_core.h>
#include <wally_script.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#define MAX_TOKENS 64

#define CHECK(expr) do { if (!(expr)) { printf("FAIL: %s\n", #expr); ok = false; } } while(0)

static bool test_tokenize_script(void)
{
    bool ok = true;
    token_t tokens[MAX_TOKENS];
    size_t count;
    int ret;

    /* Empty script */
    ret = tokenize_script(NULL, 0, tokens, MAX_TOKENS, &count);
    CHECK(ret == WALLY_OK);
    CHECK(count == 0);

    /* OP_0 */
    {
        unsigned char script[] = { OP_0 };
        ret = tokenize_script(script, 1, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK);
        CHECK(count == 1);
        CHECK(tokens[0].kind == TK_NUM);
        CHECK(tokens[0].data.num == 0);
    }

    /* OP_1 */
    {
        unsigned char script[] = { OP_1 };
        ret = tokenize_script(script, 1, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK);
        CHECK(count == 1);
        CHECK(tokens[0].kind == TK_NUM);
        CHECK(tokens[0].data.num == 1);
    }

    /* OP_16 */
    {
        unsigned char script[] = { OP_16 };
        ret = tokenize_script(script, 1, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK);
        CHECK(count == 1);
        CHECK(tokens[0].kind == TK_NUM);
        CHECK(tokens[0].data.num == 16);
    }

    /* OP_1NEGATE */
    {
        unsigned char script[] = { OP_1NEGATE };
        ret = tokenize_script(script, 1, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_EINVAL);
    }

    /* Push data — 20-byte (TK_HASH20) */
    {
        unsigned char script[21];
        script[0] = 0x14; /* push 20 bytes */
        memset(script + 1, 0xab, 20);
        ret = tokenize_script(script, 21, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK);
        CHECK(count == 1);
        CHECK(tokens[0].kind == TK_HASH20);
        CHECK(memcmp(tokens[0].data.hash20, script + 1, 20) == 0);
    }

    /* Push data — 32-byte (TK_BYTES32) */
    {
        unsigned char script[33];
        script[0] = 0x20; /* push 32 bytes */
        memset(script + 1, 0xcd, 32);
        ret = tokenize_script(script, 33, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK);
        CHECK(count == 1);
        CHECK(tokens[0].kind == TK_BYTES32);
        CHECK(memcmp(tokens[0].data.bytes32, script + 1, 32) == 0);
    }

    /* Push data — 33-byte (TK_BYTES33) */
    {
        unsigned char script[34];
        script[0] = 0x21; /* push 33 bytes */
        memset(script + 1, 0xef, 33);
        ret = tokenize_script(script, 34, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK);
        CHECK(count == 1);
        CHECK(tokens[0].kind == TK_BYTES33);
        CHECK(memcmp(tokens[0].data.bytes33, script + 1, 33) == 0);
    }

    /* Push data — 65-byte (TK_BYTES65) */
    {
        unsigned char script[66];
        script[0] = 0x41; /* push 65 bytes */
        memset(script + 1, 0x04, 65);
        ret = tokenize_script(script, 66, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK);
        CHECK(count == 1);
        CHECK(tokens[0].kind == TK_BYTES65);
        CHECK(memcmp(tokens[0].data.bytes65, script + 1, 65) == 0);
    }

    /* Push data — CScriptNum (1-byte positive integer, value 5) */
    {
        unsigned char script[] = { 0x01, 0x05 };
        ret = tokenize_script(script, 2, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK);
        CHECK(count == 1);
        CHECK(tokens[0].kind == TK_NUM);
        CHECK(tokens[0].data.num == 5);
    }

    /* Push data — unsupported length (5 bytes) */
    {
        unsigned char script[] = { 0x05, 0, 0, 0, 0, 0 };
        ret = tokenize_script(script, 6, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_EINVAL);
    }

    /* Push data — truncated (push-N but script too short) */
    {
        unsigned char script[] = { 0x14 }; /* says push 20, but nothing follows */
        ret = tokenize_script(script, 1, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_EINVAL);
    }

    /* OP_PUSHDATA1 — valid (20 bytes) */
    {
        unsigned char script[22];
        script[0] = OP_PUSHDATA1;
        script[1] = 20;
        memset(script + 2, 0x11, 20);
        ret = tokenize_script(script, 22, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK);
        CHECK(count == 1);
        CHECK(tokens[0].kind == TK_HASH20);
        CHECK(memcmp(tokens[0].data.hash20, script + 2, 20) == 0);
    }

    /* OP_PUSHDATA1 — truncated (missing length byte) */
    {
        unsigned char script[] = { OP_PUSHDATA1 };
        ret = tokenize_script(script, 1, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_EINVAL);
    }

    /* OP_PUSHDATA2 — valid (20 bytes, little-endian length) */
    {
        unsigned char script[23];
        script[0] = OP_PUSHDATA2;
        script[1] = 20;
        script[2] = 0;
        memset(script + 3, 0x22, 20);
        ret = tokenize_script(script, 23, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK);
        CHECK(count == 1);
        CHECK(tokens[0].kind == TK_HASH20);
        CHECK(memcmp(tokens[0].data.hash20, script + 3, 20) == 0);
    }

    /* OP_PUSHDATA2 — truncated (only one length byte) */
    {
        unsigned char script[] = { OP_PUSHDATA2, 20 };
        ret = tokenize_script(script, 2, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_EINVAL);
    }

    /* Opcode-only tokens */
    {
        unsigned char s[1];
        s[0] = OP_BOOLAND;
        ret = tokenize_script(s, 1, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK && count == 1 && tokens[0].kind == TK_BOOL_AND);

        s[0] = OP_BOOLOR;
        ret = tokenize_script(s, 1, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK && count == 1 && tokens[0].kind == TK_BOOL_OR);

        s[0] = OP_ADD;
        ret = tokenize_script(s, 1, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK && count == 1 && tokens[0].kind == TK_ADD);

        s[0] = OP_EQUAL;
        ret = tokenize_script(s, 1, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK && count == 1 && tokens[0].kind == TK_EQUAL);

        s[0] = OP_NUMEQUAL;
        ret = tokenize_script(s, 1, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK && count == 1 && tokens[0].kind == TK_NUM_EQUAL);

        s[0] = OP_CHECKSIG;
        ret = tokenize_script(s, 1, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK && count == 1 && tokens[0].kind == TK_CHECK_SIG);

        s[0] = OP_CHECKSIGADD;
        ret = tokenize_script(s, 1, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK && count == 1 && tokens[0].kind == TK_CHECK_SIG_ADD);

        s[0] = OP_CHECKMULTISIG;
        ret = tokenize_script(s, 1, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK && count == 1 && tokens[0].kind == TK_CHECK_MULTI_SIG);

        s[0] = OP_CHECKSEQUENCEVERIFY;
        ret = tokenize_script(s, 1, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK && count == 1 && tokens[0].kind == TK_CHECK_SEQUENCE_VERIFY);

        s[0] = OP_CHECKLOCKTIMEVERIFY;
        ret = tokenize_script(s, 1, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK && count == 1 && tokens[0].kind == TK_CHECK_LOCK_TIME_VERIFY);

        s[0] = OP_FROMALTSTACK;
        ret = tokenize_script(s, 1, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK && count == 1 && tokens[0].kind == TK_FROM_ALT_STACK);

        s[0] = OP_TOALTSTACK;
        ret = tokenize_script(s, 1, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK && count == 1 && tokens[0].kind == TK_TO_ALT_STACK);

        s[0] = OP_DROP;
        ret = tokenize_script(s, 1, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK && count == 1 && tokens[0].kind == TK_DROP);

        s[0] = OP_DUP;
        ret = tokenize_script(s, 1, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK && count == 1 && tokens[0].kind == TK_DUP);

        s[0] = OP_IF;
        ret = tokenize_script(s, 1, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK && count == 1 && tokens[0].kind == TK_IF);

        s[0] = OP_IFDUP;
        ret = tokenize_script(s, 1, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK && count == 1 && tokens[0].kind == TK_IF_DUP);

        s[0] = OP_NOTIF;
        ret = tokenize_script(s, 1, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK && count == 1 && tokens[0].kind == TK_NOT_IF);

        s[0] = OP_ELSE;
        ret = tokenize_script(s, 1, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK && count == 1 && tokens[0].kind == TK_ELSE);

        s[0] = OP_ENDIF;
        ret = tokenize_script(s, 1, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK && count == 1 && tokens[0].kind == TK_END_IF);

        s[0] = OP_0NOTEQUAL;
        ret = tokenize_script(s, 1, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK && count == 1 && tokens[0].kind == TK_ZERO_NOT_EQUAL);

        s[0] = OP_SIZE;
        ret = tokenize_script(s, 1, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK && count == 1 && tokens[0].kind == TK_SIZE);

        s[0] = OP_SWAP;
        ret = tokenize_script(s, 1, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK && count == 1 && tokens[0].kind == TK_SWAP);

        s[0] = OP_RIPEMD160;
        ret = tokenize_script(s, 1, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK && count == 1 && tokens[0].kind == TK_RIPEMD160);

        s[0] = OP_HASH160;
        ret = tokenize_script(s, 1, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK && count == 1 && tokens[0].kind == TK_HASH160);

        s[0] = OP_SHA256;
        ret = tokenize_script(s, 1, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK && count == 1 && tokens[0].kind == TK_SHA256);

        s[0] = OP_HASH256;
        ret = tokenize_script(s, 1, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK && count == 1 && tokens[0].kind == TK_HASH256);
    }

    /* OP_EQUALVERIFY → TK_EQUAL, TK_VERIFY */
    {
        unsigned char script[] = { OP_EQUALVERIFY };
        ret = tokenize_script(script, 1, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK);
        CHECK(count == 2);
        CHECK(tokens[0].kind == TK_EQUAL);
        CHECK(tokens[1].kind == TK_VERIFY);
    }

    /* OP_NUMEQUALVERIFY → TK_NUM_EQUAL, TK_VERIFY */
    {
        unsigned char script[] = { OP_NUMEQUALVERIFY };
        ret = tokenize_script(script, 1, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK);
        CHECK(count == 2);
        CHECK(tokens[0].kind == TK_NUM_EQUAL);
        CHECK(tokens[1].kind == TK_VERIFY);
    }

    /* OP_CHECKSIGVERIFY → TK_CHECK_SIG, TK_VERIFY */
    {
        unsigned char script[] = { OP_CHECKSIGVERIFY };
        ret = tokenize_script(script, 1, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK);
        CHECK(count == 2);
        CHECK(tokens[0].kind == TK_CHECK_SIG);
        CHECK(tokens[1].kind == TK_VERIFY);
    }

    /* OP_CHECKMULTISIGVERIFY → TK_CHECK_MULTI_SIG, TK_VERIFY */
    {
        unsigned char script[] = { OP_CHECKMULTISIGVERIFY };
        ret = tokenize_script(script, 1, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK);
        CHECK(count == 2);
        CHECK(tokens[0].kind == TK_CHECK_MULTI_SIG);
        CHECK(tokens[1].kind == TK_VERIFY);
    }

    /* Standalone OP_VERIFY (n=0, no preceding token) */
    {
        unsigned char script[] = { OP_VERIFY };
        ret = tokenize_script(script, 1, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK);
        CHECK(count == 1);
        CHECK(tokens[0].kind == TK_VERIFY);
    }

    /* OP_SIZE, OP_VERIFY → TK_SIZE, TK_VERIFY */
    {
        unsigned char script[] = { OP_SIZE, OP_VERIFY };
        ret = tokenize_script(script, 2, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK);
        CHECK(count == 2);
        CHECK(tokens[0].kind == TK_SIZE);
        CHECK(tokens[1].kind == TK_VERIFY);
    }

    /* NonMinimalVerify: OP_EQUAL, OP_VERIFY → WALLY_EINVAL */
    {
        unsigned char script[] = { OP_EQUAL, OP_VERIFY };
        ret = tokenize_script(script, 2, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_EINVAL);
    }

    /* NonMinimalVerify: OP_CHECKSIG, OP_VERIFY → WALLY_EINVAL */
    {
        unsigned char script[] = { OP_CHECKSIG, OP_VERIFY };
        ret = tokenize_script(script, 2, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_EINVAL);
    }

    /* NonMinimalVerify: OP_CHECKMULTISIG, OP_VERIFY → WALLY_EINVAL */
    {
        unsigned char script[] = { OP_CHECKMULTISIG, OP_VERIFY };
        ret = tokenize_script(script, 2, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_EINVAL);
    }

    /* Unknown opcode (OP_RESERVED = 0x50) → WALLY_EINVAL */
    {
        unsigned char script[] = { OP_RESERVED };
        ret = tokenize_script(script, 1, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_EINVAL);
    }

    /* Buffer overflow: OP_DUP with max_tokens = 0 */
    {
        unsigned char script[] = { OP_DUP };
        ret = tokenize_script(script, 1, tokens, 0, &count);
        CHECK(ret == WALLY_EINVAL);
    }

    /* Buffer overflow: OP_EQUALVERIFY (emits 2 tokens) with max_tokens = 1 */
    {
        unsigned char script[] = { OP_EQUALVERIFY };
        ret = tokenize_script(script, 1, tokens, 1, &count);
        CHECK(ret == WALLY_EINVAL);
    }

    /* Multi-token sequence: P2PKH-like script
     * OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
     * → TK_DUP, TK_HASH160, TK_HASH20, TK_EQUAL, TK_VERIFY, TK_CHECK_SIG */
    {
        unsigned char script[25];
        script[0] = OP_DUP;
        script[1] = OP_HASH160;
        script[2] = 0x14; /* push 20 bytes */
        memset(script + 3, 0x33, 20);
        script[23] = OP_EQUALVERIFY;
        script[24] = OP_CHECKSIG;
        ret = tokenize_script(script, 25, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK);
        CHECK(count == 6);
        CHECK(tokens[0].kind == TK_DUP);
        CHECK(tokens[1].kind == TK_HASH160);
        CHECK(tokens[2].kind == TK_HASH20);
        CHECK(memcmp(tokens[2].data.hash20, script + 3, 20) == 0);
        CHECK(tokens[3].kind == TK_EQUAL);
        CHECK(tokens[4].kind == TK_VERIFY);
        CHECK(tokens[5].kind == TK_CHECK_SIG);
    }

    return ok;
}

static bool test_decode_pk(void)
{
    bool ok = true;
    ms_node *output = NULL;
    int ret;

    /* pk_k with a 33-byte compressed pubkey: script = 0x21 <33 bytes> */
    {
        unsigned char script[34];
        unsigned char key[33];
        script[0] = 0x21;
        memset(key, 0x02, 33); /* fake compressed pubkey */
        memcpy(script + 1, key, 33);
        ret = decode_script_to_node(script, 34, 0, &output);
        CHECK(ret == WALLY_OK);
        CHECK(output != NULL);
        CHECK(output->kind == KIND_MINISCRIPT_PK_K);
        CHECK(output->data_len == 33);
        CHECK(memcmp(output->data, key, 33) == 0);
        ms_node_free(output); output = NULL;
    }

    /* pk_k with a 65-byte uncompressed pubkey: script = 0x41 <65 bytes> */
    {
        unsigned char script[66];
        unsigned char key[65];
        script[0] = 0x41;
        key[0] = 0x04;
        memset(key + 1, 0xab, 64);
        memcpy(script + 1, key, 65);
        ret = decode_script_to_node(script, 66, 0, &output);
        CHECK(ret == WALLY_OK);
        CHECK(output != NULL);
        CHECK(output->kind == KIND_MINISCRIPT_PK_K);
        CHECK(output->data_len == 65);
        CHECK(memcmp(output->data, key, 65) == 0);
        ms_node_free(output); output = NULL;
    }

    /* pk_k with a 32-byte x-only pubkey: script = 0x20 <32 bytes> */
    {
        unsigned char script[33];
        unsigned char key[32];
        script[0] = 0x20;
        memset(key, 0xcd, 32);
        memcpy(script + 1, key, 32);
        ret = decode_script_to_node(script, 33, 0, &output);
        CHECK(ret == WALLY_OK);
        CHECK(output != NULL);
        CHECK(output->kind == KIND_MINISCRIPT_PK_K);
        CHECK(output->data_len == 32);
        CHECK(memcmp(output->data, key, 32) == 0);
        ms_node_free(output); output = NULL;
    }

    /* pk_h: DUP HASH160 <20-byte-hash> EQUALVERIFY
     * script = OP_DUP OP_HASH160 0x14 <20 bytes> OP_EQUALVERIFY */
    {
        unsigned char script[25];
        unsigned char hash[20];
        memset(hash, 0x77, 20);
        script[0] = OP_DUP;
        script[1] = OP_HASH160;
        script[2] = 0x14;
        memcpy(script + 3, hash, 20);
        script[23] = OP_EQUALVERIFY;
        ret = decode_script_to_node(script, 24, 0, &output);
        CHECK(ret == WALLY_OK);
        CHECK(output != NULL);
        CHECK(output->kind == KIND_MINISCRIPT_PK_H);
        CHECK(output->data_len == 20);
        CHECK(memcmp(output->data, hash, 20) == 0);
        ms_node_free(output); output = NULL;
    }

    return ok;
}

static bool test_decode_multi(void)
{
    bool ok = true;
    ms_node *output = NULL;
    int ret;

    /* multi(2, pk1, pk2, pk3): OP_2 push33(pk1) push33(pk2) push33(pk3) OP_3 OP_CHECKMULTISIG */
    {
        unsigned char pk1[33], pk2[33], pk3[33];
        unsigned char script[1 + 34 + 34 + 34 + 1 + 1];
        size_t off = 0;
        memset(pk1, 0x02, 33);
        memset(pk2, 0x03, 33);
        memset(pk3, 0x04, 33);
        script[off++] = OP_2;
        script[off++] = 0x21; memcpy(script + off, pk1, 33); off += 33;
        script[off++] = 0x21; memcpy(script + off, pk2, 33); off += 33;
        script[off++] = 0x21; memcpy(script + off, pk3, 33); off += 33;
        script[off++] = OP_3;
        script[off++] = OP_CHECKMULTISIG;
        ret = decode_script_to_node(script, sizeof(script), 0, &output);
        CHECK(ret == WALLY_OK);
        CHECK(output != NULL);
        CHECK(output->kind == KIND_MINISCRIPT_MULTI);
        CHECK(output->number == 2);
        CHECK(output->child != NULL);
        CHECK(output->child->kind == KIND_MINISCRIPT_PK_K);
        CHECK(output->child->data_len == 33);
        CHECK(memcmp(output->child->data, pk1, 33) == 0);
        CHECK(output->child->next != NULL);
        CHECK(memcmp(output->child->next->data, pk2, 33) == 0);
        CHECK(output->child->next->next != NULL);
        CHECK(memcmp(output->child->next->next->data, pk3, 33) == 0);
        CHECK(output->child->next->next->next == NULL);
        ms_node_free(output); output = NULL;
    }

    /* multi(1, pk1): single key, threshold 1 (boundary) */
    {
        unsigned char pk1[33];
        unsigned char script[1 + 34 + 1 + 1];
        size_t off = 0;
        memset(pk1, 0xaa, 33);
        script[off++] = OP_1;
        script[off++] = 0x21; memcpy(script + off, pk1, 33); off += 33;
        script[off++] = OP_1;
        script[off++] = OP_CHECKMULTISIG;
        ret = decode_script_to_node(script, sizeof(script), 0, &output);
        CHECK(ret == WALLY_OK);
        CHECK(output != NULL);
        CHECK(output->kind == KIND_MINISCRIPT_MULTI);
        CHECK(output->number == 1);
        CHECK(output->child != NULL);
        CHECK(output->child->data_len == 33);
        CHECK(memcmp(output->child->data, pk1, 33) == 0);
        CHECK(output->child->next == NULL);
        ms_node_free(output); output = NULL;
    }

    /* Error path: k > n (k=3, n=2) → WALLY_EINVAL */
    {
        unsigned char pk1[33], pk2[33];
        unsigned char script[1 + 34 + 34 + 1 + 1];
        size_t off = 0;
        memset(pk1, 0x02, 33);
        memset(pk2, 0x03, 33);
        script[off++] = OP_3;
        script[off++] = 0x21; memcpy(script + off, pk1, 33); off += 33;
        script[off++] = 0x21; memcpy(script + off, pk2, 33); off += 33;
        script[off++] = OP_2;
        script[off++] = OP_CHECKMULTISIG;
        ret = decode_script_to_node(script, sizeof(script), 0, &output);
        CHECK(ret == WALLY_EINVAL);
        CHECK(output == NULL);
    }

    return ok;
}

int main(void)
{
    bool ok = true;
    if (!test_tokenize_script()) {
        printf("[test_tokenize_script] failed!\n");
        ok = false;
    }
    if (!test_decode_pk()) {
        printf("[test_decode_pk] failed!\n");
        ok = false;
    }
    if (!test_decode_multi()) {
        printf("[test_decode_multi] failed!\n");
        ok = false;
    }
    wally_cleanup(0);
    return ok ? 0 : 1;
}
