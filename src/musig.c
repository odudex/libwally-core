#include "internal.h"
#include <include/wally_crypto.h>
#include <include/wally_musig.h>
#include <include/wally_bip32.h>

#ifndef BUILD_STANDARD_SECP
#include <secp256k1_musig.h>

/* Struct bodies kept private to prevent inadvertent copying (nonce-reuse risk) */
struct wally_musig_keyagg_cache { unsigned char data[197]; };
struct wally_musig_secnonce      { unsigned char data[132]; };
struct wally_musig_pubnonce      { unsigned char data[132]; };
struct wally_musig_aggnonce      { unsigned char data[132]; };
struct wally_musig_session       { unsigned char data[133]; };
struct wally_musig_partial_sig   { unsigned char data[36];  };

/* Comparison function for qsort: lexicographic order of 33-byte compressed pubkeys */
static int pubkey_cmp(const void *a, const void *b)
{
    return memcmp(a, b, EC_PUBLIC_KEY_LEN);
}

/* BIP-328 synthetic xpub chain code: SHA256("MuSig2MuSig2MuSig2") */
static const unsigned char MUSIG2_CHAINCODE[WALLY_MUSIG2_CHAINCODE_LEN] = {
    0x86, 0x80, 0x87, 0xca, 0x02, 0xa6, 0xf9, 0x74,
    0xc4, 0x59, 0x89, 0x24, 0xc3, 0x6b, 0x57, 0x76,
    0x2d, 0x32, 0xcb, 0x45, 0x71, 0x71, 0x67, 0xe3,
    0x00, 0x62, 0x2c, 0x71, 0x67, 0xe3, 0x89, 0x65
};

/* Compile-time size assertions to catch upstream secp256k1-zkp ABI changes */
typedef char assert_keyagg_cache_size[
    sizeof(secp256k1_musig_keyagg_cache) == sizeof(struct wally_musig_keyagg_cache) ? 1 : -1];
typedef char assert_secnonce_size[
    sizeof(secp256k1_musig_secnonce) == sizeof(struct wally_musig_secnonce) ? 1 : -1];
typedef char assert_pubnonce_size[
    sizeof(secp256k1_musig_pubnonce) == sizeof(struct wally_musig_pubnonce) ? 1 : -1];
typedef char assert_aggnonce_size[
    sizeof(secp256k1_musig_aggnonce) == sizeof(struct wally_musig_aggnonce) ? 1 : -1];
typedef char assert_session_size[
    sizeof(secp256k1_musig_session) == sizeof(struct wally_musig_session) ? 1 : -1];
typedef char assert_partial_sig_size[
    sizeof(secp256k1_musig_partial_sig) == sizeof(struct wally_musig_partial_sig) ? 1 : -1];

/* keyagg_cache lifecycle */

WALLY_CORE_API int wally_musig_keyagg_cache_free(
    struct wally_musig_keyagg_cache *cache)
{
    if (cache)
        clear_and_free(cache, sizeof(*cache));
    return WALLY_OK;
}

WALLY_CORE_API int wally_musig_keyagg_cache_serialize(
    const struct wally_musig_keyagg_cache *cache,
    unsigned char *bytes_out,
    size_t len)
{
    if (!cache || !bytes_out || len != WALLY_MUSIG_KEYAGG_CACHE_LEN)
        return WALLY_EINVAL;
    memcpy(bytes_out, cache->data, WALLY_MUSIG_KEYAGG_CACHE_LEN);
    return WALLY_OK;
}

WALLY_CORE_API int wally_musig_keyagg_cache_parse(
    const unsigned char *bytes,
    size_t bytes_len,
    struct wally_musig_keyagg_cache **output)
{
    struct wally_musig_keyagg_cache *cache;

    if (!bytes || bytes_len != WALLY_MUSIG_KEYAGG_CACHE_LEN || !output)
        return WALLY_EINVAL;
    *output = NULL;
    cache = wally_calloc(sizeof(*cache));
    if (!cache)
        return WALLY_ENOMEM;
    memcpy(cache->data, bytes, WALLY_MUSIG_KEYAGG_CACHE_LEN);
    *output = cache;
    return WALLY_OK;
}

/* secnonce lifecycle */

WALLY_CORE_API int wally_musig_secnonce_free(
    struct wally_musig_secnonce *nonce)
{
    if (nonce)
        clear_and_free(nonce, sizeof(*nonce));
    return WALLY_OK;
}

/* pubnonce parse/serialize/free */

WALLY_CORE_API int wally_musig_pubnonce_parse(
    const unsigned char *bytes,
    size_t bytes_len,
    struct wally_musig_pubnonce **output)
{
    const secp256k1_context *ctx = secp_ctx();
    secp256k1_musig_pubnonce *nonce;

    if (!bytes || bytes_len != WALLY_MUSIG_PUBNONCE_LEN || !output)
        return WALLY_EINVAL;
    *output = NULL;
    if (!ctx)
        return WALLY_ENOMEM;

    nonce = wally_calloc(sizeof(*nonce));
    if (!nonce)
        return WALLY_ENOMEM;

    if (!secp256k1_musig_pubnonce_parse(ctx, nonce, bytes)) {
        wally_free(nonce);
        return WALLY_EINVAL;
    }
    *output = (struct wally_musig_pubnonce *)nonce;
    return WALLY_OK;
}

WALLY_CORE_API int wally_musig_pubnonce_serialize(
    const struct wally_musig_pubnonce *nonce,
    unsigned char *bytes_out,
    size_t len)
{
    const secp256k1_context *ctx = secp_ctx();

    if (!nonce || !bytes_out || len != WALLY_MUSIG_PUBNONCE_LEN)
        return WALLY_EINVAL;
    if (!ctx)
        return WALLY_ENOMEM;

    if (!secp256k1_musig_pubnonce_serialize(
            ctx, bytes_out,
            (const secp256k1_musig_pubnonce *)nonce))
        return WALLY_ERROR;
    return WALLY_OK;
}

WALLY_CORE_API int wally_musig_pubnonce_free(
    struct wally_musig_pubnonce *nonce)
{
    if (nonce)
        clear_and_free(nonce, sizeof(*nonce));
    return WALLY_OK;
}

/* aggnonce parse/serialize/free */

WALLY_CORE_API int wally_musig_aggnonce_parse(
    const unsigned char *bytes,
    size_t bytes_len,
    struct wally_musig_aggnonce **output)
{
    const secp256k1_context *ctx = secp_ctx();
    secp256k1_musig_aggnonce *nonce;

    if (!bytes || bytes_len != WALLY_MUSIG_AGGNONCE_LEN || !output)
        return WALLY_EINVAL;
    *output = NULL;
    if (!ctx)
        return WALLY_ENOMEM;

    nonce = wally_calloc(sizeof(*nonce));
    if (!nonce)
        return WALLY_ENOMEM;

    if (!secp256k1_musig_aggnonce_parse(ctx, nonce, bytes)) {
        wally_free(nonce);
        return WALLY_EINVAL;
    }
    *output = (struct wally_musig_aggnonce *)nonce;
    return WALLY_OK;
}

WALLY_CORE_API int wally_musig_aggnonce_serialize(
    const struct wally_musig_aggnonce *nonce,
    unsigned char *bytes_out,
    size_t len)
{
    const secp256k1_context *ctx = secp_ctx();

    if (!nonce || !bytes_out || len != WALLY_MUSIG_AGGNONCE_LEN)
        return WALLY_EINVAL;
    if (!ctx)
        return WALLY_ENOMEM;

    if (!secp256k1_musig_aggnonce_serialize(
            ctx, bytes_out,
            (const secp256k1_musig_aggnonce *)nonce))
        return WALLY_ERROR;
    return WALLY_OK;
}

WALLY_CORE_API int wally_musig_aggnonce_free(
    struct wally_musig_aggnonce *nonce)
{
    if (nonce)
        clear_and_free(nonce, sizeof(*nonce));
    return WALLY_OK;
}

/* session lifecycle */

WALLY_CORE_API int wally_musig_session_free(
    struct wally_musig_session *session)
{
    if (session)
        clear_and_free(session, sizeof(*session));
    return WALLY_OK;
}

WALLY_CORE_API int wally_musig_session_serialize(
    const struct wally_musig_session *session,
    unsigned char *bytes_out,
    size_t len)
{
    if (!session || !bytes_out || len != WALLY_MUSIG_SESSION_LEN)
        return WALLY_EINVAL;
    memcpy(bytes_out, session->data, WALLY_MUSIG_SESSION_LEN);
    return WALLY_OK;
}

WALLY_CORE_API int wally_musig_session_parse(
    const unsigned char *bytes,
    size_t bytes_len,
    struct wally_musig_session **output)
{
    struct wally_musig_session *session;

    if (!bytes || bytes_len != WALLY_MUSIG_SESSION_LEN || !output)
        return WALLY_EINVAL;
    *output = NULL;
    session = wally_calloc(sizeof(*session));
    if (!session)
        return WALLY_ENOMEM;
    memcpy(session->data, bytes, WALLY_MUSIG_SESSION_LEN);
    *output = session;
    return WALLY_OK;
}

/* partial_sig parse/serialize/free */

WALLY_CORE_API int wally_musig_partial_sig_parse(
    const unsigned char *bytes,
    size_t bytes_len,
    struct wally_musig_partial_sig **output)
{
    const secp256k1_context *ctx = secp_ctx();
    secp256k1_musig_partial_sig *sig;

    if (!bytes || bytes_len != WALLY_MUSIG_PARTIAL_SIG_LEN || !output)
        return WALLY_EINVAL;
    *output = NULL;
    if (!ctx)
        return WALLY_ENOMEM;

    sig = wally_calloc(sizeof(*sig));
    if (!sig)
        return WALLY_ENOMEM;

    if (!secp256k1_musig_partial_sig_parse(ctx, sig, bytes)) {
        wally_free(sig);
        return WALLY_EINVAL;
    }
    *output = (struct wally_musig_partial_sig *)sig;
    return WALLY_OK;
}

WALLY_CORE_API int wally_musig_partial_sig_serialize(
    const struct wally_musig_partial_sig *sig,
    unsigned char *bytes_out,
    size_t len)
{
    const secp256k1_context *ctx = secp_ctx();

    if (!sig || !bytes_out || len != WALLY_MUSIG_PARTIAL_SIG_LEN)
        return WALLY_EINVAL;
    if (!ctx)
        return WALLY_ENOMEM;

    if (!secp256k1_musig_partial_sig_serialize(
            ctx, bytes_out,
            (const secp256k1_musig_partial_sig *)sig))
        return WALLY_ERROR;
    return WALLY_OK;
}

WALLY_CORE_API int wally_musig_partial_sig_free(
    struct wally_musig_partial_sig *sig)
{
    if (sig)
        clear_and_free(sig, sizeof(*sig));
    return WALLY_OK;
}

#endif /* ndef BUILD_STANDARD_SECP */
