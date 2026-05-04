#ifndef LIBWALLY_CORE_MUSIG_H
#define LIBWALLY_CORE_MUSIG_H

#include "wally_core.h"
#include "wally_crypto.h"
#include "wally_bip32.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef BUILD_STANDARD_SECP

/** Sizes of serialized MuSig2 objects */
#define WALLY_MUSIG_PUBNONCE_LEN    66
#define WALLY_MUSIG_AGGNONCE_LEN    66
#define WALLY_MUSIG_PARTIAL_SIG_LEN 32

/** Sizes of opaque MuSig2 objects (for buffer allocation) */
#define WALLY_MUSIG_KEYAGG_CACHE_LEN 197
#define WALLY_MUSIG_SESSION_LEN      133
#define WALLY_MUSIG_SECNONCE_LEN     132

/** Length of the BIP-328 synthetic chain code (same as BIP-32 chain code) */
#define WALLY_MUSIG2_CHAINCODE_LEN 32

/* Opaque type wrapping secp256k1_musig_keyagg_cache.
 * Holds the result of key aggregation; required for signing. */
struct wally_musig_keyagg_cache;

/* Opaque type wrapping secp256k1_musig_secnonce.
 * WARNING: MUST NOT be copied or serialized. Zeroed on free and after use. */
struct wally_musig_secnonce;

/* Opaque type wrapping secp256k1_musig_pubnonce. Serializes to 66 bytes. */
struct wally_musig_pubnonce;

/* Opaque type wrapping secp256k1_musig_aggnonce. Serializes to 66 bytes. */
struct wally_musig_aggnonce;

/* Opaque type wrapping secp256k1_musig_session. Not required to be secret. */
struct wally_musig_session;

/* Opaque type wrapping secp256k1_musig_partial_sig. Serializes to 32 bytes. */
struct wally_musig_partial_sig;

/* --- Lifecycle functions --- */

/**
 * Free a keyagg_cache.
 *
 * :param cache: The keyagg_cache to free.
 */
WALLY_CORE_API int wally_musig_keyagg_cache_free(
    struct wally_musig_keyagg_cache *cache);

/**
 * Serialize a keyagg_cache to its raw 197-byte form.
 *
 * :param cache: The keyagg_cache to serialize.
 * :param bytes_out: 197-byte output buffer.
 * FIXED_SIZED_OUTPUT(len, bytes_out, WALLY_MUSIG_KEYAGG_CACHE_LEN)
 */
WALLY_CORE_API int wally_musig_keyagg_cache_serialize(
    const struct wally_musig_keyagg_cache *cache,
    unsigned char *bytes_out,
    size_t len);

/**
 * Restore a keyagg_cache from its raw 197-byte form.
 *
 * WARNING: Do NOT call this on bytes from untrusted sources. The struct is not
 * cryptographically validated; malformed bytes produce undefined signing behaviour.
 * Only round-trip bytes produced by wally_musig_keyagg_cache_serialize().
 *
 * :param bytes: The 197-byte serialized keyagg_cache.
 * :param bytes_len: Length of bytes. Must be WALLY_MUSIG_KEYAGG_CACHE_LEN.
 * :param output: Destination for the allocated keyagg_cache.
 */
WALLY_CORE_API int wally_musig_keyagg_cache_parse(
    const unsigned char *bytes,
    size_t bytes_len,
    struct wally_musig_keyagg_cache **output);

/**
 * Free a secnonce, securely zeroing it first.
 *
 * :param nonce: The secnonce to free.
 */
WALLY_CORE_API int wally_musig_secnonce_free(
    struct wally_musig_secnonce *nonce);

/**
 * Parse a public nonce from its 66-byte serialized form.
 *
 * :param bytes: The 66-byte serialized pubnonce.
 * :param bytes_len: Length of bytes. Must be WALLY_MUSIG_PUBNONCE_LEN.
 * :param output: Destination for the allocated pubnonce.
 */
WALLY_CORE_API int wally_musig_pubnonce_parse(
    const unsigned char *bytes,
    size_t bytes_len,
    struct wally_musig_pubnonce **output);

/**
 * Serialize a public nonce to its 66-byte form.
 *
 * :param nonce: The pubnonce to serialize.
 * :param bytes_out: 66-byte output buffer.
 * FIXED_SIZED_OUTPUT(len, bytes_out, WALLY_MUSIG_PUBNONCE_LEN)
 */
WALLY_CORE_API int wally_musig_pubnonce_serialize(
    const struct wally_musig_pubnonce *nonce,
    unsigned char *bytes_out,
    size_t len);

/**
 * Free a pubnonce.
 *
 * :param nonce: The pubnonce to free.
 */
WALLY_CORE_API int wally_musig_pubnonce_free(
    struct wally_musig_pubnonce *nonce);

/**
 * Parse an aggregate nonce from its 66-byte serialized form.
 *
 * :param bytes: The 66-byte serialized aggnonce.
 * :param bytes_len: Length of bytes. Must be WALLY_MUSIG_AGGNONCE_LEN.
 * :param output: Destination for the allocated aggnonce.
 */
WALLY_CORE_API int wally_musig_aggnonce_parse(
    const unsigned char *bytes,
    size_t bytes_len,
    struct wally_musig_aggnonce **output);

/**
 * Serialize an aggregate nonce to its 66-byte form.
 *
 * :param nonce: The aggnonce to serialize.
 * :param bytes_out: 66-byte output buffer.
 * FIXED_SIZED_OUTPUT(len, bytes_out, WALLY_MUSIG_AGGNONCE_LEN)
 */
WALLY_CORE_API int wally_musig_aggnonce_serialize(
    const struct wally_musig_aggnonce *nonce,
    unsigned char *bytes_out,
    size_t len);

/**
 * Free an aggnonce.
 *
 * :param nonce: The aggnonce to free.
 */
WALLY_CORE_API int wally_musig_aggnonce_free(
    struct wally_musig_aggnonce *nonce);

/**
 * Free a session.
 *
 * :param session: The session to free.
 */
WALLY_CORE_API int wally_musig_session_free(
    struct wally_musig_session *session);

/**
 * Serialize a session to its raw 133-byte form.
 *
 * :param session: The session to serialize.
 * :param bytes_out: 133-byte output buffer.
 * FIXED_SIZED_OUTPUT(len, bytes_out, WALLY_MUSIG_SESSION_LEN)
 */
WALLY_CORE_API int wally_musig_session_serialize(
    const struct wally_musig_session *session,
    unsigned char *bytes_out,
    size_t len);

/**
 * Restore a session from its raw 133-byte form.
 *
 * WARNING: Do NOT call this on bytes from untrusted sources. The struct is not
 * cryptographically validated; malformed bytes produce undefined signing behaviour.
 * Only round-trip bytes produced by wally_musig_session_serialize().
 *
 * :param bytes: The 133-byte serialized session.
 * :param bytes_len: Length of bytes. Must be WALLY_MUSIG_SESSION_LEN.
 * :param output: Destination for the allocated session.
 */
WALLY_CORE_API int wally_musig_session_parse(
    const unsigned char *bytes,
    size_t bytes_len,
    struct wally_musig_session **output);

/**
 * Parse a partial signature from its 32-byte serialized form.
 *
 * :param bytes: The 32-byte serialized partial signature.
 * :param bytes_len: Length of bytes. Must be WALLY_MUSIG_PARTIAL_SIG_LEN.
 * :param output: Destination for the allocated partial_sig.
 */
WALLY_CORE_API int wally_musig_partial_sig_parse(
    const unsigned char *bytes,
    size_t bytes_len,
    struct wally_musig_partial_sig **output);

/**
 * Serialize a partial signature to its 32-byte form.
 *
 * :param sig: The partial_sig to serialize.
 * :param bytes_out: 32-byte output buffer.
 * FIXED_SIZED_OUTPUT(len, bytes_out, WALLY_MUSIG_PARTIAL_SIG_LEN)
 */
WALLY_CORE_API int wally_musig_partial_sig_serialize(
    const struct wally_musig_partial_sig *sig,
    unsigned char *bytes_out,
    size_t len);

/**
 * Free a partial signature.
 *
 * :param sig: The partial_sig to free.
 */
WALLY_CORE_API int wally_musig_partial_sig_free(
    struct wally_musig_partial_sig *sig);

#endif /* ndef BUILD_STANDARD_SECP */

#ifdef __cplusplus
}
#endif

#endif /* LIBWALLY_CORE_MUSIG_H */
