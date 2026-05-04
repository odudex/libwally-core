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

/* --- Key aggregation functions --- */

/**
 * Compute the MuSig2 aggregate public key from N individual public keys.
 *
 * :param pub_keys: Concatenated array of compressed public keys (each EC_PUBLIC_KEY_LEN bytes).
 * :param pub_keys_len: Length of pub_keys. Must be a non-zero multiple of EC_PUBLIC_KEY_LEN.
 * :param agg_pk_out: 32-byte buffer to receive the x-only aggregate public key. May be NULL.
 * FIXED_SIZED_OUTPUT(agg_pk_out_len, agg_pk_out, EC_XONLY_PUBLIC_KEY_LEN)
 * :param cache_out: Destination for the allocated keyagg_cache (required for signing). May be NULL.
 */
WALLY_CORE_API int wally_musig_pubkey_agg(
    const unsigned char *pub_keys,
    size_t pub_keys_len,
    unsigned char *agg_pk_out,
    size_t agg_pk_out_len,
    struct wally_musig_keyagg_cache **cache_out);

/**
 * Extract the non-xonly (compressed) aggregate public key from a keyagg_cache.
 *
 * :param cache: The keyagg_cache produced by wally_musig_pubkey_agg.
 * :param pub_key_out: 33-byte buffer to receive the compressed aggregate public key.
 * FIXED_SIZED_OUTPUT(pub_key_out_len, pub_key_out, EC_PUBLIC_KEY_LEN)
 */
WALLY_CORE_API int wally_musig_pubkey_get(
    const struct wally_musig_keyagg_cache *cache,
    unsigned char *pub_key_out,
    size_t pub_key_out_len);

/**
 * Apply BIP-32 plain EC tweaking to an aggregate key via the keyagg_cache.
 *
 * :param cache: The keyagg_cache to tweak (modified in place).
 * :param tweak: 32-byte tweak value.
 * :param tweak_len: Length of tweak. Must be 32.
 * :param pub_key_out: 33-byte buffer for the tweaked compressed public key. May be NULL.
 * FIXED_SIZED_OUTPUT(pub_key_out_len, pub_key_out, EC_PUBLIC_KEY_LEN)
 */
WALLY_CORE_API int wally_musig_pubkey_ec_tweak_add(
    struct wally_musig_keyagg_cache *cache,
    const unsigned char *tweak,
    size_t tweak_len,
    unsigned char *pub_key_out,
    size_t pub_key_out_len);

/**
 * Apply BIP-341 x-only tweaking to an aggregate key via the keyagg_cache.
 *
 * :param cache: The keyagg_cache to tweak (modified in place).
 * :param tweak: 32-byte tweak value.
 * :param tweak_len: Length of tweak. Must be 32.
 * :param pub_key_out: 33-byte buffer for the tweaked compressed public key. May be NULL.
 * FIXED_SIZED_OUTPUT(pub_key_out_len, pub_key_out, EC_PUBLIC_KEY_LEN)
 */
WALLY_CORE_API int wally_musig_pubkey_xonly_tweak_add(
    struct wally_musig_keyagg_cache *cache,
    const unsigned char *tweak,
    size_t tweak_len,
    unsigned char *pub_key_out,
    size_t pub_key_out_len);

/* --- Nonce generation and aggregation functions --- */

/**
 * Generate a MuSig2 secret/public nonce pair.
 *
 * :param session_secrand32: 32-byte unique random session ID. MUST NOT be reused.
 * :param session_secrand_len: Must be 32.
 * :param seckey: 32-byte secret key of the signer (optional, can be NULL).
 * :param seckey_len: Must be 32 if seckey is non-NULL, 0 otherwise.
 * :param pubkey33: 33-byte compressed public key of this signer (required).
 * :param pubkey_len: Must be EC_PUBLIC_KEY_LEN (33).
 * :param keyagg_cache: keyagg_cache from wally_musig_pubkey_agg (optional, can be NULL).
 * :param msg32: 32-byte message to be signed, if known (optional, can be NULL).
 * :param msg_len: Must be 32 if msg32 is non-NULL, 0 otherwise.
 * :param extra_input32: 32-byte extra entropy input (optional, can be NULL).
 * :param extra_len: Must be 32 if extra_input32 is non-NULL, 0 otherwise.
 * :param secnonce_out: Destination for the allocated secret nonce. Must be kept secret.
 * :param pubnonce_out: Destination for the allocated public nonce to send to cosigners.
 */
WALLY_CORE_API int wally_musig_nonce_gen(
    const unsigned char *session_secrand32,
    size_t session_secrand_len,
    const unsigned char *seckey,
    size_t seckey_len,
    const unsigned char *pubkey33,
    size_t pubkey_len,
    const struct wally_musig_keyagg_cache *keyagg_cache,
    const unsigned char *msg32,
    size_t msg_len,
    const unsigned char *extra_input32,
    size_t extra_len,
    struct wally_musig_secnonce **secnonce_out,
    struct wally_musig_pubnonce **pubnonce_out);

/**
 * Generate a MuSig2 secret/public nonce pair using a counter-based session ID.
 *
 * WARNING: Nonce reuse in MuSig2 is catastrophic. Calling this function with
 * the same (counter, seckey) pair more than once — across calls, sessions, or
 * process restarts — leaks the private key. The counter MUST be stored durably
 * and incremented before each signing session. See BIP-327 §Nonce generation,
 * "Synthetic nonces". Prefer wally_musig_nonce_gen() for non-hardware-wallet use.
 *
 * This variant is intended for hardware wallets or deterministic signers that
 * cannot generate random session IDs. The uint64_t counter is serialized as an
 * 8-byte little-endian value, zero-padded to 32 bytes, and used as the
 * session_id32. Per BIP-327, seckey MUST be provided when using a counter.
 *
 * :param counter: Monotonically increasing counter. Reuse with the same seckey
 *   leaks the private key. Persist and increment in durable storage.
 * :param seckey: 32-byte secret key of the signer (REQUIRED for counter mode).
 * :param seckey_len: Must be 32.
 * :param pubkey33: 33-byte compressed public key of this signer (required).
 * :param pubkey_len: Must be EC_PUBLIC_KEY_LEN (33).
 * :param keyagg_cache: keyagg_cache from wally_musig_pubkey_agg (optional, can be NULL).
 * :param msg32: 32-byte message to be signed, if known (optional, can be NULL).
 * :param msg_len: Must be 32 if msg32 is non-NULL, 0 otherwise.
 * :param extra_input32: 32-byte extra entropy input (optional, can be NULL).
 * :param extra_len: Must be 32 if extra_input32 is non-NULL, 0 otherwise.
 * :param secnonce_out: Destination for the allocated secret nonce. Must be kept secret.
 * :param pubnonce_out: Destination for the allocated public nonce to send to cosigners.
 */
WALLY_CORE_API int wally_musig_nonce_gen_counter(
    uint64_t counter,
    const unsigned char *seckey,
    size_t seckey_len,
    const unsigned char *pubkey33,
    size_t pubkey_len,
    const struct wally_musig_keyagg_cache *keyagg_cache,
    const unsigned char *msg32,
    size_t msg_len,
    const unsigned char *extra_input32,
    size_t extra_len,
    struct wally_musig_secnonce **secnonce_out,
    struct wally_musig_pubnonce **pubnonce_out);

/**
 * Aggregate N serialized public nonces into a single aggregate nonce.
 *
 * :param pubnonces: Flat array of serialized pubnonces (each WALLY_MUSIG_PUBNONCE_LEN bytes).
 * :param pubnonces_len: Total byte length. Must equal n_pubnonces * WALLY_MUSIG_PUBNONCE_LEN.
 * :param n_pubnonces: Number of pubnonces. Must be >= 2.
 * :param aggnonce_out: Destination for the allocated aggregate nonce.
 */
WALLY_CORE_API int wally_musig_nonce_agg(
    const unsigned char *pubnonces,
    size_t pubnonces_len,
    size_t n_pubnonces,
    struct wally_musig_aggnonce **aggnonce_out);

#endif /* ndef BUILD_STANDARD_SECP */

#ifdef __cplusplus
}
#endif

#endif /* LIBWALLY_CORE_MUSIG_H */
