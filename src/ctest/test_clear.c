#include "config.h"

#ifdef HAVE_ASM_PAGE_H
#   include <asm/page.h>
#endif
#include "internal.h"
#undef malloc
#undef free
#include <wally_address.h>
#include <wally_bip32.h>
#include <wally_bip39.h>
#include <wally_crypto.h>
#include <wally_descriptor.h>
#include <wally_elements.h>
#include <wally_psbt.h>
#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>


/* From ASAN wiki, modified to not break gcc */
#if defined(__has_feature)
#if __has_feature(address_sanitizer)
#define __SANITIZE_ADDRESS__ 1
#endif
#endif

#if defined(__SANITIZE_ADDRESS__)
extern void __asan_unpoison_memory_region(void const volatile *addr, size_t size);
#define ASAN_POISON_MEMORY_REGION(addr, size) \
    __asan_poison_memory_region((addr), (size))
#define ASAN_UNPOISON_MEMORY_REGION(addr, size) \
    __asan_unpoison_memory_region((addr), (size))
#else
#define ASAN_POISON_MEMORY_REGION(addr, size) \
    ((void)(addr), (void)(size))
#define ASAN_UNPOISON_MEMORY_REGION(addr, size) \
    ((void)(addr), (void)(size))
#endif

/* Many compilers these days will elide calls to memset when they
 * determine that the memory is not read afterwards. There are reports
 * that tricks designed to work around this including making data volatile,
 * calling through function pointers, dummy asm contraints etc are
 * not always effective as optimization continues to improve.
 *
 * Here we try to ensure that the wally_clear/wally_clear_n() functions work as advertised
 * by:
 * - Setting a custom thread stack, then
 * - Calling a function that processes sensitive data, then
 * - Searching the stack for any sensitive data when the function returns
 *
 * This test does not address data leaked through registers, ancillary heap
 * allocations, side channels, or being swapped to disk.
 */
#ifndef PTHREAD_STACK_MIN
/* OSX Needs a minimum of 512K of stack per thread */
#define PTHREAD_STACK_MIN 512u * 1024u
#endif
/* Creating rangeproofs when blinding PSETs needs more than e.g. Linux's minimum */
#define STACK_SIZE (PTHREAD_STACK_MIN > 256u * 1024u ? PTHREAD_STACK_MIN : 256u * 1024u)

/* Global alternate stack pointer */
static unsigned char *gstack;
/* Global scratch buffer */
static unsigned char *gbytes;

static const char *BIP39_MNEMONIC = "team hospital room inspire tenant almost "
                                    "push rich year warfare jeans foil";
static const unsigned char BIP39_SECRET[16] = {
    0xde, 0xad, 0xbe, 0xef, 0xba, 0xad, 0xf0, 0x0d,
    0xab, 0xad, 0xca, 0xfe, 0xfe, 0xe1, 0xde, 0xad
};

/* Useful for developing these tests */
static void dump_mem(volatile const void *mem, size_t len)
{
    static size_t i;
    for (i = 0; i < len; ++i) {
        if (!((const unsigned char *)mem)[i])
            printf(".");
        else
            printf("%02x, ", ((const unsigned char *)mem)[i]);
    }
    printf("\n");
}

static unsigned char *checked_malloc(size_t len)
{
    void *ret = malloc(len);
    if (!ret)
        abort();
    wally_bzero(ret, len);
    return ret;
}

/* Non-optimized memcmp.
 * On e.g. x86_64, does not leave search data in SSE/AVX registers
 * where it may be spilled to the stack when a call through the PLT
 * occurs.
 * TODO: Move to src/internal.c if we need to (we currently do not
 *       memcmp() any secret data so this is only required here).
 */
WALLY_NO_OPTIMIZE static int wally_memcmp(const void *s1, const void *s2, size_t n) {
    const unsigned char *p1 = s1;
    const unsigned char *p2 = s2;

    for (size_t i = 0; i < n; i++) {
        if (p1[i] != p2[i]) {
            return p1[i] - p2[i];
        }
    }
    return 0;
}

static bool in_stack(const char *caller, volatile const void *search, size_t len)
{
    static size_t i;

    for (i = 0; i < STACK_SIZE - len - 1; ++i)
        if (!wally_memcmp(gstack + i, (const void *)search, len)) {
            if (caller) {
                printf("Found %s secret at stack position %ld and base %p\n", caller, (long)i, (void *)gstack);
                printf("raw pointer: %p\n", gstack + i);
                dump_mem(gstack + i - 64, len + 128);
            }
            return true; /* Found */
        }

    return false; /* Not found */
}

/* Test that searching for data on the stack actually works */
static bool test_search(void)
{
    char buf[8] = { 's', 'e', 'c', 'r', 'e', 't', '_', '\0' };

    /* printf here doesn't let the optimiser elide buf off the stack */
    printf("Testing stack search with %s\n", buf);

    return in_stack(NULL, buf, sizeof(buf));
}

static bool test_bip39(void)
{
    static size_t len;
    /* Converting uses a temporary buffer on the stack */
    if (bip39_mnemonic_to_bytes(NULL, BIP39_MNEMONIC, gbytes,
                                BIP39_ENTROPY_LEN_128, &len))
        return false;

    if (in_stack("bip39_mnemonic_to_bytes", BIP39_SECRET, sizeof(BIP39_SECRET)))
        return false;

    /* Internally converts to bytes */
    if (bip39_mnemonic_validate(NULL, BIP39_MNEMONIC))
        return false;

    if (in_stack("bip39_mnemonic_validate", BIP39_SECRET, sizeof(BIP39_SECRET)))
        return false;

    return true;
}

/* Sentinel for non-bip39 secret-handling tests: 32 bytes of 0xa5.
 * Distinct from BIP39_SECRET so test_search-style false positives can't
 * mask a real leak. */
static const unsigned char SECRET32[32] = {
    0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5,
    0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5,
    0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5,
    0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5
};

static bool test_bip32_from_seed(void)
{
    /* Derive an extended key from an all-0xa5 seed. The seed bytes
     * pass through libc memcpy when stored into the ext_key struct
     * and the HMAC-SHA512 input. */
    struct ext_key key;
    if (bip32_key_from_seed(SECRET32, sizeof(SECRET32),
                            BIP32_VER_MAIN_PRIVATE, 0, &key))
        return false;
    return !in_stack("bip32_key_from_seed", SECRET32, sizeof(SECRET32));
}

static bool test_ec_private_key_verify(void)
{
    /* The privkey is fed through libc on its way to libsecp. */
    if (wally_ec_private_key_verify(SECRET32, sizeof(SECRET32)))
        return false;
    return !in_stack("wally_ec_private_key_verify", SECRET32, sizeof(SECRET32));
}

static bool test_ec_sig_from_bytes(void)
{
    static unsigned char msg[32] = { 0x11 };
    static unsigned char sig[EC_SIGNATURE_LEN];
    /* Privkey is the secret. */
    if (wally_ec_sig_from_bytes(SECRET32, sizeof(SECRET32),
                                msg, sizeof(msg),
                                EC_FLAG_ECDSA,
                                sig, sizeof(sig)))
        return false;
    return !in_stack("wally_ec_sig_from_bytes", SECRET32, sizeof(SECRET32));
}

static bool test_hmac_sha256(void)
{
    static unsigned char out[32];
    static unsigned char msg[32] = { 0x22 };
    if (wally_hmac_sha256(SECRET32, sizeof(SECRET32),
                          msg, sizeof(msg),
                          out, sizeof(out)))
        return false;
    return !in_stack("wally_hmac_sha256", SECRET32, sizeof(SECRET32));
}

/* Call from deeper in the stack, so that the frame of in_stack() does
 * not overwrite any secret left in the callee's own frame */
WALLY_NO_OPTIMIZE static int ec_scalar_op_deep(bool subtract,
                                               const unsigned char *scalar,
                                               unsigned char *out, size_t len)
{
    volatile unsigned char pad[1024];

    pad[0] = 0;
    if (subtract)
        return pad[0] + wally_ec_scalar_subtract(scalar, EC_SCALAR_LEN,
                                                 SECRET32, sizeof(SECRET32),
                                                 out, len);
    return pad[0] + wally_ec_scalar_add(scalar, EC_SCALAR_LEN,
                                        SECRET32, sizeof(SECRET32), out, len);
}

static bool test_ec_scalar_add_subtract(void)
{
    static const unsigned char zero[EC_SCALAR_LEN];
    static const unsigned char one[EC_SCALAR_LEN] = { [31] = 1 };
    static unsigned char negated[EC_SCALAR_LEN], out[EC_SCALAR_LEN];

    /* The negated operand is the secret */
    if (wally_ec_scalar_subtract(zero, sizeof(zero), SECRET32, sizeof(SECRET32),
                                 negated, sizeof(negated)))
        return false;

    /* 1 + X */
    if (ec_scalar_op_deep(false, one, out, sizeof(out)) ||
        in_stack("wally_ec_scalar_add", negated, sizeof(negated)))
        return false;

    /* -X + X = 0 */
    if (ec_scalar_op_deep(false, negated, out, sizeof(out)) ||
        in_stack("wally_ec_scalar_add", negated, sizeof(negated)))
        return false;

    /* 1 - X */
    if (ec_scalar_op_deep(true, one, out, sizeof(out)) ||
        in_stack("wally_ec_scalar_subtract", negated, sizeof(negated)))
        return false;

    return true;
}

#ifdef BUILD_ELEMENTS
/* Call from deeper in the stack, so that the frame of in_stack() does
 * not overwrite any secret left in the callee's own frame */
WALLY_NO_OPTIMIZE static int elip150_private_key_deep(unsigned char *out, size_t len)
{
    static unsigned char script[22] = { 0x00, 0x14 };
    volatile unsigned char pad[1024];

    pad[0] = 0;
    return pad[0] + wally_elip150_private_key_to_ec_private_key(SECRET32, sizeof(SECRET32),
                                                                script, sizeof(script),
                                                                out, len);
}

static bool test_elip150_private_key(void)
{
    static unsigned char out[EC_PRIVATE_KEY_LEN];
    /* The derived private key is the secret. */
    if (elip150_private_key_deep(out, sizeof(out)))
        return false;
    return !in_stack("wally_elip150_private_key_to_ec_private_key", out, sizeof(out));
}

/* Call from deeper in the stack, as for elip150_private_key_deep() */
WALLY_NO_OPTIMIZE static int asset_scalar_offset_deep(uint64_t value,
                                                      unsigned char *out, size_t len)
{
    static unsigned char vbf[32] = { 0x33 };
    volatile unsigned char pad[1024];

    pad[0] = 0;
    return pad[0] + wally_asset_scalar_offset(value, SECRET32, sizeof(SECRET32),
                                              vbf, sizeof(vbf), out, len);
}

static bool test_asset_scalar_offset(void)
{
    static unsigned char value_scalar[32] = { [30] = 0x30, [31] = 0x39 };
    static unsigned char product[32];
    static unsigned char out[32];
    /* value * abf is the secret: it reveals the abf */
    if (wally_ec_scalar_multiply(value_scalar, sizeof(value_scalar),
                                 SECRET32, sizeof(SECRET32),
                                 product, sizeof(product)))
        return false;
    if (asset_scalar_offset_deep(0x3039, out, sizeof(out)))
        return false;
    return !in_stack("wally_asset_scalar_offset", product, sizeof(product));
}

/* Call from deeper in the stack, as for elip150_private_key_deep() */
WALLY_NO_OPTIMIZE static int descriptor_parse_deep(const char *descriptor,
                                                   struct wally_descriptor **output)
{
    volatile unsigned char pad[1024];

    pad[0] = 0;
    return pad[0] + wally_descriptor_parse(descriptor, NULL, WALLY_NETWORK_LIQUID,
                                           0, output);
}

static bool test_descriptor_parse_ct_key(void)
{
    /* The hex ELIP-150 blinding private key (SECRET32) is the secret */
    static const char *descriptor = "ct(a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5"
                                    "a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5,"
                                    "elwpkh(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798))";
    static struct wally_descriptor *output;
    static bool found;

    /* Parse once first so that resolving lazily bound symbols, which
     * uses a lot of stack, does not overwrite what the parse leaves */
    if (descriptor_parse_deep(descriptor, &output))
        return false;
    wally_descriptor_free(output);
    if (descriptor_parse_deep(descriptor, &output))
        return false;
    found = in_stack("wally_descriptor_parse", SECRET32, sizeof(SECRET32));
    wally_descriptor_free(output);
    return !found;
}
#endif /* BUILD_ELEMENTS */

/* Call wally_base58_from_bytes() deeper in the stack than in_stack() reaches,
 * so that searching does not overwrite what the call left behind */
WALLY_NO_OPTIMIZE static int base58_from_bytes_deep(const unsigned char *bytes, size_t bytes_len,
                                                    char **output)
{
    volatile unsigned char pad[1024];
    pad[0] = 0;
    return pad[0] + wally_base58_from_bytes(bytes, bytes_len, 0, output);
}

static bool test_base58_from_bytes(void)
{
    /* The bignum buffer is sized from an over-estimate of the number of
     * base58 digits. Encode data for which the estimate is several bytes
     * too large and check that the least significant digits, which are
     * stored at the end of the buffer, are wiped. */
    static const char *b58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    static unsigned char digits[6];
    static char *output;
    static size_t i, j, output_len;
    static bool found;

    gbytes[0] = 0x01;
    for (i = 1; i < 370; ++i)
        gbytes[i] = 0xa5;
    if (base58_from_bytes_deep(gbytes, 370, &output))
        return false;

    /* Convert the trailing base58 characters back to digit values */
    for (output_len = 0; output[output_len]; ++output_len)
        ; /* no-op */
    for (i = 0; i < sizeof(digits); ++i)
        for (j = 0; j < 58; ++j)
            if (b58[j] == output[output_len - sizeof(digits) + i])
                digits[i] = j;

    found = in_stack("wally_base58_from_bytes", digits, sizeof(digits));
    wally_free_string(output);
    return !found;
}

#ifdef BUILD_ELEMENTS
/* A PSET with one confidential input of 100000 sats (asset 0x25*32,
 * abf 0x11*32, vbf 0x22*32) and one output to blind */
static const char *BLIND_PSET = "cHNldP8BAgQCAAAAAQQBAQEFAQEBBgEDAfsEAgAAAAABAVoLXZOQQg73GhcdncZ2IRsoX8K03raepIsqn5inmqHxmywJwdRkuWPOKf3N4PCobr4N/9N0h+8Sxr9vKEZ7yk0uEUIAFgAUMzMzMzMzMzMzMzMzMzMzMzMzMzMBDiBERERERERERERERERERERERERERERERERERERERERERAEPBAAAAAAAAQMIoIYBAAAAAAABBBYAFDMzMzMzMzMzMzMzMzMzMzMzMzMzB/wEcHNldAIgJSUlJSUlJSUlJSUlJSUlJSUlJSUlJSUlJSUlJSUlJSUH/ARwc2V0BiECmsIDNes4do0gUr4du8PI9heEB0WOUea0rSLx2RdYiVsH/ARwc2V0CAQAAAAAAA==";
static const unsigned char BLIND_VALUE[9] = {
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x86, 0xa0
};
/* Scalars computed while blinding with entropy 0x01..0x20 repeated */
static const unsigned char BLIND_SECRETS[4][32] = {
    { /* Input scalar */
        0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
        0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xed, 0xe3,
        0xbf, 0x88, 0xbd, 0xfc, 0x93, 0xb0, 0x78, 0xfb,
        0xf0, 0xfa, 0xce, 0x27, 0x28, 0x0d, 0x8c, 0x38
    }, { /* Output scalar */
        0xb2, 0xdc, 0x05, 0x2e, 0x57, 0x80, 0xa9, 0xd2,
        0xfc, 0x25, 0x4e, 0x77, 0xa0, 0xc9, 0xf5, 0x0f,
        0xae, 0xfd, 0x79, 0x9d, 0xd3, 0x95, 0x40, 0xac,
        0x14, 0xc4, 0xba, 0xde, 0x90, 0x12, 0x26, 0x57
    }, { /* Output scalar - input scalar */
        0xe6, 0x0f, 0x38, 0x61, 0x8a, 0xb3, 0xdd, 0x06,
        0x2f, 0x58, 0x81, 0xaa, 0xd3, 0xfd, 0x07, 0x2a,
        0xaa, 0x23, 0x98, 0x87, 0xef, 0x2d, 0x67, 0xeb,
        0xe3, 0x9c, 0x4b, 0x44, 0x38, 0x3a, 0xdb, 0x60
    }, { /* Final vbf */
        0x1a, 0xf2, 0xca, 0xa2, 0x7a, 0x52, 0x2a, 0x01,
        0xd9, 0xb1, 0x89, 0x61, 0x39, 0x11, 0x07, 0xe4,
        0x21, 0x9d, 0x57, 0x72, 0xd5, 0x31, 0x4f, 0x67,
        0xf5, 0x50, 0x2e, 0x64, 0xb5, 0x19, 0x85, 0x01
    }
};

static bool test_psbt_blind(void)
{
    static struct wally_psbt *psbt;
    static struct wally_map values, vbfs, assets, abfs;
    static unsigned char asset[32], abf[32], vbf[32], entropy[32 * 5];
    static size_t i;
    static bool ok;

    memset(asset, 0x25, sizeof(asset));
    memset(abf, 0x11, sizeof(abf));
    memset(vbf, 0x22, sizeof(vbf));
    for (i = 0; i < sizeof(entropy); ++i)
        entropy[i] = (i % 32) + 1;

    ok = wally_psbt_from_base64(BLIND_PSET, 0, &psbt) == WALLY_OK &&
         wally_map_init(1, NULL, &values) == WALLY_OK &&
         wally_map_init(1, NULL, &vbfs) == WALLY_OK &&
         wally_map_init(1, NULL, &assets) == WALLY_OK &&
         wally_map_init(1, NULL, &abfs) == WALLY_OK &&
         wally_map_add_integer(&values, 0, BLIND_VALUE, sizeof(BLIND_VALUE)) == WALLY_OK &&
         wally_map_add_integer(&vbfs, 0, vbf, sizeof(vbf)) == WALLY_OK &&
         wally_map_add_integer(&assets, 0, asset, sizeof(asset)) == WALLY_OK &&
         wally_map_add_integer(&abfs, 0, abf, sizeof(abf)) == WALLY_OK &&
         wally_psbt_blind(psbt, &values, &vbfs, &assets, &abfs,
                          entropy, sizeof(entropy), WALLY_PSET_BLIND_ALL,
                          0, NULL) == WALLY_OK;

    for (i = 0; ok && i < sizeof(BLIND_SECRETS) / sizeof(BLIND_SECRETS[0]); ++i)
        ok = !in_stack("wally_psbt_blind", BLIND_SECRETS[i], sizeof(BLIND_SECRETS[i]));

    wally_map_clear(&values);
    wally_map_clear(&vbfs);
    wally_map_clear(&assets);
    wally_map_clear(&abfs);
    wally_psbt_free(psbt);
    return ok;
}
#endif /* BUILD_ELEMENTS */

static void *run_tests(void *passed_stack)
{
    if (passed_stack != gstack) {
        printf("stack mismatch!\n");
        return passed_stack;
    }

#define RUN(t) if (!t()) { printf(#t " wally_clear() test failed!\n"); return gstack; }

    /* Due to the nature of the test reading poisoned bytes off the custom stack will trigger ASAN */
    ASAN_UNPOISON_MEMORY_REGION(passed_stack, STACK_SIZE);
    if (!test_search()) {
        /* Usually means the optimizer has beaten our efforts to fight it,
         * or the compiler doesn't support e.g. no-optimize attributes. In
         * both cases the tests below will fail as memcmp alone will leak.
         */
        printf("WARNING: clear tests unreliable, skipping\n");
        return NULL; /* Don't fail test runs where the optimizer has won */
    }

    ASAN_UNPOISON_MEMORY_REGION(passed_stack, STACK_SIZE);
    RUN(test_bip39);

    ASAN_UNPOISON_MEMORY_REGION(passed_stack, STACK_SIZE);
    RUN(test_bip32_from_seed);

    ASAN_UNPOISON_MEMORY_REGION(passed_stack, STACK_SIZE);
    RUN(test_ec_private_key_verify);

    ASAN_UNPOISON_MEMORY_REGION(passed_stack, STACK_SIZE);
    RUN(test_ec_sig_from_bytes);

    ASAN_UNPOISON_MEMORY_REGION(passed_stack, STACK_SIZE);
    RUN(test_hmac_sha256);

    ASAN_UNPOISON_MEMORY_REGION(passed_stack, STACK_SIZE);
    RUN(test_ec_scalar_add_subtract);

#ifdef BUILD_ELEMENTS
    ASAN_UNPOISON_MEMORY_REGION(passed_stack, STACK_SIZE);
    RUN(test_elip150_private_key);

    ASAN_UNPOISON_MEMORY_REGION(passed_stack, STACK_SIZE);
    RUN(test_asset_scalar_offset);

    ASAN_UNPOISON_MEMORY_REGION(passed_stack, STACK_SIZE);
    RUN(test_descriptor_parse_ct_key);
#endif /* BUILD_ELEMENTS */

    ASAN_UNPOISON_MEMORY_REGION(passed_stack, STACK_SIZE);
    RUN(test_base58_from_bytes);

#ifdef BUILD_ELEMENTS
    ASAN_UNPOISON_MEMORY_REGION(passed_stack, STACK_SIZE);
    RUN(test_psbt_blind);
#endif /* BUILD_ELEMENTS */

    return NULL;
}

static int error(const char *fn, int ret)
{
    printf("error: %s failed, returned %d\n", fn, ret);
    return ret;
}

int main(void)
{
    pthread_t id;
    pthread_attr_t attr;
    void *tests_ok = &gstack; /* Anything non-null */
    int ret;

    gstack = checked_malloc(STACK_SIZE);
    gbytes = checked_malloc(64u * 1024u);

    ret = pthread_attr_init(&attr);
    if (ret)
        return error("pthread_attr_init", ret);

    ret = pthread_attr_setstack(&attr, gstack, STACK_SIZE);
    if (ret)
        return error("pthread_attr_setstack", ret);

    ret = pthread_create(&id, &attr, run_tests, gstack);
    if (ret)
        return error("pthread_create", ret);

    ret = pthread_join(id, &tests_ok);
    if (ret)
        return error("pthread_join", ret);

    free(gbytes);
    free(gstack);

    return tests_ok == NULL ? 0 : 1;
}
