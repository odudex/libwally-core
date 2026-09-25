/*
 * Check that PSA Crypto hash failures are reported to callers.
 *
 * The library is compiled here as a single translation unit, with the PSA
 * hash calls renamed to wrappers that can fail on demand. Each test case is
 * run once to count its PSA calls, then once with each of those calls
 * failing in turn (or, for cases making many calls, a sample of them): the
 * case must then return WALLY_ERROR. After every run, no PSA hash operation
 * may be left active, since PSA drivers may hold resources for active
 * operations (e.g. heap memory on ESP-IDF).
 */
#include "config.h"
#include <psa/crypto.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#define NO_FAILURE SIZE_MAX
#define MAX_ACTIVE 32

static size_t num_calls; /* PSA hash calls made in this run */
static size_t fail_at = NO_FAILURE; /* Index of the call to fail */
static bool injected; /* Whether the failure was injected */
static const psa_hash_operation_t *active[MAX_ACTIVE]; /* Active operations */
static bool too_many_active;
static bool setup_while_active; /* Whether an active operation was set up again */

static bool fail_this_call(void)
{
    if (num_calls++ != fail_at)
        return false;
    injected = true;
    return true;
}

static bool op_is_active(const psa_hash_operation_t *op)
{
    size_t i;
    for (i = 0; i < MAX_ACTIVE; ++i)
        if (active[i] == op)
            return true;
    return false;
}

static void set_active(const psa_hash_operation_t *op, bool is_active)
{
    size_t i, free_slot = MAX_ACTIVE;

    for (i = 0; i < MAX_ACTIVE; ++i) {
        if (active[i] == op) {
            if (!is_active)
                active[i] = NULL;
            return;
        }
        if (!active[i] && free_slot == MAX_ACTIVE)
            free_slot = i;
    }
    if (is_active) {
        if (free_slot == MAX_ACTIVE)
            too_many_active = true;
        else
            active[free_slot] = op;
    }
}

static size_t num_active(void)
{
    size_t i, n = 0;
    for (i = 0; i < MAX_ACTIVE; ++i)
        n += active[i] != NULL;
    return n;
}

/* Whether any PSA operation was leaked: left active, or set up again
 * while still active */
static bool ops_leaked(void)
{
    return num_active() || too_many_active || setup_while_active;
}

/* An operation is active from a successful setup until it is aborted or
 * successfully finished. The PSA API requires the caller to abort an
 * operation after an error, so an injected update or finish failure makes
 * no PSA call and leaves the operation active: only the caller's abort
 * makes it inactive */
static psa_status_t test_psa_hash_setup(psa_hash_operation_t *op, psa_algorithm_t alg)
{
    psa_status_t status;
    if (op_is_active(op))
        setup_while_active = true; /* The active operation is lost */
    if (fail_this_call())
        return PSA_ERROR_INSUFFICIENT_MEMORY;
    status = psa_hash_setup(op, alg);
    if (status == PSA_SUCCESS)
        set_active(op, true);
    return status;
}

static psa_status_t test_psa_hash_update(psa_hash_operation_t *op,
                                         const uint8_t *input, size_t input_len)
{
    if (fail_this_call())
        return PSA_ERROR_HARDWARE_FAILURE;
    return psa_hash_update(op, input, input_len);
}

static psa_status_t test_psa_hash_finish(psa_hash_operation_t *op, uint8_t *hash,
                                         size_t hash_size, size_t *hash_len)
{
    psa_status_t status;
    if (fail_this_call())
        return PSA_ERROR_HARDWARE_FAILURE;
    status = psa_hash_finish(op, hash, hash_size, hash_len);
    if (status == PSA_SUCCESS)
        set_active(op, false);
    return status;
}

static psa_status_t test_psa_hash_abort(psa_hash_operation_t *op)
{
    set_active(op, false);
    return psa_hash_abort(op);
}

static psa_status_t test_psa_hash_compute(psa_algorithm_t alg,
                                          const uint8_t *input, size_t input_len,
                                          uint8_t *hash, size_t hash_size,
                                          size_t *hash_len)
{
    if (fail_this_call())
        return PSA_ERROR_INSUFFICIENT_MEMORY;
    return psa_hash_compute(alg, input, input_len, hash, hash_size, hash_len);
}

#define psa_hash_setup test_psa_hash_setup
#define psa_hash_update test_psa_hash_update
#define psa_hash_finish test_psa_hash_finish
#define psa_hash_abort test_psa_hash_abort
#define psa_hash_compute test_psa_hash_compute
#include "../amalgamation/combined.c"
#undef psa_hash_setup
#undef psa_hash_update
#undef psa_hash_finish
#undef psa_hash_abort
#undef psa_hash_compute

/* Run a case, failing the given PSA call */
static int run_case(int (*fn)(void), size_t fail_index)
{
    num_calls = 0;
    fail_at = fail_index;
    injected = false;
    return fn();
}

static bool check_failure(const char *name, int (*fn)(void), size_t i, size_t total)
{
    int ret = run_case(fn, i);

    if (!injected) {
        printf("%s: PSA call %zu of %zu was not made\n", name, i, total);
        return false;
    }
    if (ret != WALLY_ERROR) {
        printf("%s: failing PSA call %zu of %zu returned %d, expected %d\n",
               name, i, total, ret, WALLY_ERROR);
        return false;
    }
    if (ops_leaked()) {
        printf("%s: failing PSA call %zu of %zu leaked PSA operations\n",
               name, i, total);
        return false;
    }
    return true;
}

/* Check a case with each of its PSA calls failing in turn. Cases making at
 * least twice max_runs calls (e.g. PBKDF2) are sampled instead, failing
 * about max_runs calls spaced by a fixed stride, always including the first
 * and last. The stride is odd so that, for a repeated sequence of calls
 * whose length is a power of 2 (such as the 8 calls of each HMAC), the
 * sampled calls cover every position in the sequence */
static bool check_case(const char *name, int (*fn)(void), size_t max_runs)
{
    size_t total, i, step;
    int ret = run_case(fn, NO_FAILURE);

    if (ret != WALLY_OK) {
        printf("%s: failed without any failure injected (%d)\n", name, ret);
        return false;
    }
    if (ops_leaked()) {
        printf("%s: leaked PSA operations\n", name);
        return false;
    }
    if (!(total = num_calls)) {
        printf("%s: made no PSA hash calls\n", name);
        return false;
    }
    step = (total / max_runs) | 1;
    for (i = 0; i < total; i += step)
        if (!check_failure(name, fn, i, total))
            return false;
    if ((total - 1) % step && !check_failure(name, fn, total - 1, total))
        return false;
    return true;
}

/*
 * Test cases. Each returns WALLY_OK when every call it makes succeeds.
 */
static const unsigned char MSG[] = "The quick brown fox jumps over the lazy dog";
static const unsigned char LONG_KEY[200] = { 1 }; /* Longer than a hash block */

static int case_sha256(void)
{
    unsigned char out[SHA256_LEN];
    return wally_sha256(MSG, sizeof(MSG), out, sizeof(out));
}

static int case_sha256d(void)
{
    unsigned char out[SHA256_LEN];
    return wally_sha256d(MSG, sizeof(MSG), out, sizeof(out));
}

static int case_sha512(void)
{
    unsigned char out[SHA512_LEN];
    return wally_sha512(MSG, sizeof(MSG), out, sizeof(out));
}

static int case_hash160(void)
{
    unsigned char out[HASH160_LEN];
    return wally_hash160(MSG, sizeof(MSG), out, sizeof(out));
}

static int case_bip340_tagged_hash(void)
{
    unsigned char out[SHA256_LEN];
    return wally_bip340_tagged_hash(MSG, sizeof(MSG), "TapLeaf", out, sizeof(out));
}

static int case_hmac_sha256(void)
{
    unsigned char out[HMAC_SHA256_LEN];
    int ret = wally_hmac_sha256(MSG, sizeof(MSG), MSG, sizeof(MSG), out, sizeof(out));
    if (ret == WALLY_OK)
        ret = wally_hmac_sha256(LONG_KEY, sizeof(LONG_KEY), MSG, sizeof(MSG), out, sizeof(out));
    return ret;
}

static int case_hmac_sha512(void)
{
    unsigned char out[HMAC_SHA512_LEN];
    int ret = wally_hmac_sha512(MSG, sizeof(MSG), MSG, sizeof(MSG), out, sizeof(out));
    if (ret == WALLY_OK)
        ret = wally_hmac_sha512(LONG_KEY, sizeof(LONG_KEY), MSG, sizeof(MSG), out, sizeof(out));
    return ret;
}

static int case_pbkdf2_hmac_sha256(void)
{
    unsigned char out[PBKDF2_HMAC_SHA256_LEN * 2];
    return wally_pbkdf2_hmac_sha256(MSG, sizeof(MSG), MSG, sizeof(MSG), 0, 3, out, sizeof(out));
}

static int case_pbkdf2_hmac_sha512(void)
{
    unsigned char out[PBKDF2_HMAC_SHA512_LEN * 2];
    return wally_pbkdf2_hmac_sha512(MSG, sizeof(MSG), MSG, sizeof(MSG), 0, 3, out, sizeof(out));
}


/*
 * keys cases
 */
/*
 * Key derivation and encoding cases: bip39, bip32, bip85, symmetric keys,
 * AES with ECDH keys, base58, WIF, bip38 and scrypt.
 *
 * Cases compare their outputs with known vectors, returning
 * KEYS_MISMATCH on a difference. A call that succeeds with wrong output
 * after an injected failure (i.e. a swallowed failure) is then reported
 * as returning KEYS_MISMATCH instead of WALLY_ERROR.
 */
enum { KEYS_MISMATCH = -100 };

/* BIP32 test vector 1 (seed 000102030405060708090a0b0c0d0e0f) */
static const char KEYS_BIP32_SEED[] = "000102030405060708090a0b0c0d0e0f";
static const char KEYS_M_XPRV[] = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
static const char KEYS_M_XPUB[] = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
static const char KEYS_M_PRV[] = "0488ade4000000000000000000873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d50800e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35";
static const char KEYS_M_PUB[] = "0488b21e000000000000000000873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d5080339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2";
static const char KEYS_M_CHAIN[] = "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508";
static const char KEYS_M_PRIV[] = "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35";
static const char KEYS_M_PUBKEY[] = "0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2";
static const char KEYS_M_H160[] = "3442193e1bb70916e914552172cd4e2dbc9df811";
/* m/0h */
static const char KEYS_H0_PRV[] = "0488ade4013442193e8000000047fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae623614100edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea";
static const char KEYS_H0_PUB[] = "0488b21e013442193e8000000047fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141035a784662a4a20a65bf6aab9ae98a6c068a81c52e4b032c0fb5400c706cfccc56";
static const char KEYS_H0_CHAIN[] = "47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141";
static const char KEYS_H0_PRIV[] = "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea";
static const char KEYS_H0_PUBKEY[] = "035a784662a4a20a65bf6aab9ae98a6c068a81c52e4b032c0fb5400c706cfccc56";
static const char KEYS_H0_H160[] = "5c1bd648ed23aa5fd50ba52b2457c11e9e80a6a7";
/* m/0h/1 */
static const char KEYS_H0_1_PRV[] = "0488ade4025c1bd648000000012a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c19003c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368";
static const char KEYS_H0_1_PUB[] = "0488b21e025c1bd648000000012a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c1903501e454bf00751f24b1b489aa925215d66af2234e3891c3b21a52bedb3cd711c";
static const char KEYS_H0_1_PUBKEY[] = "03501e454bf00751f24b1b489aa925215d66af2234e3891c3b21a52bedb3cd711c";
static const char KEYS_H0_1_H160[] = "bef5a2f9a56a94aab12459f72ad9cf8cf19c7bbe";
/* m/0h/1/2h */
static const char KEYS_H0_1_2H_PRV[] = "0488ade403bef5a2f98000000204466b9cc8e161e966409ca52986c584f07e9dc81f735db683c3ff6ec7b1503f00cbce0d719ecf7431d88e6a89fa1483e02e35092af60c042b1df2ff59fa424dca";
static const char KEYS_H0_1_2H_PUB[] = "0488b21e03bef5a2f98000000204466b9cc8e161e966409ca52986c584f07e9dc81f735db683c3ff6ec7b1503f0357bfe1e341d01c69fe5654309956cbea516822fba8a601743a012a7896ee8dc2";
static const char KEYS_H0_1_2H_H160[] = "ee7ab90cde56a8c0e2bb086ac49748b8db9dce72";

/* BIP39 */
static const char KEYS_MN_ABANDON[] = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
static const char KEYS_MN_LEGAL[] = "legal winner thank year wave sausage worth useful legal winner thank yellow";
static const char KEYS_MN_ZOO[] = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote";
/* 36 bytes of entropy 00 01 02 .. 23: a checksum spanning two bytes */
static const char KEYS_MN_36[] = "abandon amount liar amount expire adjust cage candy arch gather drum bullet absurd math era live bid rhythm alien crouch range attend journey tomato cancel baby struggle";
static const char KEYS_SEED_TREZOR[] = "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04";

/* BIP85 */
static const char KEYS_B85_CHAIN[] = "1b67969d1ec69bdfeeae43213da8460ba34b92d0788c8f7bfcfa44906e8a589c";
static const char KEYS_B85_PRIV[] = "3f15e5d852dc2e9ba5e9fe189a8dd2e1547badef5b563bbe6579fc6807d80ed9";
static const char KEYS_B85_H160[] = "627ef3a6babc4067d9a185eb2e6bc77cf46f82aa";
static const char KEYS_B85_BIP39_12[] = "6250b68daf746d12a24d58b4787a714b";
static const char KEYS_B85_RSA_1024_0[] = "b3415a819ba8175a7f11b949d75133725594ee3dcf6284dbec8fe6a625d0e0df757c148e576369f9405b19aec9356a848897de64202df8da4880a5f769aac297";

/* Symmetric keys (seed 01 * 16) */
static const char KEYS_SYM_MASTER[] = "c14fb20608fab55699cd071aea19bf019244da44c244a7e41f198d4c78870a391f31524a6148f270df0a26f70956ddc9575b20cc59ad813103af5d3ea9fd5cc4";
static const char KEYS_SYM_CHILD_SHORT[] = "cf8f122e3fcd9579c2b1cd0fa8a4418ed9e5e0366cf8f2baa4d03a71dbc86d3e46bda6a2800c401e5db6eae594227ed0a327316ae4904c95b8435a773abd0611";
static const char KEYS_SYM_CHILD_LONG[] = "8025621e96d1d05b22fa4438211ad958b67477879811aef9d81c971912df51b9d50b4d47b64b761ac18746815a9e1b966e285349fe83707afc35b8beeb5860e6";

/* AES with ECDH keys (from test_aes.py) */
static const char KEYS_AES_A_PRIV[] = "1c6a837d1ac663fdc7f1002327ca38452766eaf4fe3b80ce620bf7cd3f584cf6";
static const char KEYS_AES_A_PUB[] = "03e581be89d1ef8ce11d60746d08e4f8aedf934d1d861dd436042ee2e3b16db918";
static const char KEYS_AES_B_PRIV[] = "0b6b3dc90d203d854100110788ac87d43aa00620c9cdb361b281b09022ef4b53";
static const char KEYS_AES_B_PUB[] = "03ff06999ad61c0f3a733b93fc1e6b75ecfb1439b326e840de590a56454f0eeb0d";
static const char KEYS_AES_IV[] = "bd5d4724243880738e7e8b0c02658700";
static const char KEYS_AES_LABEL[] = "a sample label";
static const char KEYS_AES_PAYLOAD[] = "This is an example response/payload to encrypt";
static const char KEYS_AES_ENC[] = "bd5d4724243880738e7e8b0c026587003aacc57c5cefeff8381c3bc438d072d826b470cca55aa960a61655333de7dd8fe4561c44b68d2b37d41d16316f38d5dc4a5c859a9abcc65558f97e9d5aaf181624874573a69c66311c42ba1048a0c528";

/* WIF (from test_wif.py) */
static const char KEYS_WIF_PRIV[] = "0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d";
static const char KEYS_WIF_U[] = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ";
static const char KEYS_WIF_C[] = "KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617";
static const char KEYS_WIF_PUB_C[] = "02d0de0aaeaefad02b8bdc8a01a1b8b11c696bd3d66a2c5f10780d95b7df42645c";
static const char KEYS_WIF_PUB_U[] = "04d0de0aaeaefad02b8bdc8a01a1b8b11c696bd3d66a2c5f10780d95b7df42645cd85228a6fb29940e858e7e55842ae2bd115d1ed7cc0e82d934e929c97648cb0a";
static const char KEYS_WIF_ADDR_U[] = "1GAehh7TsJAHuUAeKZcXf5CnwuGuGgyX2S";
static const char KEYS_WIF_ADDR_C[] = "1LoVGDgRs9hTfTNJNuXKSpywcbdvwRXpmK";

/* BIP38 (from test_bip38.py) */
static const char KEYS_B38_PRIV_1[] = "cbf4b9f70470856bb4f40f80b87edb90865997ffee6df315ab166d713af433a5";
static const char KEYS_B38_PASS_1[] = "TestingOneTwoThree";
static const char KEYS_B38_ENC_1[] = "6PRVWUbkzzsbcVac2qwfssoUJAN1Xhrg6bNk8J7Nzm5H7kxEbn2Nh2ZoGg";
static const char KEYS_B38_ENC_1C[] = "6PYNKZ1EAgYgmQfmNVamxyXVWHzK5s6DGhwP4J5o44cvXdoY7sRzhtpUeo";
static const char KEYS_B38_PRIV_2[] = "09c2686880095b1a4c249ee3ac4eea8a014f11e6f986d0b5025ac1f39afbd9ae";
static const char KEYS_B38_PASS_2[] = "Satoshi";
static const char KEYS_B38_RAW_2[] = "0142e00b76ea60b62f66f0af93d8b5380652af51d1a3902ee00726cceb70ca636b5b57ce6d3e2f";
static const char KEYS_B38_PRIV_3[] = "3cbc4d1e5c5248f81338596c0b1ee025fbe6c112633c357d66d2ce0be541ea18";
static const char KEYS_B38_PASS_3[] = "jon";
static const char KEYS_B38_RAW_3[] = "0142e09f8ee6e3a2ffcb13a99aa976aeda5a2002ed3df97fcb9957cd863357b55aa2072d3eb2f9";

/* scrypt (draft-josefsson-scrypt-kdf-04) */
static const char KEYS_SCRYPT_1[] = "77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906";
static const char KEYS_SCRYPT_2[] = "fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640";

/* Decode a hex vector of exactly len bytes (makes no PSA calls) */
static int keys_hex(const char *hex, unsigned char *bytes_out, size_t len)
{
    size_t written;
    int ret = wally_hex_to_bytes(hex, bytes_out, len, &written);
    return ret == WALLY_OK && written != len ? WALLY_EINVAL : ret;
}

static bool keys_eq_hex(const unsigned char *bytes, size_t len, const char *hex)
{
    unsigned char buf[128];
    size_t written;
    return len <= sizeof(buf) &&
           wally_hex_to_bytes(hex, buf, sizeof(buf), &written) == WALLY_OK &&
           written == len && !memcmp(bytes, buf, len);
}

static bool keys_eq_str(const char *str, const char *expected)
{
    return str && !strcmp(str, expected);
}

static bool keys_is_zero(const void *p, size_t len)
{
    const unsigned char *bytes = p;
    size_t i;
    for (i = 0; i < len; ++i)
        if (bytes[i])
            return false;
    return true;
}

static int keys_expect(bool ok)
{
    return ok ? WALLY_OK : KEYS_MISMATCH;
}

static int keys_free_str(char **str)
{
    if (*str)
        wally_free_string(*str);
    *str = NULL;
    return WALLY_OK;
}

/* Compare a key's serialization with a hex vector */
static int keys_check_ser(const struct ext_key *key, uint32_t flags, const char *hex)
{
    unsigned char ser[BIP32_SERIALIZED_LEN];
    int ret = bip32_key_serialize(key, flags, ser, sizeof(ser));
    if (ret == WALLY_OK)
        ret = keys_expect(keys_eq_hex(ser, sizeof(ser), hex));
    return ret;
}

/* Initialize a key from raw vector fields, without any PSA calls */
static int keys_init_key(uint32_t version, uint32_t depth, uint32_t child_num,
                         const char *chain_hex, const char *pub_hex,
                         const char *priv_hex, const char *h160_hex,
                         const char *parent_h160_hex, struct ext_key *key_out)
{
    unsigned char chain[32], pub[EC_PUBLIC_KEY_LEN], priv[EC_PRIVATE_KEY_LEN];
    unsigned char h160[HASH160_LEN], parent160[HASH160_LEN];
    int ret = keys_hex(chain_hex, chain, sizeof(chain));
    if (ret == WALLY_OK && pub_hex)
        ret = keys_hex(pub_hex, pub, sizeof(pub));
    if (ret == WALLY_OK && priv_hex)
        ret = keys_hex(priv_hex, priv, sizeof(priv));
    if (ret == WALLY_OK && h160_hex)
        ret = keys_hex(h160_hex, h160, sizeof(h160));
    if (ret == WALLY_OK && parent_h160_hex)
        ret = keys_hex(parent_h160_hex, parent160, sizeof(parent160));
    if (ret == WALLY_OK)
        ret = bip32_key_init(version, depth, child_num, chain, sizeof(chain),
                             pub_hex ? pub : NULL, pub_hex ? sizeof(pub) : 0,
                             priv_hex ? priv : NULL, priv_hex ? sizeof(priv) : 0,
                             h160_hex ? h160 : NULL, h160_hex ? sizeof(h160) : 0,
                             parent_h160_hex ? parent160 : NULL,
                             parent_h160_hex ? sizeof(parent160) : 0, key_out);
    return ret;
}

static int keys_init_master(struct ext_key *key_out)
{
    return keys_init_key(BIP32_VER_MAIN_PRIVATE, 0, 0, KEYS_M_CHAIN,
                         KEYS_M_PUBKEY, KEYS_M_PRIV, KEYS_M_H160, NULL, key_out);
}

static int keys_init_h0(bool is_private, struct ext_key *key_out)
{
    return keys_init_key(is_private ? BIP32_VER_MAIN_PRIVATE : BIP32_VER_MAIN_PUBLIC,
                         1, BIP32_INITIAL_HARDENED_CHILD, KEYS_H0_CHAIN,
                         KEYS_H0_PUBKEY, is_private ? KEYS_H0_PRIV : NULL,
                         KEYS_H0_H160, KEYS_M_H160, key_out);
}

/*
 * BIP39
 */
static int case_keys_bip39_from_bytes(void)
{
    unsigned char entropy[36];
    char *mnemonic = NULL;
    size_t i;
    int ret;

    memset(entropy, 0, 16);
    ret = bip39_mnemonic_from_bytes(NULL, entropy, 16, &mnemonic);
    if (ret == WALLY_OK)
        ret = keys_expect(keys_eq_str(mnemonic, KEYS_MN_ABANDON));
    keys_free_str(&mnemonic);
    if (ret == WALLY_OK) {
        memset(entropy, 0xff, 32);
        ret = bip39_mnemonic_from_bytes(NULL, entropy, 32, &mnemonic);
    }
    if (ret == WALLY_OK)
        ret = keys_expect(keys_eq_str(mnemonic, KEYS_MN_ZOO));
    keys_free_str(&mnemonic);
    if (ret == WALLY_OK) {
        for (i = 0; i < sizeof(entropy); ++i)
            entropy[i] = i;
        ret = bip39_mnemonic_from_bytes(NULL, entropy, sizeof(entropy), &mnemonic);
    }
    if (ret == WALLY_OK)
        ret = keys_expect(keys_eq_str(mnemonic, KEYS_MN_36));
    keys_free_str(&mnemonic);
    return ret;
}

static int case_keys_bip39_to_bytes(void)
{
    unsigned char entropy[BIP39_ENTROPY_MAX_LEN], expected[36];
    size_t i, written;
    int ret = bip39_mnemonic_to_bytes(NULL, KEYS_MN_LEGAL, entropy,
                                      sizeof(entropy), &written);
    if (ret == WALLY_OK) {
        memset(expected, 0x7f, 16);
        ret = keys_expect(written == 16 && !memcmp(entropy, expected, 16));
    }
    if (ret == WALLY_OK)
        ret = bip39_mnemonic_to_bytes(NULL, KEYS_MN_36, entropy,
                                      sizeof(entropy), &written);
    if (ret == WALLY_OK) {
        for (i = 0; i < sizeof(expected); ++i)
            expected[i] = i;
        ret = keys_expect(written == sizeof(expected) &&
                          !memcmp(entropy, expected, sizeof(expected)));
    }
    return ret;
}

static int case_keys_bip39_validate(void)
{
    int ret = bip39_mnemonic_validate(NULL, KEYS_MN_ABANDON);
    if (ret == WALLY_OK)
        ret = bip39_mnemonic_validate(NULL, KEYS_MN_ZOO);
    return ret;
}

/* Written by the seed cases, for check_keys_bip39_seed_cleared */
static unsigned char keys_seed_out[BIP39_SEED_LEN_512];
static size_t keys_seed_written;

static int case_keys_bip39_to_seed512(void)
{
    int ret = bip39_mnemonic_to_seed512(KEYS_MN_ABANDON, "TREZOR", keys_seed_out,
                                        sizeof(keys_seed_out));
    if (ret == WALLY_OK)
        ret = keys_expect(keys_eq_hex(keys_seed_out, sizeof(keys_seed_out), KEYS_SEED_TREZOR));
    return ret;
}

static int case_keys_bip39_to_seed(void)
{
    int ret;
    keys_seed_written = 1234;
    ret = bip39_mnemonic_to_seed(KEYS_MN_ABANDON, "TREZOR", keys_seed_out,
                                 sizeof(keys_seed_out), &keys_seed_written);
    if (ret == WALLY_OK)
        ret = keys_expect(keys_seed_written == BIP39_SEED_LEN_512 &&
                          keys_eq_hex(keys_seed_out, sizeof(keys_seed_out), KEYS_SEED_TREZOR));
    return ret;
}

/*
 * BIP32
 */
static int case_keys_bip32_from_seed(void)
{
    unsigned char seed[16];
    struct ext_key key, *key_p = NULL;
    int ret = keys_hex(KEYS_BIP32_SEED, seed, sizeof(seed));
    if (ret == WALLY_OK)
        ret = bip32_key_from_seed(seed, sizeof(seed), BIP32_VER_MAIN_PRIVATE, 0, &key);
    if (ret == WALLY_OK)
        ret = keys_check_ser(&key, BIP32_FLAG_KEY_PRIVATE, KEYS_M_PRV);
    if (ret == WALLY_OK)
        ret = keys_expect(keys_eq_hex(key.hash160, sizeof(key.hash160), KEYS_M_H160));
    if (ret == WALLY_OK)
        ret = bip32_key_from_seed_alloc(seed, sizeof(seed), BIP32_VER_MAIN_PRIVATE, 0, &key_p);
    if (ret == WALLY_OK)
        ret = keys_expect(!memcmp(&key, key_p, sizeof(key)));
    if (key_p)
        bip32_key_free(key_p);
    return ret;
}

static int case_keys_bip32_from_seed_skip_hash(void)
{
    unsigned char seed[16];
    struct ext_key key;
    int ret = keys_hex(KEYS_BIP32_SEED, seed, sizeof(seed));
    if (ret == WALLY_OK)
        ret = bip32_key_from_seed(seed, sizeof(seed), BIP32_VER_MAIN_PRIVATE,
                                  BIP32_FLAG_SKIP_HASH, &key);
    if (ret == WALLY_OK)
        ret = keys_check_ser(&key, BIP32_FLAG_KEY_PRIVATE, KEYS_M_PRV);
    if (ret == WALLY_OK)
        ret = keys_expect(keys_is_zero(key.hash160, sizeof(key.hash160)));
    return ret;
}

/* A custom HMAC key longer than a SHA-512 block, which is hashed first */
static int case_keys_bip32_from_seed_custom(void)
{
    static const char KEYS_CUSTOM_PRV[] = "0488ade400000000000000000041d977c56e079af2683df20cf8fdc51f30277ecc6c5ffb4390ecd2c241cba2a500547d874adc6d7d0588438f5d7b0dcc1a67e8251071678f82210b2781a597bf94";
    static const char KEYS_CUSTOM_H160[] = "f3845adac05f37f2127731587ace969be58470ff";
    unsigned char seed[16], hmac_key[200] = { 1 };
    struct ext_key *key_p = NULL;
    int ret = keys_hex(KEYS_BIP32_SEED, seed, sizeof(seed));
    if (ret == WALLY_OK)
        ret = bip32_key_from_seed_custom_alloc(seed, sizeof(seed), BIP32_VER_MAIN_PRIVATE,
                                               hmac_key, sizeof(hmac_key), 0, &key_p);
    if (ret == WALLY_OK)
        ret = keys_check_ser(key_p, BIP32_FLAG_KEY_PRIVATE, KEYS_CUSTOM_PRV);
    if (ret == WALLY_OK)
        ret = keys_expect(keys_eq_hex(key_p->hash160, sizeof(key_p->hash160), KEYS_CUSTOM_H160));
    if (key_p)
        bip32_key_free(key_p);
    return ret;
}

/* Private parent -> private hardened child, and private -> public */
static int case_keys_bip32_from_parent_hardened(void)
{
    struct ext_key master, child, *child_p = NULL;
    int ret = keys_init_master(&master);
    if (ret == WALLY_OK)
        ret = bip32_key_from_parent(&master, BIP32_INITIAL_HARDENED_CHILD,
                                    BIP32_FLAG_KEY_PRIVATE, &child);
    if (ret == WALLY_OK)
        ret = keys_check_ser(&child, BIP32_FLAG_KEY_PRIVATE, KEYS_H0_PRV);
    if (ret == WALLY_OK)
        ret = keys_expect(keys_eq_hex(child.hash160, sizeof(child.hash160), KEYS_H0_H160));
    if (ret == WALLY_OK)
        ret = bip32_key_from_parent_alloc(&master, BIP32_INITIAL_HARDENED_CHILD,
                                          BIP32_FLAG_KEY_PUBLIC, &child_p);
    if (ret == WALLY_OK)
        ret = keys_check_ser(child_p, BIP32_FLAG_KEY_PUBLIC, KEYS_H0_PUB);
    if (ret == WALLY_OK)
        ret = keys_expect(keys_eq_hex(child_p->hash160, sizeof(child_p->hash160), KEYS_H0_H160));
    if (child_p)
        bip32_key_free(child_p);
    return ret;
}

/* Private parent -> private/public non-hardened child */
static int case_keys_bip32_from_parent_normal(void)
{
    struct ext_key parent, child;
    int ret = keys_init_h0(true, &parent);
    if (ret == WALLY_OK)
        ret = bip32_key_from_parent(&parent, 1, BIP32_FLAG_KEY_PRIVATE, &child);
    if (ret == WALLY_OK)
        ret = keys_check_ser(&child, BIP32_FLAG_KEY_PRIVATE, KEYS_H0_1_PRV);
    if (ret == WALLY_OK)
        ret = keys_expect(keys_eq_hex(child.hash160, sizeof(child.hash160), KEYS_H0_1_H160));
    if (ret == WALLY_OK)
        ret = bip32_key_from_parent(&parent, 1, BIP32_FLAG_KEY_PUBLIC, &child);
    if (ret == WALLY_OK)
        ret = keys_check_ser(&child, BIP32_FLAG_KEY_PUBLIC, KEYS_H0_1_PUB);
    return ret;
}

/* Public parent -> public child, with and without hash160 */
static int case_keys_bip32_from_parent_pub(void)
{
    struct ext_key parent, child;
    int ret = keys_init_h0(false, &parent);
    if (ret == WALLY_OK)
        ret = bip32_key_from_parent(&parent, 1, BIP32_FLAG_KEY_PUBLIC, &child);
    if (ret == WALLY_OK)
        ret = keys_check_ser(&child, BIP32_FLAG_KEY_PUBLIC, KEYS_H0_1_PUB);
    if (ret == WALLY_OK)
        ret = keys_expect(keys_eq_hex(child.hash160, sizeof(child.hash160), KEYS_H0_1_H160));
    if (ret == WALLY_OK)
        ret = bip32_key_from_parent(&parent, 1, BIP32_FLAG_KEY_PUBLIC | BIP32_FLAG_SKIP_HASH,
                                    &child);
    if (ret == WALLY_OK)
        ret = keys_expect(keys_eq_hex(child.pub_key, sizeof(child.pub_key), KEYS_H0_1_PUBKEY) &&
                          keys_is_zero(child.hash160, sizeof(child.hash160)) &&
                          keys_is_zero(child.parent160, sizeof(child.parent160)));
    return ret;
}

static int case_keys_bip32_from_parent_path(void)
{
    const uint32_t path[3] = { BIP32_INITIAL_HARDENED_CHILD, 1, BIP32_INITIAL_HARDENED_CHILD | 2 };
    struct ext_key master, child, *child_p = NULL;
    int ret = keys_init_master(&master);
    if (ret == WALLY_OK)
        ret = bip32_key_from_parent_path(&master, path, 3, BIP32_FLAG_KEY_PRIVATE, &child);
    if (ret == WALLY_OK)
        ret = keys_check_ser(&child, BIP32_FLAG_KEY_PRIVATE, KEYS_H0_1_2H_PRV);
    if (ret == WALLY_OK)
        ret = keys_expect(keys_eq_hex(child.hash160, sizeof(child.hash160), KEYS_H0_1_2H_H160));
    if (ret == WALLY_OK)
        ret = bip32_key_from_parent_path(&master, path, 3, BIP32_FLAG_KEY_PUBLIC, &child);
    if (ret == WALLY_OK)
        ret = keys_check_ser(&child, BIP32_FLAG_KEY_PUBLIC, KEYS_H0_1_2H_PUB);
    if (ret == WALLY_OK)
        ret = bip32_key_from_parent_path_str(&master, "m/0h/1/2h", 0,
                                             BIP32_FLAG_KEY_PRIVATE, &child);
    if (ret == WALLY_OK)
        ret = keys_check_ser(&child, BIP32_FLAG_KEY_PRIVATE, KEYS_H0_1_2H_PRV);
    if (ret == WALLY_OK)
        ret = bip32_key_from_parent_path_alloc(&master, path, 3,
                                               BIP32_FLAG_KEY_PRIVATE, &child_p);
    if (ret == WALLY_OK)
        ret = keys_check_ser(child_p, BIP32_FLAG_KEY_PRIVATE, KEYS_H0_1_2H_PRV);
    if (child_p)
        bip32_key_free(child_p);
    return ret;
}

/* Public derivation along a path from a public key */
static int case_keys_bip32_from_parent_path_pub(void)
{
    const uint32_t path[2] = { 1, 2 };
    unsigned char ser_priv[BIP32_SERIALIZED_LEN], ser_pub[BIP32_SERIALIZED_LEN];
    struct ext_key parent, child_priv, child_pub;
    int ret = keys_init_h0(true, &parent);
    if (ret == WALLY_OK)
        ret = bip32_key_from_parent_path(&parent, path, 2, BIP32_FLAG_KEY_PUBLIC, &child_priv);
    if (ret == WALLY_OK)
        ret = keys_init_h0(false, &parent);
    if (ret == WALLY_OK)
        ret = bip32_key_from_parent_path(&parent, path, 2, BIP32_FLAG_KEY_PUBLIC, &child_pub);
    if (ret == WALLY_OK)
        ret = bip32_key_serialize(&child_priv, BIP32_FLAG_KEY_PUBLIC, ser_priv, sizeof(ser_priv));
    if (ret == WALLY_OK)
        ret = bip32_key_serialize(&child_pub, BIP32_FLAG_KEY_PUBLIC, ser_pub, sizeof(ser_pub));
    if (ret == WALLY_OK)
        ret = keys_expect(!memcmp(ser_priv, ser_pub, sizeof(ser_pub)) &&
                          !memcmp(child_priv.hash160, child_pub.hash160, sizeof(child_pub.hash160)) &&
                          !keys_is_zero(child_pub.hash160, sizeof(child_pub.hash160)));
    return ret;
}

/* Elements: derivation accumulating the public key tweak sum. For a
 * non-hardened path, tweaking the parent public key by the sum gives
 * the derived public key */
static int case_keys_bip32_with_tweak_path(void)
{
    const uint32_t path[2] = { 1, 2 };
    struct ext_key master, child;
#ifdef BUILD_ELEMENTS
    struct ext_key *tweaked_p = NULL;
#endif
    int ret = keys_init_master(&master);
    if (ret == WALLY_OK)
        ret = bip32_key_from_parent_path(&master, path, 2, BIP32_FLAG_KEY_PUBLIC, &child);
#ifdef BUILD_ELEMENTS
    if (ret == WALLY_OK)
        ret = bip32_key_with_tweak_from_parent_path_alloc(&master, path, 2,
                                                          BIP32_FLAG_KEY_PUBLIC |
                                                          BIP32_FLAG_KEY_TWEAK_SUM,
                                                          &tweaked_p);
    if (ret == WALLY_OK)
        ret = keys_expect(!memcmp(tweaked_p->pub_key, child.pub_key, sizeof(child.pub_key)) &&
                          !keys_is_zero(tweaked_p->pub_key_tweak_sum,
                                        sizeof(tweaked_p->pub_key_tweak_sum)));
    if (tweaked_p)
        bip32_key_free(tweaked_p);
#endif
    return ret;
}

static int case_keys_bip32_base58(void)
{
    struct ext_key key, *key_p = NULL;
    char *str = NULL;
    int ret = bip32_key_from_base58(KEYS_M_XPRV, &key);
    if (ret == WALLY_OK)
        ret = keys_expect(keys_eq_hex(key.hash160, sizeof(key.hash160), KEYS_M_H160) &&
                          keys_eq_hex(key.priv_key + 1, sizeof(key.priv_key) - 1, KEYS_M_PRIV));
    if (ret == WALLY_OK)
        ret = bip32_key_to_base58(&key, BIP32_FLAG_KEY_PRIVATE, &str);
    if (ret == WALLY_OK)
        ret = keys_expect(keys_eq_str(str, KEYS_M_XPRV));
    keys_free_str(&str);
    if (ret == WALLY_OK)
        ret = bip32_key_to_base58(&key, BIP32_FLAG_KEY_PUBLIC, &str);
    if (ret == WALLY_OK)
        ret = keys_expect(keys_eq_str(str, KEYS_M_XPUB));
    keys_free_str(&str);
    if (ret == WALLY_OK)
        ret = bip32_key_from_base58_alloc(KEYS_M_XPUB, &key_p);
    if (ret == WALLY_OK)
        ret = keys_expect(keys_eq_hex(key_p->hash160, sizeof(key_p->hash160), KEYS_M_H160) &&
                          keys_eq_hex(key_p->pub_key, sizeof(key_p->pub_key), KEYS_M_PUBKEY));
    if (key_p)
        bip32_key_free(key_p);
    return ret;
}

static int case_keys_bip32_unserialize(void)
{
    unsigned char ser[BIP32_SERIALIZED_LEN];
    struct ext_key key, *key_p = NULL;
    int ret = keys_hex(KEYS_H0_PRV, ser, sizeof(ser));
    if (ret == WALLY_OK)
        ret = bip32_key_unserialize(ser, sizeof(ser), &key);
    if (ret == WALLY_OK)
        ret = keys_expect(keys_eq_hex(key.hash160, sizeof(key.hash160), KEYS_H0_H160) &&
                          keys_eq_hex(key.pub_key, sizeof(key.pub_key), KEYS_H0_PUBKEY));
    if (ret == WALLY_OK)
        ret = keys_hex(KEYS_H0_PUB, ser, sizeof(ser));
    if (ret == WALLY_OK)
        ret = bip32_key_unserialize_alloc(ser, sizeof(ser), &key_p);
    if (ret == WALLY_OK)
        ret = keys_expect(keys_eq_hex(key_p->hash160, sizeof(key_p->hash160), KEYS_H0_H160) &&
                          key_p->priv_key[0] == BIP32_FLAG_KEY_PUBLIC);
    if (key_p)
        bip32_key_free(key_p);
    return ret;
}

/* bip32_key_init with and without hash160 */
static int case_keys_bip32_init(void)
{
    struct ext_key key, *key_p = NULL;
    /* With hash160 given: no hashing */
    int ret = keys_init_master(&key);
    if (ret == WALLY_OK)
        ret = keys_check_ser(&key, BIP32_FLAG_KEY_PRIVATE, KEYS_M_PRV);
    /* Private, no public key or hash160: both are computed */
    if (ret == WALLY_OK)
        ret = keys_init_key(BIP32_VER_MAIN_PRIVATE, 0, 0, KEYS_M_CHAIN,
                            NULL, KEYS_M_PRIV, NULL, NULL, &key);
    if (ret == WALLY_OK)
        ret = keys_expect(keys_eq_hex(key.hash160, sizeof(key.hash160), KEYS_M_H160) &&
                          keys_eq_hex(key.pub_key, sizeof(key.pub_key), KEYS_M_PUBKEY));
    if (ret == WALLY_OK)
        ret = keys_check_ser(&key, BIP32_FLAG_KEY_PRIVATE, KEYS_M_PRV);
    if (ret == WALLY_OK)
        ret = keys_check_ser(&key, BIP32_FLAG_KEY_PUBLIC, KEYS_M_PUB);
    /* Public, no hash160 */
    if (ret == WALLY_OK)
        ret = keys_init_key(BIP32_VER_MAIN_PUBLIC, 1, BIP32_INITIAL_HARDENED_CHILD,
                            KEYS_H0_CHAIN, KEYS_H0_PUBKEY, NULL, NULL, KEYS_M_H160, &key);
    if (ret == WALLY_OK)
        ret = keys_expect(keys_eq_hex(key.hash160, sizeof(key.hash160), KEYS_H0_H160));
    if (ret == WALLY_OK)
        ret = keys_check_ser(&key, BIP32_FLAG_KEY_PUBLIC, KEYS_H0_PUB);
    /* Allocated, no hash160 */
    if (ret == WALLY_OK) {
        unsigned char chain[32], priv[EC_PRIVATE_KEY_LEN];
        ret = keys_hex(KEYS_M_CHAIN, chain, sizeof(chain));
        if (ret == WALLY_OK)
            ret = keys_hex(KEYS_M_PRIV, priv, sizeof(priv));
        if (ret == WALLY_OK)
            ret = bip32_key_init_alloc(BIP32_VER_MAIN_PRIVATE, 0, 0, chain, sizeof(chain),
                                       NULL, 0, priv, sizeof(priv), NULL, 0, NULL, 0, &key_p);
    }
    if (ret == WALLY_OK)
        ret = keys_expect(keys_eq_hex(key_p->hash160, sizeof(key_p->hash160), KEYS_M_H160));
    if (key_p)
        bip32_key_free(key_p);
    return ret;
}

/* Fingerprints of keys whose hash160 was not computed */
static int case_keys_bip32_fingerprint(void)
{
    unsigned char seed[16], fp[BIP32_KEY_FINGERPRINT_LEN];
    struct ext_key key, child;
    int ret = keys_hex(KEYS_BIP32_SEED, seed, sizeof(seed));
    if (ret == WALLY_OK)
        ret = bip32_key_from_seed(seed, sizeof(seed), BIP32_VER_MAIN_PRIVATE,
                                  BIP32_FLAG_SKIP_HASH, &key);
    if (ret == WALLY_OK)
        ret = bip32_key_get_fingerprint(&key, fp, sizeof(fp));
    if (ret == WALLY_OK)
        ret = keys_expect(keys_eq_hex(fp, sizeof(fp), "3442193e") &&
                          keys_eq_hex(key.hash160, sizeof(key.hash160), KEYS_M_H160));
    if (ret == WALLY_OK)
        ret = bip32_key_get_fingerprint(&key, fp, sizeof(fp)); /* Cached */
    if (ret == WALLY_OK)
        ret = keys_expect(keys_eq_hex(fp, sizeof(fp), "3442193e"));
    if (ret == WALLY_OK)
        ret = bip32_key_from_parent(&key, BIP32_INITIAL_HARDENED_CHILD,
                                    BIP32_FLAG_KEY_PRIVATE | BIP32_FLAG_SKIP_HASH, &child);
    if (ret == WALLY_OK)
        ret = keys_expect(keys_is_zero(child.hash160, sizeof(child.hash160)));
    if (ret == WALLY_OK)
        ret = bip32_key_get_fingerprint(&child, fp, sizeof(fp));
    if (ret == WALLY_OK)
        ret = keys_expect(keys_eq_hex(fp, sizeof(fp), "5c1bd648"));
    return ret;
}

/* State for check_keys_bip32_fingerprint_retry */
static struct ext_key keys_fp_key;
static unsigned char keys_fp_out[BIP32_KEY_FINGERPRINT_LEN];

static int keys_fp_make_key(void)
{
    unsigned char seed[16];
    int ret = keys_hex(KEYS_BIP32_SEED, seed, sizeof(seed));
    if (ret == WALLY_OK)
        ret = bip32_key_from_seed(seed, sizeof(seed), BIP32_VER_MAIN_PRIVATE,
                                  BIP32_FLAG_SKIP_HASH, &keys_fp_key);
    return ret;
}

static int keys_fp_get(void)
{
    memset(keys_fp_out, 0xaa, sizeof(keys_fp_out));
    return bip32_key_get_fingerprint(&keys_fp_key, keys_fp_out, sizeof(keys_fp_out));
}

/* A failed fingerprint computation must not be cached: the next call
 * must compute and return the correct fingerprint */
static bool check_keys_bip32_fingerprint_retry(void)
{
    const char *name = "check_keys_bip32_fingerprint_retry";
    size_t i, total;
    int ret;

    if (run_case(keys_fp_make_key, NO_FAILURE) != WALLY_OK ||
        run_case(keys_fp_get, NO_FAILURE) != WALLY_OK ||
        !keys_eq_hex(keys_fp_out, sizeof(keys_fp_out), "3442193e")) {
        printf("%s: fingerprint failed without any failure injected\n", name);
        return false;
    }
    if (!(total = num_calls)) {
        printf("%s: fingerprint made no PSA hash calls\n", name);
        return false;
    }
    for (i = 0; i < total; ++i) {
        if (run_case(keys_fp_make_key, NO_FAILURE) != WALLY_OK ||
            !keys_is_zero(keys_fp_key.hash160, sizeof(keys_fp_key.hash160))) {
            printf("%s: key creation failed\n", name);
            return false;
        }
        ret = run_case(keys_fp_get, i);
        if (!injected || ret != WALLY_ERROR || ops_leaked()) {
            printf("%s: failing PSA call %zu of %zu returned %d, expected %d\n",
                   name, i, total, ret, WALLY_ERROR);
            return false;
        }
        if (!keys_is_zero(keys_fp_key.hash160, sizeof(keys_fp_key.hash160))) {
            printf("%s: failing PSA call %zu of %zu left a non-zero hash160 cached\n",
                   name, i, total);
            return false;
        }
        ret = run_case(keys_fp_get, NO_FAILURE);
        if (ret != WALLY_OK || !keys_eq_hex(keys_fp_out, sizeof(keys_fp_out), "3442193e") ||
            !keys_eq_hex(keys_fp_key.hash160, sizeof(keys_fp_key.hash160), KEYS_M_H160)) {
            printf("%s: after failing PSA call %zu of %zu, the next call returned %d "
                   "with an incorrect fingerprint\n", name, i, total, ret);
            return false;
        }
    }
    return true;
}

/* State for check_keys_bip32_failure_wipes_key */
static struct ext_key keys_wipe_key;

static int keys_wipe_from_seed(void)
{
    unsigned char seed[16];
    int ret = keys_hex(KEYS_BIP32_SEED, seed, sizeof(seed));
    memset(&keys_wipe_key, 0xaa, sizeof(keys_wipe_key));
    if (ret == WALLY_OK)
        ret = bip32_key_from_seed(seed, sizeof(seed), BIP32_VER_MAIN_PRIVATE, 0, &keys_wipe_key);
    return ret;
}

static int keys_wipe_from_parent(void)
{
    struct ext_key master;
    int ret = keys_init_master(&master);
    memset(&keys_wipe_key, 0xaa, sizeof(keys_wipe_key));
    if (ret == WALLY_OK)
        ret = bip32_key_from_parent(&master, BIP32_INITIAL_HARDENED_CHILD,
                                    BIP32_FLAG_KEY_PRIVATE, &keys_wipe_key);
    return ret;
}

static int keys_wipe_unserialize(void)
{
    unsigned char ser[BIP32_SERIALIZED_LEN];
    int ret = keys_hex(KEYS_H0_PRV, ser, sizeof(ser));
    memset(&keys_wipe_key, 0xaa, sizeof(keys_wipe_key));
    if (ret == WALLY_OK)
        ret = bip32_key_unserialize(ser, sizeof(ser), &keys_wipe_key);
    return ret;
}

static int keys_wipe_init(void)
{
    memset(&keys_wipe_key, 0xaa, sizeof(keys_wipe_key));
    return keys_init_key(BIP32_VER_MAIN_PRIVATE, 0, 0, KEYS_M_CHAIN,
                         NULL, KEYS_M_PRIV, NULL, NULL, &keys_wipe_key);
}

/* A failed key derivation/import must not leave (partial) private key
 * material in the output key */
static bool check_keys_bip32_failure_wipes_key(void)
{
    static const struct {
        const char *name;
        int (*fn)(void);
    } fns[] = {
        { "bip32_key_from_seed", keys_wipe_from_seed },
        { "bip32_key_from_parent", keys_wipe_from_parent },
        { "bip32_key_unserialize", keys_wipe_unserialize },
        { "bip32_key_init", keys_wipe_init },
    };
    size_t f, i, total;
    int ret;
    bool ok = true;

    for (f = 0; f < sizeof(fns) / sizeof(fns[0]); ++f) {
        if (run_case(fns[f].fn, NO_FAILURE) != WALLY_OK || !(total = num_calls)) {
            printf("check_keys_bip32_failure_wipes_key: %s failed without any failure injected\n",
                   fns[f].name);
            ok = false;
            continue;
        }
        for (i = 0; i < total; ++i) {
            ret = run_case(fns[f].fn, i);
            if (!injected || ret != WALLY_ERROR) {
                printf("check_keys_bip32_failure_wipes_key: %s: failing PSA call %zu of %zu "
                       "returned %d, expected %d\n", fns[f].name, i, total, ret, WALLY_ERROR);
                ok = false;
                break;
            }
            if (!keys_is_zero(&keys_wipe_key, sizeof(keys_wipe_key))) {
                printf("check_keys_bip32_failure_wipes_key: %s: failing PSA call %zu of %zu "
                       "did not wipe the output key\n", fns[f].name, i, total);
                ok = false;
                break;
            }
        }
    }
    return ok;
}

/*
 * BIP85
 */
static int keys_init_bip85_master(struct ext_key *key_out)
{
    return keys_init_key(BIP32_VER_MAIN_PRIVATE, 0, 0, KEYS_B85_CHAIN,
                         NULL, KEYS_B85_PRIV, KEYS_B85_H160, NULL, key_out);
}

static int case_keys_bip85_bip39_entropy(void)
{
    unsigned char out[HMAC_SHA512_LEN];
    struct ext_key master;
    size_t written;
    int ret = keys_init_bip85_master(&master);
    if (ret == WALLY_OK)
        ret = bip85_get_bip39_entropy(&master, "en", 12, 0, out, sizeof(out), &written);
    if (ret == WALLY_OK)
        ret = keys_expect(written == BIP39_ENTROPY_LEN_128 &&
                          keys_eq_hex(out, written, KEYS_B85_BIP39_12));
    return ret;
}

static int case_keys_bip85_rsa_entropy(void)
{
    unsigned char out[HMAC_SHA512_LEN];
    struct ext_key master;
    size_t written;
    int ret = keys_init_bip85_master(&master);
    if (ret == WALLY_OK)
        ret = bip85_get_rsa_entropy(&master, 1024, 0, out, sizeof(out), &written);
    if (ret == WALLY_OK)
        ret = keys_expect(written == HMAC_SHA512_LEN &&
                          keys_eq_hex(out, written, KEYS_B85_RSA_1024_0));
    return ret;
}

/*
 * Symmetric keys
 */
static int case_keys_symmetric_key(void)
{
    unsigned char seed[16], master[HMAC_SHA512_LEN], child[HMAC_SHA512_LEN];
    unsigned char label[65];
    int ret;

    memset(seed, 0x01, sizeof(seed));
    ret = wally_symmetric_key_from_seed(seed, sizeof(seed), master, sizeof(master));
    if (ret == WALLY_OK)
        ret = keys_expect(keys_eq_hex(master, sizeof(master), KEYS_SYM_MASTER));
    if (ret == WALLY_OK) {
        label[0] = 0x0f;
        label[1] = label[2] = 0;
        ret = wally_symmetric_key_from_parent(master, sizeof(master), 0, label, 3,
                                              child, sizeof(child));
    }
    if (ret == WALLY_OK)
        ret = keys_expect(keys_eq_hex(child, sizeof(child), KEYS_SYM_CHILD_SHORT));
    if (ret == WALLY_OK) {
        /* A label too long for the stack buffer */
        memset(label, 0x0f, sizeof(label));
        ret = wally_symmetric_key_from_parent(master, sizeof(master), 0, label, sizeof(label),
                                              child, sizeof(child));
    }
    if (ret == WALLY_OK)
        ret = keys_expect(keys_eq_hex(child, sizeof(child), KEYS_SYM_CHILD_LONG));
    return ret;
}

/*
 * AES with ECDH keys
 */
static int case_keys_aes_ecdh_encrypt(void)
{
    unsigned char priv[EC_PRIVATE_KEY_LEN], pub[EC_PUBLIC_KEY_LEN], iv[AES_BLOCK_LEN];
    unsigned char out[96];
    const size_t payload_len = sizeof(KEYS_AES_PAYLOAD) - 1;
    size_t written;
    int ret = keys_hex(KEYS_AES_B_PRIV, priv, sizeof(priv));
    if (ret == WALLY_OK)
        ret = keys_hex(KEYS_AES_A_PUB, pub, sizeof(pub));
    if (ret == WALLY_OK)
        ret = keys_hex(KEYS_AES_IV, iv, sizeof(iv));
    if (ret == WALLY_OK)
        ret = wally_aes_cbc_with_ecdh_key(priv, sizeof(priv), iv, sizeof(iv),
                                          (const unsigned char *)KEYS_AES_PAYLOAD, payload_len,
                                          pub, sizeof(pub),
                                          (const unsigned char *)KEYS_AES_LABEL,
                                          sizeof(KEYS_AES_LABEL) - 1, AES_FLAG_ENCRYPT,
                                          out, sizeof(out), &written);
    if (ret == WALLY_OK)
        ret = keys_expect(written == sizeof(out) && keys_eq_hex(out, written, KEYS_AES_ENC));
    return ret;
}

static int case_keys_aes_ecdh_decrypt(void)
{
    unsigned char priv[EC_PRIVATE_KEY_LEN], pub[EC_PUBLIC_KEY_LEN], enc[96], out[48];
    const size_t payload_len = sizeof(KEYS_AES_PAYLOAD) - 1;
    size_t written;
    int ret = keys_hex(KEYS_AES_A_PRIV, priv, sizeof(priv));
    if (ret == WALLY_OK)
        ret = keys_hex(KEYS_AES_B_PUB, pub, sizeof(pub));
    if (ret == WALLY_OK)
        ret = keys_hex(KEYS_AES_ENC, enc, sizeof(enc));
    if (ret == WALLY_OK)
        ret = wally_aes_cbc_with_ecdh_key(priv, sizeof(priv), NULL, 0, enc, sizeof(enc),
                                          pub, sizeof(pub),
                                          (const unsigned char *)KEYS_AES_LABEL,
                                          sizeof(KEYS_AES_LABEL) - 1, AES_FLAG_DECRYPT,
                                          out, sizeof(out), &written);
    if (ret == WALLY_OK)
        ret = keys_expect(written == payload_len && !memcmp(out, KEYS_AES_PAYLOAD, payload_len));
    return ret;
}

/*
 * Base58 with checksums
 */
static int case_keys_base58_checksum(void)
{
    unsigned char ser[BIP32_SERIALIZED_LEN], buf[BIP32_SERIALIZED_LEN + BASE58_CHECKSUM_LEN];
    unsigned char addr[1 + HASH160_LEN + BASE58_CHECKSUM_LEN];
    char *str = NULL;
    size_t written;
    int ret = keys_hex(KEYS_M_PRV, ser, sizeof(ser));
    if (ret == WALLY_OK)
        ret = wally_base58_from_bytes(ser, sizeof(ser), BASE58_FLAG_CHECKSUM, &str);
    if (ret == WALLY_OK)
        ret = keys_expect(keys_eq_str(str, KEYS_M_XPRV));
    keys_free_str(&str);
    if (ret == WALLY_OK)
        ret = wally_base58_to_bytes(KEYS_M_XPRV, BASE58_FLAG_CHECKSUM, buf, sizeof(buf), &written);
    if (ret == WALLY_OK)
        ret = keys_expect(written == sizeof(ser) && !memcmp(buf, ser, sizeof(ser)));
    /* An address, with a leading zero byte */
    if (ret == WALLY_OK)
        ret = wally_base58_to_bytes(KEYS_WIF_ADDR_U, BASE58_FLAG_CHECKSUM, addr, sizeof(addr), &written);
    if (ret == WALLY_OK)
        ret = keys_expect(written == 1 + HASH160_LEN && addr[0] == 0);
    if (ret == WALLY_OK)
        ret = wally_base58_from_bytes(addr, written, BASE58_FLAG_CHECKSUM, &str);
    if (ret == WALLY_OK)
        ret = keys_expect(keys_eq_str(str, KEYS_WIF_ADDR_U));
    keys_free_str(&str);
    return ret;
}

/*
 * WIF
 */
static int case_keys_wif_from_bytes(void)
{
    unsigned char priv[EC_PRIVATE_KEY_LEN];
    char *str = NULL;
    int ret = keys_hex(KEYS_WIF_PRIV, priv, sizeof(priv));
    if (ret == WALLY_OK)
        ret = wally_wif_from_bytes(priv, sizeof(priv), WALLY_ADDRESS_VERSION_WIF_MAINNET,
                                   WALLY_WIF_FLAG_COMPRESSED, &str);
    if (ret == WALLY_OK)
        ret = keys_expect(keys_eq_str(str, KEYS_WIF_C));
    keys_free_str(&str);
    if (ret == WALLY_OK)
        ret = wally_wif_from_bytes(priv, sizeof(priv), WALLY_ADDRESS_VERSION_WIF_MAINNET,
                                   WALLY_WIF_FLAG_UNCOMPRESSED, &str);
    if (ret == WALLY_OK)
        ret = keys_expect(keys_eq_str(str, KEYS_WIF_U));
    keys_free_str(&str);
    return ret;
}

static int case_keys_wif_to_bytes(void)
{
    unsigned char priv[EC_PRIVATE_KEY_LEN];
    int ret = wally_wif_to_bytes(KEYS_WIF_C, WALLY_ADDRESS_VERSION_WIF_MAINNET,
                                 WALLY_WIF_FLAG_COMPRESSED, priv, sizeof(priv));
    if (ret == WALLY_OK)
        ret = keys_expect(keys_eq_hex(priv, sizeof(priv), KEYS_WIF_PRIV));
    if (ret == WALLY_OK)
        ret = wally_wif_to_bytes(KEYS_WIF_U, WALLY_ADDRESS_VERSION_WIF_MAINNET,
                                 WALLY_WIF_FLAG_UNCOMPRESSED, priv, sizeof(priv));
    if (ret == WALLY_OK)
        ret = keys_expect(keys_eq_hex(priv, sizeof(priv), KEYS_WIF_PRIV));
    return ret;
}

static int case_keys_wif_is_uncompressed(void)
{
    size_t uncompressed = 2;
    int ret = wally_wif_is_uncompressed(KEYS_WIF_C, &uncompressed);
    if (ret == WALLY_OK)
        ret = keys_expect(uncompressed == 0);
    if (ret == WALLY_OK)
        ret = wally_wif_is_uncompressed(KEYS_WIF_U, &uncompressed);
    if (ret == WALLY_OK)
        ret = keys_expect(uncompressed == 1);
    return ret;
}

static int case_keys_wif_to_public_key(void)
{
    unsigned char pub[EC_PUBLIC_KEY_UNCOMPRESSED_LEN];
    size_t written;
    int ret = wally_wif_to_public_key(KEYS_WIF_C, WALLY_ADDRESS_VERSION_WIF_MAINNET,
                                      pub, sizeof(pub), &written);
    if (ret == WALLY_OK)
        ret = keys_expect(written == EC_PUBLIC_KEY_LEN &&
                          keys_eq_hex(pub, written, KEYS_WIF_PUB_C));
    if (ret == WALLY_OK)
        ret = wally_wif_to_public_key(KEYS_WIF_U, WALLY_ADDRESS_VERSION_WIF_MAINNET,
                                      pub, sizeof(pub), &written);
    if (ret == WALLY_OK)
        ret = keys_expect(written == EC_PUBLIC_KEY_UNCOMPRESSED_LEN &&
                          keys_eq_hex(pub, written, KEYS_WIF_PUB_U));
    return ret;
}

static int case_keys_wif_to_address(void)
{
    char *str = NULL;
    int ret = wally_wif_to_address(KEYS_WIF_C, WALLY_ADDRESS_VERSION_WIF_MAINNET,
                                   WALLY_ADDRESS_VERSION_P2PKH_MAINNET, &str);
    if (ret == WALLY_OK)
        ret = keys_expect(keys_eq_str(str, KEYS_WIF_ADDR_C));
    keys_free_str(&str);
    if (ret == WALLY_OK)
        ret = wally_wif_to_address(KEYS_WIF_U, WALLY_ADDRESS_VERSION_WIF_MAINNET,
                                   WALLY_ADDRESS_VERSION_P2PKH_MAINNET, &str);
    if (ret == WALLY_OK)
        ret = keys_expect(keys_eq_str(str, KEYS_WIF_ADDR_U));
    keys_free_str(&str);
    return ret;
}

/*
 * BIP38 (scrypt with N=16384, r=8, p=8: sample these)
 */
static int case_keys_bip38_raw_from_private_key(void)
{
    unsigned char priv[EC_PRIVATE_KEY_LEN], out[BIP38_SERIALIZED_LEN];
    int ret = keys_hex(KEYS_B38_PRIV_2, priv, sizeof(priv));
    if (ret == WALLY_OK)
        ret = bip38_raw_from_private_key(priv, sizeof(priv),
                                         (const unsigned char *)KEYS_B38_PASS_2,
                                         sizeof(KEYS_B38_PASS_2) - 1,
                                         BIP38_KEY_MAINNET | BIP38_KEY_COMPRESSED | BIP38_KEY_RAW_MODE,
                                         out, sizeof(out));
    if (ret == WALLY_OK)
        ret = keys_expect(keys_eq_hex(out, sizeof(out), KEYS_B38_RAW_2));
    return ret;
}

static int case_keys_bip38_raw_to_private_key(void)
{
    unsigned char raw[BIP38_SERIALIZED_LEN], priv[EC_PRIVATE_KEY_LEN];
    int ret = keys_hex(KEYS_B38_RAW_3, raw, sizeof(raw));
    if (ret == WALLY_OK)
        ret = bip38_raw_to_private_key(raw, sizeof(raw),
                                       (const unsigned char *)KEYS_B38_PASS_3,
                                       sizeof(KEYS_B38_PASS_3) - 1,
                                       BIP38_KEY_MAINNET | BIP38_KEY_COMPRESSED |
                                       BIP38_KEY_RAW_MODE | BIP38_KEY_SWAP_ORDER,
                                       priv, sizeof(priv));
    if (ret == WALLY_OK)
        ret = keys_expect(keys_eq_hex(priv, sizeof(priv), KEYS_B38_PRIV_3));
    return ret;
}

static int case_keys_bip38_from_private_key(void)
{
    unsigned char priv[EC_PRIVATE_KEY_LEN];
    char *str = NULL;
    int ret = keys_hex(KEYS_B38_PRIV_1, priv, sizeof(priv));
    if (ret == WALLY_OK)
        ret = bip38_from_private_key(priv, sizeof(priv),
                                     (const unsigned char *)KEYS_B38_PASS_1,
                                     sizeof(KEYS_B38_PASS_1) - 1, BIP38_KEY_MAINNET, &str);
    if (ret == WALLY_OK)
        ret = keys_expect(keys_eq_str(str, KEYS_B38_ENC_1));
    keys_free_str(&str);
    return ret;
}

/* Written by case_keys_bip38_to_private_key, for check_keys_bip38_no_unverified_key */
static unsigned char keys_b38_out[EC_PRIVATE_KEY_LEN];

static int case_keys_bip38_to_private_key(void)
{
    int ret = bip38_to_private_key(KEYS_B38_ENC_1C, (const unsigned char *)KEYS_B38_PASS_1,
                                   sizeof(KEYS_B38_PASS_1) - 1,
                                   BIP38_KEY_MAINNET | BIP38_KEY_COMPRESSED,
                                   keys_b38_out, sizeof(keys_b38_out));
    if (ret == WALLY_OK)
        ret = keys_expect(keys_eq_hex(keys_b38_out, sizeof(keys_b38_out), KEYS_B38_PRIV_1));
    return ret;
}

/* Structure-only checks: no scrypt */
static int case_keys_bip38_quick_check(void)
{
    size_t flags = 0;
    int ret = bip38_to_private_key(KEYS_B38_ENC_1C, NULL, 0,
                                   BIP38_KEY_MAINNET | BIP38_KEY_QUICK_CHECK, NULL, 0);
    if (ret == WALLY_OK)
        ret = bip38_get_flags(KEYS_B38_ENC_1C, &flags);
    if (ret == WALLY_OK)
        ret = keys_expect(flags == BIP38_KEY_COMPRESSED);
    return ret;
}

/* When scrypt's final PBKDF2 or the checks after decryption fail, the
 * (unverified) decrypted key must not be returned */
static bool check_keys_bip38_no_unverified_key(void)
{
    const char *name = "check_keys_bip38_no_unverified_key";
    /* The last PBKDF2 call in scrypt, then the address checks after
     * decryption: sha256 + 2x sha256d */
    const size_t num_final = 6;
    size_t i, total;
    int ret;

    if (run_case(case_keys_bip38_to_private_key, NO_FAILURE) != WALLY_OK) {
        printf("%s: failed without any failure injected\n", name);
        return false;
    }
    total = num_calls;
    if (total < num_final) {
        printf("%s: too few PSA calls (%zu)\n", name, total);
        return false;
    }
    for (i = total - num_final; i < total; ++i) {
        memset(keys_b38_out, 0, sizeof(keys_b38_out));
        ret = run_case(case_keys_bip38_to_private_key, i);
        if (!injected || ret != WALLY_ERROR) {
            printf("%s: failing PSA call %zu of %zu returned %d, expected %d\n",
                   name, i, total, ret, WALLY_ERROR);
            return false;
        }
        if (!keys_is_zero(keys_b38_out, sizeof(keys_b38_out))) {
            printf("%s: failing PSA call %zu of %zu returned the decrypted key\n",
                   name, i, total);
            return false;
        }
    }
    return true;
}

/*
 * scrypt
 */
static int case_keys_scrypt(void)
{
    unsigned char out[64];
    int ret = wally_scrypt((const unsigned char *)"", 0, (const unsigned char *)"", 0,
                           16, 1, 1, out, sizeof(out));
    if (ret == WALLY_OK)
        ret = keys_expect(keys_eq_hex(out, sizeof(out), KEYS_SCRYPT_1));
    return ret;
}

static int case_keys_scrypt_parallel(void)
{
    unsigned char out[64];
    int ret = wally_scrypt((const unsigned char *)"password", 8,
                           (const unsigned char *)"NaCl", 4,
                           1024, 8, 16, out, sizeof(out));
    if (ret == WALLY_OK)
        ret = keys_expect(keys_eq_hex(out, sizeof(out), KEYS_SCRYPT_2));
    return ret;
}

/* The first, middle and last PBKDF2 calls failing must wipe the seed */
static bool check_keys_bip39_seed_cleared(void)
{
    const char *name = "check_keys_bip39_seed_cleared";
    size_t n, i, total, idx[3];
    int ret;

    if (run_case(case_keys_bip39_to_seed, NO_FAILURE) != WALLY_OK) {
        printf("%s: failed without any failure injected\n", name);
        return false;
    }
    total = num_calls;
    idx[0] = 0;
    idx[1] = total / 2;
    idx[2] = total - 1;
    for (n = 0; n < 3; ++n) {
        i = idx[n];
        memset(keys_seed_out, 0xaa, sizeof(keys_seed_out));
        ret = run_case(case_keys_bip39_to_seed, i);
        if (!injected || ret != WALLY_ERROR || ops_leaked()) {
            printf("%s: failing PSA call %zu of %zu returned %d, expected %d\n",
                   name, i, total, ret, WALLY_ERROR);
            return false;
        }
        if (!keys_is_zero(keys_seed_out, sizeof(keys_seed_out)) || keys_seed_written) {
            printf("%s: failing PSA call %zu of %zu left seed output (written %zu)\n",
                   name, i, total, keys_seed_written);
            return false;
        }
    }
    return true;
}

/*
 * tx cases
 */
/*
 * Transactions: txid, hashPrevouts, legacy/segwit v0/taproot signature
 * hashes (with and without a signing cache), bitcoin message hashing and
 * taptree leaf/branch hashing.
 */
#define CASETX_NUM_INPUTS 2
#define CASETX_MANY_INPUTS 30 /* Enough to exceed the stack buffer for hashPrevouts */
#define CASETX_BIG_SCRIPT_LEN 2100 /* Enough to exceed the stack buffer for txid */

/* x-only generator point */
#define CASETX_XONLY_BYTES \
    0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, \
    0xce, 0x87, 0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, \
    0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98

#define CASETX_H160_BYTES \
    0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, \
    0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42

/* P2TR scriptPubKey */
static const unsigned char CASETX_SPK_TR[34] = { 0x51, 0x20, CASETX_XONLY_BYTES };
/* P2WPKH scriptPubKey */
static const unsigned char CASETX_SPK_WPKH[22] = { 0x00, 0x14, CASETX_H160_BYTES };
/* P2PKH script, used as legacy script and segwit v0 scriptCode */
static const unsigned char CASETX_SCRIPTCODE[25] = {
    0x76, 0xa9, 0x14, CASETX_H160_BYTES, 0x88, 0xac
};
/* Tapscript leaf: <xonly> OP_CHECKSIG */
static const unsigned char CASETX_TAPLEAF[34] = { 0x20, CASETX_XONLY_BYTES, 0xac };
/* BIP341 annex */
static const unsigned char CASETX_ANNEX[4] = { 0x50, 0x01, 0x02, 0x03 };
/* Elements genesis blockhash (any non-zero value) */
static const unsigned char CASETX_GENESIS[SHA256_LEN] = {
    0x14, 0x66, 0x27, 0x58, 0x36, 0x22, 0x0d, 0xb2, 0x94, 0x4c, 0xa0, 0x59,
    0xa3, 0xa1, 0x0e, 0xf6, 0xfd, 0x2e, 0xa6, 0x84, 0xb0, 0x68, 0x8d, 0x2c,
    0x37, 0x92, 0x96, 0x88, 0x8a, 0x20, 0x60, 0x03
};

struct casetx_fx {
    struct wally_tx *tx;
    struct wally_map *scripts; /* Input scriptPubKeys (all P2TR) */
    struct wally_map *values; /* Input values (satoshi or value commitments) */
    struct wally_map *assets; /* Input assets (Elements only) */
};

static void casetx_fx_free(struct casetx_fx *f)
{
    wally_tx_free(f->tx);
    wally_map_free(f->scripts);
    wally_map_free(f->values);
    wally_map_free(f->assets);
    memset(f, 0, sizeof(*f));
}

#ifdef BUILD_ELEMENTS
/* The explicit asset of all Elements inputs and outputs */
static void casetx_asset(unsigned char *asset_out)
{
    asset_out[0] = 0x01;
    memset(asset_out + 1, 0x6d, WALLY_TX_ASSET_CT_ASSET_LEN - 1);
}

/* Add Elements input i, spending an explicit asset and value. Input 1 is
 * an asset issuance, so that signature hashes hash issuance data */
static int casetx_add_elements_input(struct casetx_fx *f, size_t i,
                                     const unsigned char *txhash,
                                     uint32_t sequence, uint64_t satoshi)
{
    unsigned char nonce[SHA256_LEN], entropy[SHA256_LEN];
    unsigned char asset[WALLY_TX_ASSET_CT_ASSET_LEN];
    unsigned char value[WALLY_TX_ASSET_CT_VALUE_UNBLIND_LEN];
    unsigned char issuance[WALLY_TX_ASSET_CT_VALUE_UNBLIND_LEN];
    static const unsigned char issuance_rangeproof[2] = { 0x0e, 0x0f };
    const bool is_issuance = i == 1;
    const uint32_t utxo_index = (uint32_t)i | (is_issuance ? WALLY_TX_ISSUANCE_FLAG : 0);
    int ret;

    memset(nonce, 0, sizeof(nonce));
    memset(entropy, 0x3e, sizeof(entropy));
    casetx_asset(asset);
    ret = wally_tx_confidential_value_from_satoshi(500, issuance, sizeof(issuance));
    if (ret == WALLY_OK)
        ret = wally_tx_add_elements_raw_input(f->tx, txhash, WALLY_TXHASH_LEN,
                                              utxo_index, sequence, NULL, 0, NULL,
                                              is_issuance ? nonce : NULL,
                                              is_issuance ? sizeof(nonce) : 0,
                                              is_issuance ? entropy : NULL,
                                              is_issuance ? sizeof(entropy) : 0,
                                              is_issuance ? issuance : NULL,
                                              is_issuance ? sizeof(issuance) : 0,
                                              NULL, 0,
                                              is_issuance ? issuance_rangeproof : NULL,
                                              is_issuance ? sizeof(issuance_rangeproof) : 0,
                                              NULL, 0, NULL, 0);
    if (ret == WALLY_OK && is_issuance &&
        !(f->tx->inputs[i].features & WALLY_TX_IS_ISSUANCE))
        ret = WALLY_EINVAL; /* Its issuance data would not be hashed */
    if (ret == WALLY_OK)
        ret = wally_tx_confidential_value_from_satoshi(satoshi, value, sizeof(value));
    if (ret == WALLY_OK)
        ret = wally_map_add_integer(f->values, (uint32_t)i, value, sizeof(value));
    if (ret == WALLY_OK)
        ret = wally_map_add_integer(f->assets, (uint32_t)i, asset, sizeof(asset));
    return ret;
}

/* Add the Elements outputs, with (fake) proofs so that SIGHASH_RANGEPROOF
 * hashes the output witnesses */
static int casetx_add_elements_outputs(struct casetx_fx *f,
                                       const unsigned char *out_script,
                                       size_t out_script_len)
{
    unsigned char asset[WALLY_TX_ASSET_CT_ASSET_LEN];
    unsigned char value[WALLY_TX_ASSET_CT_VALUE_UNBLIND_LEN];
    static const unsigned char surjectionproof[3] = { 0xaa, 0xbb, 0xcc };
    static const unsigned char rangeproof[4] = { 0x01, 0x02, 0x03, 0x04 };
    int ret;

    casetx_asset(asset);
    ret = wally_tx_confidential_value_from_satoshi(5000, value, sizeof(value));
    if (ret == WALLY_OK)
        ret = wally_tx_add_elements_raw_output(f->tx, CASETX_SPK_WPKH,
                                               sizeof(CASETX_SPK_WPKH),
                                               asset, sizeof(asset),
                                               value, sizeof(value), NULL, 0,
                                               surjectionproof, sizeof(surjectionproof),
                                               rangeproof, sizeof(rangeproof), 0);
    if (ret == WALLY_OK)
        ret = wally_tx_confidential_value_from_satoshi(4000, value, sizeof(value));
    if (ret == WALLY_OK)
        ret = wally_tx_add_elements_raw_output(f->tx, out_script, out_script_len,
                                               asset, sizeof(asset),
                                               value, sizeof(value), NULL, 0,
                                               rangeproof, sizeof(rangeproof),
                                               surjectionproof, sizeof(surjectionproof), 0);
    return ret;
}
#else
/* Only Elements cases, which are not built, use Elements fixtures */
#define casetx_add_elements_input(f, i, txhash, sequence, satoshi) WALLY_EINVAL
#define casetx_add_elements_outputs(f, out_script, out_script_len) WALLY_EINVAL
#endif /* BUILD_ELEMENTS */

/* Build a tx with num_inputs inputs and 2 outputs (P2WPKH, P2TR). If
 * big_script_len is non-zero, the second output gets a script that long */
static int casetx_fx_init_ex(struct casetx_fx *f, size_t num_inputs,
                             bool elements, size_t big_script_len)
{
    unsigned char txhash[WALLY_TXHASH_LEN];
    unsigned char *big_script = NULL;
    const unsigned char *out_script = CASETX_SPK_TR;
    size_t out_script_len = sizeof(CASETX_SPK_TR), i;
    int ret;

    memset(f, 0, sizeof(*f));

    if (big_script_len) {
        if (!(big_script = wally_malloc(big_script_len)))
            return WALLY_ENOMEM;
        memset(big_script, 0x61, big_script_len); /* OP_NOP */
        out_script = big_script;
        out_script_len = big_script_len;
    }

    ret = wally_tx_init_alloc(2, 0x1234, num_inputs, 2, &f->tx);
    if (ret == WALLY_OK)
        ret = wally_map_init_alloc(num_inputs, NULL, &f->scripts);
    if (ret == WALLY_OK)
        ret = wally_map_init_alloc(num_inputs, NULL, &f->values);
    if (ret == WALLY_OK && elements)
        ret = wally_map_init_alloc(num_inputs, NULL, &f->assets);

    for (i = 0; ret == WALLY_OK && i < num_inputs; ++i) {
        const uint64_t satoshi = 10000 + i * 1000;
        const uint32_t sequence = 0xfffffffd - (uint32_t)i;
        memset(txhash, (int)(0x11 * (i + 1)) & 0xff, sizeof(txhash));
        txhash[0] = (unsigned char)i;
        if (elements)
            ret = casetx_add_elements_input(f, i, txhash, sequence, satoshi);
        else {
            ret = wally_tx_add_raw_input(f->tx, txhash, sizeof(txhash), (uint32_t)i,
                                         sequence, NULL, 0, NULL, 0);
            if (ret == WALLY_OK)
                ret = wally_map_add_integer(f->values, (uint32_t)i,
                                            (const unsigned char *)&satoshi, sizeof(satoshi));
        }
        if (ret == WALLY_OK)
            ret = wally_map_add_integer(f->scripts, (uint32_t)i,
                                        CASETX_SPK_TR, sizeof(CASETX_SPK_TR));
    }

    if (ret == WALLY_OK) {
        if (elements)
            ret = casetx_add_elements_outputs(f, out_script, out_script_len);
        else {
            ret = wally_tx_add_raw_output(f->tx, 5000, CASETX_SPK_WPKH,
                                          sizeof(CASETX_SPK_WPKH), 0);
            if (ret == WALLY_OK)
                ret = wally_tx_add_raw_output(f->tx, 4000, out_script, out_script_len, 0);
        }
    }
    wally_free(big_script);
    if (ret != WALLY_OK)
        casetx_fx_free(f);
    return ret;
}

static int casetx_fx_init(struct casetx_fx *f, bool elements)
{
    return casetx_fx_init_ex(f, CASETX_NUM_INPUTS, elements, 0);
}

/* A signature hash to compute */
struct casetx_spec {
    uint32_t sigtype; /* WALLY_SIGTYPE_ */
    uint32_t sighash; /* WALLY_SIGHASH_ */
    bool scriptpath; /* Taproot: sign with CASETX_TAPLEAF */
    uint32_t key_version; /* Taproot script path key version */
    bool annex; /* Taproot: include CASETX_ANNEX */
};

#define CASETX_ACP WALLY_SIGHASH_ANYONECANPAY
#define CASETX_PRE_SW(sh) { WALLY_SIGTYPE_PRE_SW, sh, false, 0, false }
#define CASETX_SW_V0(sh) { WALLY_SIGTYPE_SW_V0, sh, false, 0, false }
#define CASETX_KEYPATH(sh) { WALLY_SIGTYPE_SW_V1, sh, false, 0, false }
#define CASETX_KEYPATH_ANNEX(sh) { WALLY_SIGTYPE_SW_V1, sh, false, 0, true }
#define CASETX_SCRIPTPATH(sh) { WALLY_SIGTYPE_SW_V1, sh, true, 0, false }
#define CASETX_SCRIPTPATH_ANNEX(sh) { WALLY_SIGTYPE_SW_V1, sh, true, 0, true }
#define CASETX_SCRIPTPATH_V1(sh) { WALLY_SIGTYPE_SW_V1, sh, true, 1, false }

static int casetx_sighash(const struct casetx_fx *f, size_t index,
                          const struct casetx_spec *s, struct wally_map *cache,
                          unsigned char *bytes_out)
{
    const unsigned char *script = NULL;
    size_t script_len = 0;

    if (s->sigtype != WALLY_SIGTYPE_SW_V1) {
        script = CASETX_SCRIPTCODE;
        script_len = sizeof(CASETX_SCRIPTCODE);
    } else if (s->scriptpath) {
        script = CASETX_TAPLEAF;
        script_len = sizeof(CASETX_TAPLEAF);
    }
    return wally_tx_get_input_signature_hash(f->tx, index, f->scripts, f->assets,
                                             f->values, script, script_len,
                                             s->key_version, WALLY_NO_CODESEPARATOR,
                                             s->annex ? CASETX_ANNEX : NULL,
                                             s->annex ? sizeof(CASETX_ANNEX) : 0,
                                             f->assets ? CASETX_GENESIS : NULL,
                                             f->assets ? sizeof(CASETX_GENESIS) : 0,
                                             s->sighash, s->sigtype, cache,
                                             bytes_out, SHA256_LEN);
}

/* Compute every spec for every input, without a cache and then with one */
static int casetx_run_specs(bool elements, const struct casetx_spec *specs,
                            size_t num_specs)
{
    struct casetx_fx f;
    struct wally_map *cache = NULL;
    unsigned char out[SHA256_LEN];
    size_t pass, i, index;
    int ret = casetx_fx_init(&f, elements);

    for (pass = 0; ret == WALLY_OK && pass < 2; ++pass) {
        if (pass == 1)
            ret = wally_map_init_alloc(8, NULL, &cache);
        for (i = 0; ret == WALLY_OK && i < num_specs; ++i)
            for (index = 0; ret == WALLY_OK && index < CASETX_NUM_INPUTS; ++index)
                ret = casetx_sighash(&f, index, specs + i, cache, out);
    }
    wally_map_free(cache);
    casetx_fx_free(&f);
    return ret;
}

#define CASETX_NUM(a) (sizeof(a) / sizeof(a[0]))

static const struct casetx_spec CASETX_LEGACY_SPECS[] = {
    CASETX_PRE_SW(WALLY_SIGHASH_ALL),
    CASETX_PRE_SW(WALLY_SIGHASH_NONE),
    CASETX_PRE_SW(WALLY_SIGHASH_SINGLE),
    CASETX_PRE_SW(WALLY_SIGHASH_ALL | CASETX_ACP),
    CASETX_PRE_SW(WALLY_SIGHASH_NONE | CASETX_ACP),
    CASETX_PRE_SW(WALLY_SIGHASH_SINGLE | CASETX_ACP),
};

static const struct casetx_spec CASETX_SEGWIT_SPECS[] = {
    CASETX_SW_V0(WALLY_SIGHASH_ALL),
    CASETX_SW_V0(WALLY_SIGHASH_NONE),
    CASETX_SW_V0(WALLY_SIGHASH_SINGLE),
    CASETX_SW_V0(WALLY_SIGHASH_ALL | CASETX_ACP),
    CASETX_SW_V0(WALLY_SIGHASH_NONE | CASETX_ACP),
    CASETX_SW_V0(WALLY_SIGHASH_SINGLE | CASETX_ACP),
};

static const struct casetx_spec CASETX_KEYPATH_SPECS[] = {
    CASETX_KEYPATH(WALLY_SIGHASH_DEFAULT),
    CASETX_KEYPATH(WALLY_SIGHASH_ALL),
    CASETX_KEYPATH(WALLY_SIGHASH_NONE),
    CASETX_KEYPATH(WALLY_SIGHASH_SINGLE),
    CASETX_KEYPATH(WALLY_SIGHASH_ALL | CASETX_ACP),
    CASETX_KEYPATH(WALLY_SIGHASH_NONE | CASETX_ACP),
    CASETX_KEYPATH(WALLY_SIGHASH_SINGLE | CASETX_ACP),
};

static const struct casetx_spec CASETX_SCRIPTPATH_SPECS[] = {
    CASETX_SCRIPTPATH(WALLY_SIGHASH_DEFAULT),
    CASETX_SCRIPTPATH(WALLY_SIGHASH_NONE),
    CASETX_SCRIPTPATH(WALLY_SIGHASH_SINGLE | CASETX_ACP),
    /* BIP118: ANYPREVOUT hashes the tapleaf, ANYPREVOUTANYSCRIPT does not */
    CASETX_SCRIPTPATH_V1(WALLY_SIGHASH_ALL | WALLY_SIGHASH_ANYPREVOUT),
    CASETX_SCRIPTPATH_V1(WALLY_SIGHASH_SINGLE | WALLY_SIGHASH_ANYPREVOUTANYSCRIPT),
};

static const struct casetx_spec CASETX_ANNEX_SPECS[] = {
    CASETX_KEYPATH_ANNEX(WALLY_SIGHASH_DEFAULT),
    CASETX_KEYPATH_ANNEX(WALLY_SIGHASH_SINGLE | CASETX_ACP),
    CASETX_SCRIPTPATH_ANNEX(WALLY_SIGHASH_DEFAULT),
    CASETX_SCRIPTPATH_ANNEX(WALLY_SIGHASH_ALL | CASETX_ACP),
};

static int case_tx_txid(void)
{
    struct casetx_fx f;
    unsigned char txid[WALLY_TXHASH_LEN];
    int ret = casetx_fx_init(&f, false);
    if (ret == WALLY_OK)
        ret = wally_tx_get_txid(f.tx, txid, sizeof(txid));
    casetx_fx_free(&f);
#ifdef BUILD_ELEMENTS
    if (ret == WALLY_OK && (ret = casetx_fx_init(&f, true)) == WALLY_OK) {
        ret = wally_tx_get_txid(f.tx, txid, sizeof(txid));
        casetx_fx_free(&f);
    }
#endif
    return ret;
}

/* A tx too large to serialize into the stack buffer */
static int case_tx_txid_large(void)
{
    struct casetx_fx f;
    unsigned char txid[WALLY_TXHASH_LEN];
    int ret = casetx_fx_init_ex(&f, CASETX_NUM_INPUTS, false, CASETX_BIG_SCRIPT_LEN);
    if (ret == WALLY_OK)
        ret = wally_tx_get_txid(f.tx, txid, sizeof(txid));
    casetx_fx_free(&f);
    return ret;
}

static int case_tx_hash_prevouts(void)
{
    struct casetx_fx f;
    unsigned char txhashes[CASETX_NUM_INPUTS * WALLY_TXHASH_LEN], out[SHA256_LEN];
    uint32_t utxo_indices[CASETX_NUM_INPUTS];
    size_t i;
    int ret;

    for (i = 0; i < CASETX_NUM_INPUTS; ++i) {
        memset(txhashes + i * WALLY_TXHASH_LEN, (int)(0x21 + i), WALLY_TXHASH_LEN);
        utxo_indices[i] = (uint32_t)i + 3;
    }
    ret = wally_get_hash_prevouts(txhashes, sizeof(txhashes),
                                  utxo_indices, CASETX_NUM_INPUTS, out, sizeof(out));
    if (ret != WALLY_OK)
        return ret;

    ret = casetx_fx_init(&f, false);
    if (ret == WALLY_OK)
        ret = wally_tx_get_hash_prevouts(f.tx, 0, 0xffffffff, out, sizeof(out));
    if (ret == WALLY_OK)
        ret = wally_tx_get_hash_prevouts(f.tx, 1, 1, out, sizeof(out));
    casetx_fx_free(&f);
    if (ret != WALLY_OK)
        return ret;

    /* Enough inputs to require an allocated buffer */
    ret = casetx_fx_init_ex(&f, CASETX_MANY_INPUTS, false, 0);
    if (ret == WALLY_OK)
        ret = wally_tx_get_hash_prevouts(f.tx, 0, 0xffffffff, out, sizeof(out));
    if (ret == WALLY_OK)
        ret = wally_tx_get_hash_prevouts(f.tx, 2, CASETX_MANY_INPUTS - 2, out, sizeof(out));
    casetx_fx_free(&f);
    return ret;
}

static int case_tx_legacy_sighash(void)
{
    return casetx_run_specs(false, CASETX_LEGACY_SPECS, CASETX_NUM(CASETX_LEGACY_SPECS));
}

static int case_tx_segwit_sighash(void)
{
    return casetx_run_specs(false, CASETX_SEGWIT_SPECS, CASETX_NUM(CASETX_SEGWIT_SPECS));
}

static int case_tx_taproot_keypath_sighash(void)
{
    return casetx_run_specs(false, CASETX_KEYPATH_SPECS, CASETX_NUM(CASETX_KEYPATH_SPECS));
}

static int case_tx_taproot_scriptpath_sighash(void)
{
    return casetx_run_specs(false, CASETX_SCRIPTPATH_SPECS,
                            CASETX_NUM(CASETX_SCRIPTPATH_SPECS));
}

static int case_tx_taproot_annex_sighash(void)
{
    return casetx_run_specs(false, CASETX_ANNEX_SPECS, CASETX_NUM(CASETX_ANNEX_SPECS));
}

#ifdef BUILD_ELEMENTS
#define CASETX_RANGEPROOF WALLY_SIGHASH_RANGEPROOF
static const struct casetx_spec CASETX_ELEMENTS_SEGWIT_SPECS[] = {
    CASETX_PRE_SW(WALLY_SIGHASH_ALL),
    CASETX_PRE_SW(WALLY_SIGHASH_SINGLE | CASETX_ACP),
    CASETX_SW_V0(WALLY_SIGHASH_ALL),
    CASETX_SW_V0(WALLY_SIGHASH_NONE | CASETX_ACP),
    CASETX_SW_V0(WALLY_SIGHASH_SINGLE | CASETX_RANGEPROOF),
    CASETX_SW_V0(WALLY_SIGHASH_ALL | CASETX_RANGEPROOF),
};

static const struct casetx_spec CASETX_ELEMENTS_TAPROOT_SPECS[] = {
    CASETX_KEYPATH(WALLY_SIGHASH_DEFAULT),
    CASETX_KEYPATH(WALLY_SIGHASH_SINGLE | CASETX_ACP),
    CASETX_KEYPATH_ANNEX(WALLY_SIGHASH_NONE),
    CASETX_SCRIPTPATH(WALLY_SIGHASH_DEFAULT),
    CASETX_SCRIPTPATH_ANNEX(WALLY_SIGHASH_ALL | CASETX_ACP),
};

static int case_tx_elements_segwit_sighash(void)
{
    return casetx_run_specs(true, CASETX_ELEMENTS_SEGWIT_SPECS,
                            CASETX_NUM(CASETX_ELEMENTS_SEGWIT_SPECS));
}

static int case_tx_elements_taproot_sighash(void)
{
    return casetx_run_specs(true, CASETX_ELEMENTS_TAPROOT_SPECS,
                            CASETX_NUM(CASETX_ELEMENTS_TAPROOT_SPECS));
}

/* Elements pre-segwit SIGHASH_RANGEPROOF: legacy_signature_hash() implements
 * it, but wally_tx_get_input_signature_hash() currently rejects it */
static const struct casetx_spec CASETX_ELEMENTS_LEGACY_RANGEPROOF_SPECS[] = {
    CASETX_PRE_SW(WALLY_SIGHASH_ALL | CASETX_RANGEPROOF),
    CASETX_PRE_SW(WALLY_SIGHASH_SINGLE | CASETX_RANGEPROOF | CASETX_ACP),
};

static int case_tx_elements_legacy_rangeproof_sighash(void)
{
    return casetx_run_specs(true, CASETX_ELEMENTS_LEGACY_RANGEPROOF_SPECS,
                            CASETX_NUM(CASETX_ELEMENTS_LEGACY_RANGEPROOF_SPECS));
}
#endif /* BUILD_ELEMENTS */

/* The deprecated signature hash wrappers */
static int case_tx_sighash_wrappers(void)
{
    struct casetx_fx f;
    const uint64_t values[CASETX_NUM_INPUTS] = { 10000, 11000 };
    unsigned char out[SHA256_LEN];
    int ret = casetx_fx_init(&f, false);

    if (ret == WALLY_OK)
        ret = wally_tx_get_btc_signature_hash(f.tx, 0, CASETX_SCRIPTCODE,
                                              sizeof(CASETX_SCRIPTCODE), 0,
                                              WALLY_SIGHASH_ALL, 0, out, sizeof(out));
    if (ret == WALLY_OK)
        ret = wally_tx_get_btc_signature_hash(f.tx, 1, CASETX_SCRIPTCODE,
                                              sizeof(CASETX_SCRIPTCODE), 11000,
                                              WALLY_SIGHASH_SINGLE | CASETX_ACP,
                                              WALLY_TX_FLAG_USE_WITNESS, out, sizeof(out));
    if (ret == WALLY_OK)
        ret = wally_tx_get_signature_hash(f.tx, 0, CASETX_SCRIPTCODE,
                                          sizeof(CASETX_SCRIPTCODE), NULL, 0, 0, 10000,
                                          WALLY_SIGHASH_ALL, WALLY_SIGHASH_ALL,
                                          WALLY_TX_FLAG_USE_WITNESS, out, sizeof(out));
    if (ret == WALLY_OK)
        ret = wally_tx_get_btc_taproot_signature_hash(f.tx, 0, f.scripts, values,
                                                      CASETX_NUM_INPUTS, NULL, 0, 0,
                                                      WALLY_NO_CODESEPARATOR, NULL, 0,
                                                      WALLY_SIGHASH_DEFAULT, 0,
                                                      out, sizeof(out));
    if (ret == WALLY_OK)
        ret = wally_tx_get_btc_taproot_signature_hash(f.tx, 1, f.scripts, values,
                                                      CASETX_NUM_INPUTS, CASETX_TAPLEAF,
                                                      sizeof(CASETX_TAPLEAF), 0,
                                                      WALLY_NO_CODESEPARATOR,
                                                      CASETX_ANNEX, sizeof(CASETX_ANNEX),
                                                      WALLY_SIGHASH_SINGLE | CASETX_ACP, 0,
                                                      out, sizeof(out));
    casetx_fx_free(&f);
#ifdef BUILD_ELEMENTS
    if (ret == WALLY_OK && (ret = casetx_fx_init(&f, true)) == WALLY_OK) {
        const struct wally_map_item *v = wally_map_get_integer(f.values, 0);
        ret = wally_tx_get_elements_signature_hash(f.tx, 0, CASETX_SCRIPTCODE,
                                                   sizeof(CASETX_SCRIPTCODE),
                                                   v->value, v->value_len,
                                                   WALLY_SIGHASH_ALL,
                                                   WALLY_TX_FLAG_USE_WITNESS,
                                                   out, sizeof(out));
        casetx_fx_free(&f);
    }
#endif
    return ret;
}

static int case_tx_bitcoin_message(void)
{
    static const unsigned char short_msg[] = "Hello, world";
    unsigned char long_msg[300], out[SHA256_LEN];
    size_t written;
    int ret;

    memset(long_msg, 'x', sizeof(long_msg));
    ret = wally_format_bitcoin_message(short_msg, sizeof(short_msg) - 1,
                                       BITCOIN_MESSAGE_FLAG_HASH,
                                       out, sizeof(out), &written);
    if (ret == WALLY_OK && written != SHA256_LEN)
        ret = WALLY_EINVAL;
    if (ret == WALLY_OK)
        ret = wally_format_bitcoin_message(long_msg, sizeof(long_msg),
                                           BITCOIN_MESSAGE_FLAG_HASH,
                                           out, sizeof(out), &written);
    if (ret == WALLY_OK && written != SHA256_LEN)
        ret = WALLY_EINVAL;
    return ret;
}

/* Tapleaf and tapbranch hashing through the descriptor API */
static int case_tx_taptree_hashes(void)
{
    static const char *desc_str =
        "tr(b71aa79cab0ae2d83b82d44cbdc23f5dcca3797e8ba622c4e45a8f7dce28ba0e,"
        "{pk(79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798),"
        "{pk(dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659),"
        "pk(f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)}})";
    struct wally_descriptor *desc = NULL;
    unsigned char hash[SHA256_LEN], cb[33 + 2 * SHA256_LEN];
    size_t written;
    uint32_t leaf;
    int ret = wally_descriptor_parse(desc_str, NULL, WALLY_NETWORK_BITCOIN_MAINNET,
                                     0, &desc);

    for (leaf = 0; ret == WALLY_OK && leaf < 3; ++leaf) {
        ret = wally_descriptor_get_taproot_leaf_hash(desc, leaf, 0, 0, 0,
                                                     hash, sizeof(hash));
        if (ret == WALLY_OK)
            ret = wally_descriptor_get_taproot_control_block(desc, leaf, 0, 0, 0,
                                                             cb, sizeof(cb), &written);
        if (ret == WALLY_OK && written > sizeof(cb))
            ret = WALLY_EINVAL;
    }
    wally_descriptor_free(desc);
    return ret;
}

/*
 * Signing cache checks.
 */
static bool casetx_fail(const char *name, size_t i, const char *what, int ret)
{
    if (i == NO_FAILURE)
        printf("%s: without failure injected: %s (ret %d)\n", name, what, ret);
    else
        printf("%s: failing PSA call %zu: %s (ret %d)\n", name, i, what, ret);
    return false;
}

/* Run one signature hash 's' of input 0 with a fresh cache (first warmed by
 * a successful 'warm' hash of input 1 if given), failing PSA call
 * fail_index, then check that reusing the cache gives the uncached results
 * for both inputs. With NO_FAILURE, returns the number of PSA calls made */
static bool casetx_cache_pass(const char *name, const struct casetx_fx *f,
                              const struct casetx_spec *warm,
                              const struct casetx_spec *s, size_t fail_index,
                              unsigned char ref[CASETX_NUM_INPUTS][SHA256_LEN],
                              const unsigned char *warm_ref, size_t *total)
{
    struct wally_map *cache = NULL;
    unsigned char out[SHA256_LEN];
    size_t index;
    bool ok = true;
    int ret;

    fail_at = NO_FAILURE;
    if ((ret = wally_map_init_alloc(8, NULL, &cache)) != WALLY_OK)
        return casetx_fail(name, fail_index, "cache allocation failed", ret);
    if (warm && (ret = casetx_sighash(f, 1, warm, cache, out)) != WALLY_OK)
        ok = casetx_fail(name, fail_index, "warming the cache failed", ret);
    if (ok) {
        num_calls = 0;
        injected = false;
        fail_at = fail_index;
        ret = casetx_sighash(f, 0, s, cache, out);
        fail_at = NO_FAILURE;
        if (fail_index == NO_FAILURE) {
            *total = num_calls;
            if (ret != WALLY_OK)
                ok = casetx_fail(name, fail_index, "cached hash failed", ret);
            else if (!num_calls)
                ok = casetx_fail(name, fail_index, "no PSA calls made", ret);
            else if (memcmp(out, ref[0], SHA256_LEN))
                ok = casetx_fail(name, fail_index, "cached hash differs from uncached", ret);
        } else if (!injected)
            ok = casetx_fail(name, fail_index, "PSA call was not made", ret);
        else if (ret != WALLY_ERROR)
            ok = casetx_fail(name, fail_index, "did not return WALLY_ERROR", ret);
    }
    if (ok && ops_leaked())
        ok = casetx_fail(name, fail_index, "leaked PSA operations", ret);
    /* Reuse the cache: results must match the uncached ones */
    for (index = 0; ok && index < CASETX_NUM_INPUTS; ++index) {
        if ((ret = casetx_sighash(f, index, s, cache, out)) != WALLY_OK)
            ok = casetx_fail(name, fail_index, "hash reusing the cache failed", ret);
        else if (memcmp(out, ref[index], SHA256_LEN))
            ok = casetx_fail(name, fail_index, index ? "poisoned the cache (input 1)"
                                                     : "poisoned the cache (input 0)", ret);
    }
    if (ok && warm) {
        if ((ret = casetx_sighash(f, 0, warm, cache, out)) != WALLY_OK)
            ok = casetx_fail(name, fail_index, "warm hash reusing the cache failed", ret);
        else if (memcmp(out, warm_ref, SHA256_LEN))
            ok = casetx_fail(name, fail_index, "poisoned the cache (warm hash)", ret);
    }
    wally_map_free(cache);
    return ok;
}

/* Check that a failed signature hash does not poison the cache, failing
 * each PSA call of 's' in turn */
static bool casetx_check_cache(const char *name, bool elements,
                               const struct casetx_spec *warm,
                               const struct casetx_spec *s)
{
    struct casetx_fx f;
    unsigned char ref[CASETX_NUM_INPUTS][SHA256_LEN], warm_ref[SHA256_LEN];
    size_t total = 0, i, index;
    bool ok = true;
    int ret;

    fail_at = NO_FAILURE;
    if ((ret = casetx_fx_init(&f, elements)) != WALLY_OK) {
        printf("%s: fixture creation failed (%d)\n", name, ret);
        return false;
    }
    /* Uncached references */
    for (index = 0; ok && index < CASETX_NUM_INPUTS; ++index)
        if ((ret = casetx_sighash(&f, index, s, NULL, ref[index])) != WALLY_OK)
            ok = casetx_fail(name, NO_FAILURE, "uncached reference failed", ret);
    if (ok && warm && (ret = casetx_sighash(&f, 0, warm, NULL, warm_ref)) != WALLY_OK)
        ok = casetx_fail(name, NO_FAILURE, "uncached warm reference failed", ret);

    if (ok)
        ok = casetx_cache_pass(name, &f, warm, s, NO_FAILURE, ref, warm_ref, &total);
    for (i = 0; ok && i < total; ++i)
        ok = casetx_cache_pass(name, &f, warm, s, i, ref, warm_ref, &total);
    casetx_fx_free(&f);
    return ok;
}

static bool check_tx_sighash_cache(void)
{
    static const struct {
        const char *name;
        bool elements;
        bool has_warm;
        struct casetx_spec warm;
        struct casetx_spec s;
    } checks[] = {
        { "cache: segwit v0 ALL", false, false,
          CASETX_SW_V0(0), CASETX_SW_V0(WALLY_SIGHASH_ALL) },
        { "cache: segwit v0 ALL after NONE", false, true,
          CASETX_SW_V0(WALLY_SIGHASH_NONE), CASETX_SW_V0(WALLY_SIGHASH_ALL) },
        { "cache: segwit v0 SINGLE|ACP after ALL", false, true,
          CASETX_SW_V0(WALLY_SIGHASH_ALL), CASETX_SW_V0(WALLY_SIGHASH_SINGLE | CASETX_ACP) },
        { "cache: taproot keypath DEFAULT", false, false,
          CASETX_KEYPATH(0), CASETX_KEYPATH(WALLY_SIGHASH_DEFAULT) },
        { "cache: taproot keypath DEFAULT after NONE", false, true,
          CASETX_KEYPATH(WALLY_SIGHASH_NONE), CASETX_KEYPATH(WALLY_SIGHASH_DEFAULT) },
        { "cache: taproot keypath SINGLE|ACP", false, false,
          CASETX_KEYPATH(0), CASETX_KEYPATH(WALLY_SIGHASH_SINGLE | CASETX_ACP) },
        { "cache: taproot scriptpath DEFAULT", false, false,
          CASETX_KEYPATH(0), CASETX_SCRIPTPATH(WALLY_SIGHASH_DEFAULT) },
        { "cache: taproot scriptpath DEFAULT after keypath", false, true,
          CASETX_KEYPATH(WALLY_SIGHASH_DEFAULT), CASETX_SCRIPTPATH(WALLY_SIGHASH_DEFAULT) },
        { "cache: taproot scriptpath ANYPREVOUT after keypath", false, true,
          CASETX_KEYPATH(WALLY_SIGHASH_DEFAULT),
          CASETX_SCRIPTPATH_V1(WALLY_SIGHASH_ALL | WALLY_SIGHASH_ANYPREVOUT) },
        { "cache: taproot keypath annex DEFAULT", false, false,
          CASETX_KEYPATH(0), CASETX_KEYPATH_ANNEX(WALLY_SIGHASH_DEFAULT) },
        { "cache: taproot keypath annex DEFAULT after keypath", false, true,
          CASETX_KEYPATH(WALLY_SIGHASH_DEFAULT), CASETX_KEYPATH_ANNEX(WALLY_SIGHASH_DEFAULT) },
        { "cache: taproot scriptpath annex ALL|ACP", false, false,
          CASETX_KEYPATH(0), CASETX_SCRIPTPATH_ANNEX(WALLY_SIGHASH_ALL | CASETX_ACP) },
        { "cache: taproot scriptpath annex DEFAULT after scriptpath", false, true,
          CASETX_SCRIPTPATH(WALLY_SIGHASH_DEFAULT),
          CASETX_SCRIPTPATH_ANNEX(WALLY_SIGHASH_DEFAULT) },
#ifdef BUILD_ELEMENTS
        { "cache: elements segwit v0 ALL", true, false,
          CASETX_SW_V0(0), CASETX_SW_V0(WALLY_SIGHASH_ALL) },
        { "cache: elements segwit v0 ALL after NONE", true, true,
          CASETX_SW_V0(WALLY_SIGHASH_NONE), CASETX_SW_V0(WALLY_SIGHASH_ALL) },
        { "cache: elements taproot keypath DEFAULT", true, false,
          CASETX_KEYPATH(0), CASETX_KEYPATH(WALLY_SIGHASH_DEFAULT) },
        { "cache: elements taproot scriptpath annex DEFAULT after keypath", true, true,
          CASETX_KEYPATH(WALLY_SIGHASH_DEFAULT),
          CASETX_SCRIPTPATH_ANNEX(WALLY_SIGHASH_DEFAULT) },
#endif
    };
    size_t i;
    bool ok = true;

    for (i = 0; i < CASETX_NUM(checks); ++i)
        if (!casetx_check_cache(checks[i].name, checks[i].elements,
                                checks[i].has_warm ? &checks[i].warm : NULL,
                                &checks[i].s))
            ok = false;
    return ok;
}

#ifdef BUILD_ELEMENTS
/* Compare the cached and uncached results of a sequence of hashes over a
 * shared cache, without any failures injected */
static bool casetx_check_cache_consistency(const char *name,
                                           const struct casetx_fx *f,
                                           const struct casetx_spec *specs,
                                           size_t num_specs)
{
    struct wally_map *cache = NULL;
    unsigned char ref[SHA256_LEN], out[SHA256_LEN];
    size_t i, index;
    bool ok = true;
    int ret;

    fail_at = NO_FAILURE;
    if ((ret = wally_map_init_alloc(8, NULL, &cache)) != WALLY_OK) {
        printf("%s: cache allocation failed (%d)\n", name, ret);
        return false;
    }
    for (i = 0; ok && i < num_specs; ++i) {
        for (index = 0; ok && index < CASETX_NUM_INPUTS; ++index) {
            if ((ret = casetx_sighash(f, index, specs + i, NULL, ref)) != WALLY_OK ||
                (ret = casetx_sighash(f, index, specs + i, cache, out)) != WALLY_OK) {
                printf("%s: hash %zu input %zu failed (%d)\n", name, i, index, ret);
                ok = false;
            } else if (memcmp(ref, out, SHA256_LEN)) {
                printf("%s: hash %zu (sigtype %u sighash 0x%02x) input %zu: "
                       "cached result differs from uncached\n", name, i,
                       (unsigned)specs[i].sigtype, (unsigned)specs[i].sighash, index);
                ok = false;
            }
        }
    }
    wally_map_free(cache);
    return ok;
}

/* Elements segwit v0 SIGHASH_RANGEPROOF: the output witnesses hash must not
 * be confused with the outputs hash in the cache */
static bool check_tx_elements_rangeproof_cache(void)
{
    static const struct casetx_spec specs[] = {
        CASETX_SW_V0(WALLY_SIGHASH_ALL | CASETX_RANGEPROOF),
        CASETX_SW_V0(WALLY_SIGHASH_ALL | CASETX_RANGEPROOF | CASETX_ACP),
        CASETX_SW_V0(WALLY_SIGHASH_ALL),
    };
    static const struct casetx_spec specs_rev[] = {
        CASETX_SW_V0(WALLY_SIGHASH_ALL),
        CASETX_SW_V0(WALLY_SIGHASH_ALL | CASETX_RANGEPROOF),
    };
    struct casetx_fx f;
    bool ok;
    int ret;

    fail_at = NO_FAILURE;
    if ((ret = casetx_fx_init(&f, true)) != WALLY_OK) {
        printf("elements rangeproof cache: fixture creation failed (%d)\n", ret);
        return false;
    }
    ok = casetx_check_cache_consistency("elements rangeproof cache",
                                        &f, specs, CASETX_NUM(specs));
    ok &= casetx_check_cache_consistency("elements rangeproof cache (ALL first)",
                                         &f, specs_rev, CASETX_NUM(specs_rev));
    casetx_fx_free(&f);
    return ok;
}
#endif /* BUILD_ELEMENTS */

/* Taproot: the annex hash and the tapleaf hash are cached keyed by their
 * raw bytes; an annex equal to the tapleaf script must not be confused */
static bool check_tx_annex_tapleaf_cache(void)
{
    /* A tapscript that is byte-identical to the annex below */
    static const unsigned char same[2] = { 0x50, 0xac };
    struct casetx_fx f;
    struct wally_map *cache = NULL;
    unsigned char ref[SHA256_LEN], out[SHA256_LEN];
    bool ok = true;
    int ret;

    fail_at = NO_FAILURE;
    if ((ret = casetx_fx_init(&f, false)) != WALLY_OK) {
        printf("annex/tapleaf cache: fixture creation failed (%d)\n", ret);
        return false;
    }
    ret = wally_map_init_alloc(8, NULL, &cache);
    if (ret == WALLY_OK)
        ret = wally_tx_get_input_signature_hash(f.tx, 0, f.scripts, NULL, f.values,
                                                same, sizeof(same), 0,
                                                WALLY_NO_CODESEPARATOR,
                                                same, sizeof(same), NULL, 0,
                                                WALLY_SIGHASH_DEFAULT,
                                                WALLY_SIGTYPE_SW_V1, NULL,
                                                ref, sizeof(ref));
    if (ret == WALLY_OK)
        ret = wally_tx_get_input_signature_hash(f.tx, 0, f.scripts, NULL, f.values,
                                                same, sizeof(same), 0,
                                                WALLY_NO_CODESEPARATOR,
                                                same, sizeof(same), NULL, 0,
                                                WALLY_SIGHASH_DEFAULT,
                                                WALLY_SIGTYPE_SW_V1, cache,
                                                out, sizeof(out));
    if (ret != WALLY_OK) {
        printf("annex/tapleaf cache: hash failed (%d)\n", ret);
        ok = false;
    } else if (memcmp(ref, out, SHA256_LEN)) {
        printf("annex/tapleaf cache: cached result differs from uncached "
               "when the annex equals the tapleaf script\n");
        ok = false;
    }
    wally_map_free(cache);
    casetx_fx_free(&f);
    return ok;
}

/*
 * psbt cases
 */
/*
 * PSBT, descriptor, map, address and script cases.
 */

/* v0 PSBT spending 4 inputs, with keypaths from TPSBT_XPRV m/0/0..m/0/3:
 * 0: p2pkh (non-witness utxo), 1: p2wpkh, 2: p2sh-p2wpkh (redeem script),
 * 3: p2wsh 1-of-1 multisig (witness script) */
static const char TPSBT_MIXED[] =
    "cHNidP8BAM0CAAAABKMPNrdKClCrRpBTSl8+DbgqWOaXEePK4lF+r94XFEADAAAAAAD9////IiIi"
    "IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIAAAAAAP3///8zMzMzMzMzMzMzMzMzMzMzMzMz"
    "MzMzMzMzMzMzMzMzMwEAAAAA/f///0REREREREREREREREREREREREREREREREREREREREREAgAA"
    "AAD9////AXDzBQAAAAAAFgAUGkw9FkCd3cSZFgIw3IShGCsqs44AAAAAAAEAVQIAAAABERERERER"
    "EREREREREREREREREREREREREREREREREREAAAAAAP////8BoIYBAAAAAAAZdqkUDRycAqe+m6i4"
    "hCgE/rlhSBzmVhuIrAAAAAAiBgJ1beGCxd1LcX6ofmkwBtpi27PN2qSlytLtH1u6t1Xw9Qw0Qhk+"
    "AAAAAAAAAAAAAQEfoIYBAAAAAAAWABQaTD0WQJ3dxJkWAjDchKEYKyqzjiIGAudA0hOhqldGxmuu"
    "Hs2juV1/ZNS/iv+dk3AvwwLyjfDxDDRCGT4AAAAAAQAAAAABASCghgEAAAAAABepFI0pWyJ6WJxH"
    "oE8LZbf4o30+8injhwEEFgAUuxuocYAUscKE0rjddY/yPSZIzVsiBgNH/z2s0HofQ4BexoCOgBUF"
    "puGCRReGCZcqaK+8J3f/Kww0Qhk+AAAAAAIAAAAAAQEroIYBAAAAAAAiACAnycajQvLl7EA0IiLT"
    "4nqtfMxsTYr3HYInb+j9Zx2ChAEFJVEhAluA/MEru8/49VYrhmQv6Fg3ONnA5VjTkxNwGiSsm5Cm"
    "Ua4iBgJbgPzBK7vP+PVWK4ZkL+hYNzjZwOVY05MTcBokrJuQpgw0Qhk+AAAAAAMAAAAAAA==";

/* The same unsigned tx as TPSBT_MIXED, with sha256/hash160/hash256/ripemd160
 * preimages of TPSBT_PREIMAGE on input 1, and 2 global xpubs (m and m/0) */
static const char TPSBT_EXTRA[] =
    "cHNidP8BAM0CAAAABKMPNrdKClCrRpBTSl8+DbgqWOaXEePK4lF+r94XFEADAAAAAAD9////IiIi"
    "IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIAAAAAAP3///8zMzMzMzMzMzMzMzMzMzMzMzMz"
    "MzMzMzMzMzMzMzMzMwEAAAAA/f///0REREREREREREREREREREREREREREREREREREREREREAgAA"
    "AAD9////AXDzBQAAAAAAFgAUGkw9FkCd3cSZFgIw3IShGCsqs44AAAAATwEEiLIeAAAAAAAAAAAA"
    "hz3/gcAvUlYj/R/lFn6sOlWgSd49MUu0LuIn/+031QgDOaNgEzAVl9rvQfvlk6AsxRPQtVUn7C3x"
    "BQ4uj/SchcIENEIZPk8BBIiyHgE0Qhk+AAAAANMj8b5a85otLwj16PZkYzhJZT2+MpgC6YR8/IX4"
    "17UqAnxLCf+5hcKYr+flgTJmy/y3eAtICsKUsLQ9wh8r49E8CDRCGT4AAAAAAAAhC79HD7PGPa5d"
    "HUOX8JMeydQv8d+FObavRtt/YgwVqQ0VE3dhbGx5IHBzYnQgcHJlaW1hZ2UVDPMvu9lEoZiSjsRK"
    "yp7nDG9WpIVHE3dhbGx5IHBzYnQgcHJlaW1hZ2UhDbUTlaM+/hAs+reMieGDLTZ5CypKVIQ7uUqb"
    "5QBp5isOE3dhbGx5IHBzYnQgcHJlaW1hZ2UVChHE7lE/zZatr1dYPPq7VZlA6tmmE3dhbGx5IHBz"
    "YnQgcHJlaW1hZ2UAAAAA";

/* v0 PSBT with one p2tr key path input (internal key m/0/4, with taproot
 * keypath) */
static const char TPSBT_TAPROOT[] =
    "cHNidP8BAFICAAAAAVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVAAAAAAD9////AZBf"
    "AQAAAAAAFgAUGkw9FkCd3cSZFgIw3IShGCsqs44AAAAAAAEBK6CGAQAAAAAAIlEgGBd8mqZvm8oi"
    "PzIU1TZPA1iwcH5tCBj6QPTZjGelu50hFlNElq6IEqMVAg3bEvztQRuJH6Gh5TzhQGTQUsVlEq13"
    "DQA0Qhk+AAAAAAQAAAABFyBTRJauiBKjFQIN2xL87UEbiR+hoeU84UBk0FLFZRKtdwAA";

/* BIP-174 test vector: PSBT v0 with PSBT_GLOBAL_XPUB */
static const char TPSBT_BIP174_XPUBS[] =
    "cHNidP8BAJ0BAAAAAnEOp2q0XFy2Q45gflnMA3YmmBgFrp4N/ZCJASq7C+U1AQAAAAD/////GQmU"
    "1qizyMgsy8+y+6QQaqBmObhyqNRHRlwNQliNbWcAAAAAAP////8CAOH1BQAAAAAZdqkUtrwsDuVl"
    "WoQ9ea/t0MzD991kNAmIrGBa9AUAAAAAFgAUEYjvjkzgRJ6qyPsUHL9aEXbmoIgAAAAATwEEiLIe"
    "A55TDKyAAAAAPbyKXJdp8DGxfnf+oVGGAyIaGP0Y8rmlTGyMGsdcvDUC8jBYSxVdHH8c1FEgplPE"
    "jWULQxtnxbLBPyfXFCA3wWkQJ1acUDEAAIAAAACAAAAAgAABAR8A4fUFAAAAABYAFDO5gvkbKPFg"
    "ySC0q5XljOUN2jpKIgIDMJaA8zx9446mpHzU7NZvH1pJdHxv+4gI7QkDkkPjrVxHMEQCIC1wTO2D"
    "DFapCTRL10K2hS3M0QPpY7rpLTjnUlTSu0JFAiAthsQ3GV30bAztoITyopHD2i1kBw92v5uQsZXn"
    "7yj3cgEiBgMwloDzPH3jjqakfNTs1m8fWkl0fG/7iAjtCQOSQ+OtXBgnVpxQMQAAgAAAAIAAAACA"
    "AAAAAAEAAAAAAQEfAOH1BQAAAAAWABQ4j7lEMH63fvRRl9CwskXgefAR3iICAsd3Fh9z0LfHK57n"
    "veZQKT0T8JW8dlatH1Jdpf0uELEQRzBEAiBMsftfhpyULg4mEAV2ElQ5F5rojcqKncO6CPeVOYj6"
    "pgIgUh9JynkcJ9cOJzybFGFphZCTYeJb4nTqIA1+CIJ+UU0BIgYCx3cWH3PQt8crnue95lApPRPw"
    "lbx2Vq0fUl2l/S4QsRAYJ1acUDEAAIAAAACAAAAAgAAAAAAAAAAAAAAiAgLSDKUC7iiWhtIYFb1D"
    "qAY3sGmOH7zb5MrtRF9sGgqQ7xgnVpxQMQAAgAAAAIAAAACAAAAAAAQAAAAA";

static const char TPSBT_XPRV[] =
    "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
static const char TPSBT_XPUB[] =
    "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
/* Serialized TPSBT_XPUB, fingerprint 3442193e */
static const char TPSBT_XPUB_HEX[] =
    "0488b21e000000000000000000873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d5080339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2";
/* Private keys m/0/0 .. m/0/3 of TPSBT_XPRV */
static const char *const TPSBT_PRIVS[4] = {
    "f26cf12f89ab91aeeb8d7324a22e8ba080829db15c9245414b073a8c342322aa",
    "472e3788b980839678da16b6a285113a1edb579114b62f9efe628335049fca83",
    "31d86797d300886a277997220828a2e49b6477016d82028c9e205d648b4961af",
    "f1fe2fa8fa66ca0668b12f79dddc52d8ac1b00907015eeb28b4e3c3093bc9ef9"
};
/* Public key m/0/4 of TPSBT_XPRV */
static const char TPSBT_PUB_HEX[] =
    "03534496ae8812a315020ddb12fced411b891fa1a1e53ce14064d052c56512ad77";
static const unsigned char TPSBT_PREIMAGE[] = "wally psbt preimage";

#define TPSBT_BUF_LEN 2048

static int tpsbt_hex(const char *hex, unsigned char *bytes_out, size_t len)
{
    size_t written;
    int ret = wally_hex_to_bytes(hex, bytes_out, len, &written);
    return ret == WALLY_OK && written != len ? WALLY_EINVAL : ret;
}

static int tpsbt_from_base64_as_bytes(const char *b64, struct wally_psbt **output)
{
    unsigned char buf[TPSBT_BUF_LEN];
    size_t written;
    int ret = wally_base64_to_bytes(b64, 0, buf, sizeof(buf), &written);
    if (ret == WALLY_OK && written > sizeof(buf))
        ret = WALLY_EINVAL;
    if (ret == WALLY_OK)
        ret = wally_psbt_from_bytes(buf, written, 0, output);
    return ret;
}

/* Get the scriptcode to sign input i with */
static int tpsbt_scriptcode(const struct wally_psbt *psbt, size_t i,
                            unsigned char *scriptcode, size_t *scriptcode_len)
{
    unsigned char script[256];
    size_t script_len;
    int ret = wally_psbt_get_input_signing_script(psbt, i, script, sizeof(script),
                                                  &script_len);
    if (ret == WALLY_OK && script_len > sizeof(script))
        ret = WALLY_EINVAL;
    if (ret == WALLY_OK)
        ret = wally_psbt_get_input_scriptcode(psbt, i, script, script_len,
                                              scriptcode, 256, scriptcode_len);
    if (ret == WALLY_OK && *scriptcode_len > 256)
        ret = WALLY_EINVAL;
    return ret;
}

/* Compute the signature hashes of all inputs */
static int tpsbt_sighashes(struct wally_psbt *psbt, unsigned char *hashes)
{
    unsigned char scriptcode[256];
    size_t i, scriptcode_len;
    int ret = WALLY_OK;

    for (i = 0; ret == WALLY_OK && i < psbt->num_inputs; ++i) {
        ret = tpsbt_scriptcode(psbt, i, scriptcode, &scriptcode_len);
        if (ret == WALLY_OK)
            ret = wally_psbt_get_input_signature_hash(psbt, i, psbt->tx,
                                                      scriptcode, scriptcode_len, 0,
                                                      hashes + i * SHA256_LEN,
                                                      SHA256_LEN);
    }
    return ret;
}

/*
 * PSBT parsing: input preimages and global xpubs are verified by hashing
 */
static int case_psbt_parse_extra_base64(void)
{
    struct wally_psbt *psbt = NULL;
    int ret = wally_psbt_from_base64(TPSBT_EXTRA, 0, &psbt);
    wally_psbt_free(psbt);
    return ret;
}

static int case_psbt_parse_extra_bytes(void)
{
    struct wally_psbt *psbt = NULL;
    int ret = tpsbt_from_base64_as_bytes(TPSBT_EXTRA, &psbt);
    wally_psbt_free(psbt);
    return ret;
}

static int case_psbt_parse_bip174_xpubs(void)
{
    struct wally_psbt *psbt = NULL;
    int ret = wally_psbt_from_base64(TPSBT_BIP174_XPUBS, 0, &psbt);
    wally_psbt_free(psbt);
    psbt = NULL;
    if (ret == WALLY_OK)
        ret = tpsbt_from_base64_as_bytes(TPSBT_BIP174_XPUBS, &psbt);
    wally_psbt_free(psbt);
    return ret;
}

/*
 * PSBT operations
 */
static int case_psbt_get_id(void)
{
    unsigned char id[WALLY_TXHASH_LEN];
    struct wally_psbt *psbt = NULL;
    int ret = wally_psbt_from_base64(TPSBT_MIXED, 0, &psbt);

    if (ret == WALLY_OK)
        ret = wally_psbt_get_id(psbt, 0, id, sizeof(id));
    if (ret == WALLY_OK)
        ret = wally_psbt_get_id(psbt, WALLY_PSBT_ID_AS_V2, id, sizeof(id));
    if (ret == WALLY_OK)
        ret = wally_psbt_get_id(psbt, WALLY_PSBT_ID_USE_LOCKTIME, id, sizeof(id));
    if (ret == WALLY_OK)
        ret = wally_psbt_set_version(psbt, 0, WALLY_PSBT_VERSION_2);
    if (ret == WALLY_OK)
        ret = wally_psbt_get_id(psbt, 0, id, sizeof(id));
    wally_psbt_free(psbt);
    return ret;
}

static int case_psbt_combine(void)
{
    struct wally_psbt *psbt = NULL, *src = NULL;
    int ret = wally_psbt_from_base64(TPSBT_MIXED, 0, &psbt);

    if (ret == WALLY_OK)
        ret = wally_psbt_from_base64(TPSBT_EXTRA, 0, &src);
    if (ret == WALLY_OK)
        ret = wally_psbt_combine(psbt, src);
    if (ret == WALLY_OK && (psbt->inputs[1].preimages.num_items != 4 ||
                            psbt->global_xpubs.num_items != 2))
        ret = WALLY_EINVAL; /* Combine didn't copy preimages/xpubs */
    wally_psbt_free(src);
    wally_psbt_free(psbt);
    return ret;
}

static int case_psbt_clone(void)
{
    struct wally_psbt *psbt = NULL, *clone = NULL;
    int ret = wally_psbt_from_base64(TPSBT_EXTRA, 0, &psbt);

    if (ret == WALLY_OK)
        ret = wally_psbt_clone_alloc(psbt, 0, &clone);
    if (ret == WALLY_OK && (clone->inputs[1].preimages.num_items != 4 ||
                            clone->global_xpubs.num_items != 2))
        ret = WALLY_EINVAL; /* Clone didn't copy preimages/xpubs */
    wally_psbt_free(clone);
    wally_psbt_free(psbt);
    return ret;
}

static int case_psbt_signing_script(void)
{
    unsigned char script[256];
    struct wally_psbt *psbt = NULL;
    size_t i, written;
    int ret = wally_psbt_from_base64(TPSBT_MIXED, 0, &psbt);

    for (i = 0; ret == WALLY_OK && i < 4; ++i)
        ret = wally_psbt_get_input_signing_script(psbt, i, script, sizeof(script),
                                                  &written);
    wally_psbt_free(psbt);
    return ret;
}

static int case_psbt_scriptcode(void)
{
    unsigned char scriptcode[256];
    struct wally_psbt *psbt = NULL;
    size_t i, written;
    int ret = wally_psbt_from_base64(TPSBT_MIXED, 0, &psbt);

    for (i = 0; ret == WALLY_OK && i < 4; ++i)
        ret = tpsbt_scriptcode(psbt, i, scriptcode, &written);
    wally_psbt_free(psbt);
    return ret;
}

static int case_psbt_sighash(void)
{
    unsigned char hashes[4 * SHA256_LEN];
    struct wally_psbt *psbt = NULL;
    int ret = wally_psbt_from_base64(TPSBT_MIXED, 0, &psbt);

    if (ret == WALLY_OK)
        ret = tpsbt_sighashes(psbt, hashes);
    wally_psbt_free(psbt);
    return ret;
}

static int case_psbt_sighash_cached(void)
{
    unsigned char hashes[4 * SHA256_LEN];
    struct wally_psbt *psbt = NULL;
    int ret = wally_psbt_from_base64(TPSBT_MIXED, 0, &psbt);

    if (ret == WALLY_OK)
        ret = wally_psbt_signing_cache_enable(psbt, 0);
    if (ret == WALLY_OK)
        ret = tpsbt_sighashes(psbt, hashes);
    if (ret == WALLY_OK)
        ret = tpsbt_sighashes(psbt, hashes); /* Uses the cache */
    wally_psbt_free(psbt);
    return ret;
}

static int case_psbt_sighash_taproot(void)
{
    unsigned char hash[SHA256_LEN];
    struct wally_psbt *psbt = NULL;
    int ret = wally_psbt_from_base64(TPSBT_TAPROOT, 0, &psbt);

    if (ret == WALLY_OK)
        ret = tpsbt_sighashes(psbt, hash);
    if (ret == WALLY_OK)
        ret = wally_psbt_signing_cache_enable(psbt, 0);
    if (ret == WALLY_OK)
        ret = tpsbt_sighashes(psbt, hash);
    if (ret == WALLY_OK)
        ret = tpsbt_sighashes(psbt, hash); /* Uses the cache */
    wally_psbt_free(psbt);
    return ret;
}

/* Finalize and extract, then compute the final txid */
static int tpsbt_finish(struct wally_psbt *psbt)
{
    unsigned char txid[WALLY_TXHASH_LEN];
    struct wally_tx *tx = NULL;
    int ret = wally_psbt_finalize(psbt, 0);

    if (ret == WALLY_OK)
        ret = wally_psbt_extract(psbt, WALLY_PSBT_EXTRACT_FINAL, &tx);
    if (ret == WALLY_OK)
        ret = wally_tx_get_txid(tx, txid, sizeof(txid));
    wally_tx_free(tx);
    return ret;
}

static int case_psbt_sign_finalize(void)
{
    unsigned char priv_key[EC_PRIVATE_KEY_LEN];
    struct wally_psbt *psbt = NULL;
    size_t i;
    int ret = wally_psbt_from_base64(TPSBT_MIXED, 0, &psbt);

    for (i = 0; ret == WALLY_OK && i < 4; ++i) {
        ret = tpsbt_hex(TPSBT_PRIVS[i], priv_key, sizeof(priv_key));
        if (ret == WALLY_OK)
            ret = wally_psbt_sign(psbt, priv_key, sizeof(priv_key), 0);
        if (ret == WALLY_OK && psbt->inputs[i].signatures.num_items != 1)
            ret = WALLY_EINVAL; /* Input not signed */
    }
    if (ret == WALLY_OK)
        ret = tpsbt_finish(psbt);
    wally_psbt_free(psbt);
    wally_clear(priv_key, sizeof(priv_key));
    return ret;
}

static int case_psbt_sign_bip32(void)
{
    struct ext_key master;
    struct wally_psbt *psbt = NULL;
    size_t i;
    int ret = wally_psbt_from_base64(TPSBT_MIXED, 0, &psbt);

    if (ret == WALLY_OK)
        ret = bip32_key_from_base58(TPSBT_XPRV, &master);
    if (ret == WALLY_OK)
        ret = wally_psbt_sign_bip32(psbt, &master, 0);
    for (i = 0; ret == WALLY_OK && i < 4; ++i)
        if (psbt->inputs[i].signatures.num_items != 1)
            ret = WALLY_EINVAL; /* Input not signed */
    if (ret == WALLY_OK)
        ret = tpsbt_finish(psbt);
    wally_psbt_free(psbt);
    wally_clear(&master, sizeof(master));
    return ret;
}

static int case_psbt_sign_taproot(void)
{
    struct ext_key master;
    struct wally_psbt *psbt = NULL;
    int ret = wally_psbt_from_base64(TPSBT_TAPROOT, 0, &psbt);

    if (ret == WALLY_OK)
        ret = bip32_key_from_base58(TPSBT_XPRV, &master);
    if (ret == WALLY_OK)
        ret = wally_psbt_sign_bip32(psbt, &master, 0);
    if (ret == WALLY_OK &&
        !wally_map_get_integer(&psbt->inputs[0].psbt_fields, PSBT_IN_TAP_KEY_SIG))
        ret = WALLY_EINVAL; /* Input not signed */
    if (ret == WALLY_OK)
        ret = tpsbt_finish(psbt);
    wally_psbt_free(psbt);
    wally_clear(&master, sizeof(master));
    return ret;
}

/* A PSBT created from a tx, with keypaths, preimages and a global xpub
 * added to it */
static int case_psbt_from_tx(void)
{
    unsigned char txhash[WALLY_TXHASH_LEN], pub_key[EC_PUBLIC_KEY_LEN];
    unsigned char xpub[BIP32_SERIALIZED_LEN], fingerprint[BIP32_KEY_FINGERPRINT_LEN];
    unsigned char id[WALLY_TXHASH_LEN];
    const uint32_t path[2] = { 0, 4 };
    struct wally_tx *tx = NULL;
    struct wally_psbt *psbt = NULL;
    int ret;

    memset(txhash, 0x55, sizeof(txhash));
    ret = wally_tx_init_alloc(2, 0, 1, 1, &tx);
    if (ret == WALLY_OK)
        ret = wally_tx_add_raw_input(tx, txhash, sizeof(txhash), 0, 0xffffffff,
                                     NULL, 0, NULL, 0);
    if (ret == WALLY_OK)
        ret = tpsbt_hex(TPSBT_PUB_HEX, pub_key, sizeof(pub_key));
    if (ret == WALLY_OK)
        ret = tpsbt_hex(TPSBT_XPUB_HEX, xpub, sizeof(xpub));
    if (ret == WALLY_OK)
        ret = tpsbt_hex("3442193e", fingerprint, sizeof(fingerprint));
    if (ret == WALLY_OK)
        ret = wally_tx_add_raw_output(tx, 1000, txhash, 22, 0);
    if (ret == WALLY_OK)
        ret = wally_psbt_from_tx(tx, WALLY_PSBT_VERSION_0, 0, &psbt);
    if (ret == WALLY_OK)
        ret = wally_psbt_add_input_keypath(psbt, 0, pub_key, sizeof(pub_key),
                                           fingerprint, sizeof(fingerprint), path, 2);
    if (ret == WALLY_OK)
        ret = wally_map_preimage_sha256_add(&psbt->inputs[0].preimages,
                                            TPSBT_PREIMAGE, sizeof(TPSBT_PREIMAGE) - 1);
    if (ret == WALLY_OK)
        ret = wally_map_keypath_add(&psbt->global_xpubs, xpub, sizeof(xpub),
                                    fingerprint, sizeof(fingerprint), NULL, 0);
    if (ret == WALLY_OK)
        ret = wally_psbt_get_id(psbt, 0, id, sizeof(id));
    wally_psbt_free(psbt);
    wally_tx_free(tx);
    return ret;
}

/*
 * Maps
 */
static int case_psbt_map_preimages(void)
{
    const unsigned char *pre = TPSBT_PREIMAGE;
    const size_t pre_len = sizeof(TPSBT_PREIMAGE) - 1;
    unsigned char key[1 + SHA256_LEN];
    struct wally_map *map = NULL;
    int ret = wally_map_preimage_init_alloc(0, &map);

    if (ret == WALLY_OK)
        ret = wally_map_preimage_sha256_add(map, pre, pre_len);
    if (ret == WALLY_OK)
        ret = wally_map_preimage_hash160_add(map, pre, pre_len);
    if (ret == WALLY_OK)
        ret = wally_map_preimage_sha256d_add(map, pre, pre_len);
    if (ret == WALLY_OK)
        ret = wally_map_preimage_ripemd160_add(map, pre, pre_len);
    /* Add with an explicit key, verified by hashing the preimage */
    key[0] = PSBT_IN_SHA256;
    if (ret == WALLY_OK)
        ret = wally_sha256(pre, pre_len - 1, key + 1, SHA256_LEN);
    if (ret == WALLY_OK)
        ret = wally_map_add(map, key, sizeof(key), pre, pre_len - 1);
    if (ret == WALLY_OK)
        ret = wally_map_hash_preimage_verify(key, sizeof(key), pre, pre_len - 1);
    key[0] = PSBT_IN_HASH256;
    if (ret == WALLY_OK)
        ret = wally_sha256d(pre, pre_len - 2, key + 1, SHA256_LEN);
    if (ret == WALLY_OK)
        ret = wally_map_hash_preimage_verify(key, sizeof(key), pre, pre_len - 2);
    key[0] = PSBT_IN_HASH160;
    if (ret == WALLY_OK)
        ret = wally_hash160(pre, pre_len - 3, key + 1, HASH160_LEN);
    if (ret == WALLY_OK)
        ret = wally_map_add(map, key, 1 + HASH160_LEN, pre, pre_len - 3);
    if (ret == WALLY_OK && map->num_items != 6)
        ret = WALLY_EINVAL;
    wally_map_free(map);
    return ret;
}

static int case_psbt_map_keypath_xpub(void)
{
    unsigned char xpub[BIP32_SERIALIZED_LEN], val[BIP32_KEY_FINGERPRINT_LEN];
    const uint32_t path[1] = { 0 };
    struct wally_map *map = NULL;
    struct ext_key master, child;
    int ret = tpsbt_hex(TPSBT_XPUB_HEX, xpub, sizeof(xpub));

    if (ret == WALLY_OK)
        ret = tpsbt_hex("3442193e", val, sizeof(val));
    if (ret == WALLY_OK)
        ret = wally_keypath_bip32_verify(xpub, sizeof(xpub), val, sizeof(val));
    if (ret == WALLY_OK)
        ret = wally_map_keypath_bip32_init_alloc(0, &map);
    if (ret == WALLY_OK)
        ret = wally_map_keypath_add(map, xpub, sizeof(xpub), val, sizeof(val), NULL, 0);
    /* Add a depth-1 child xpub with its path */
    if (ret == WALLY_OK)
        ret = bip32_key_from_base58(TPSBT_XPUB, &master);
    if (ret == WALLY_OK)
        ret = bip32_key_from_parent_path(&master, path, 1, BIP32_FLAG_KEY_PUBLIC, &child);
    if (ret == WALLY_OK)
        ret = bip32_key_serialize(&child, BIP32_FLAG_KEY_PUBLIC, xpub, sizeof(xpub));
    if (ret == WALLY_OK)
        ret = wally_map_keypath_add(map, xpub, sizeof(xpub), val, sizeof(val), path, 1);
    if (ret == WALLY_OK && map->num_items != 2)
        ret = WALLY_EINVAL;
    wally_map_free(map);
    return ret;
}

/*
 * Descriptors
 */
static int tpsbt_descriptor(const char *str, uint32_t flags, uint32_t child_num,
                            bool get_address, bool check_address)
{
    unsigned char script[256];
    struct wally_descriptor *desc = NULL;
    char *addr = NULL;
    size_t written;
    int ret = wally_descriptor_parse(str, NULL, WALLY_NETWORK_BITCOIN_MAINNET,
                                     flags, &desc);

    if (ret == WALLY_OK)
        ret = wally_descriptor_to_script(desc, 0, 0, 0, 0, child_num, 0,
                                         script, sizeof(script), &written);
    if (ret == WALLY_OK && written > sizeof(script))
        ret = WALLY_EINVAL;
    if (ret == WALLY_OK && get_address)
        ret = wally_descriptor_to_address(desc, 0, 0, child_num, 0, &addr);
    if (ret == WALLY_OK && check_address) {
        /* Round trip the address to a scriptpubkey */
        unsigned char spk[WALLY_SCRIPTPUBKEY_P2PKH_LEN];
        size_t spk_len;
        ret = wally_address_to_scriptpubkey(addr, WALLY_NETWORK_BITCOIN_MAINNET,
                                            spk, sizeof(spk), &spk_len);
        if (ret == WALLY_OK && (spk_len != written || memcmp(spk, script, written)))
            ret = WALLY_EINVAL;
    }
    wally_free_string(addr);
    wally_descriptor_free(desc);
    return ret;
}

static int case_psbt_desc_pkh_xpub(void)
{
    return tpsbt_descriptor("pkh(xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8/0/*)",
                            0, 5, true, true);
}

static int case_psbt_desc_wpkh_xprv(void)
{
    return tpsbt_descriptor("wpkh([3442193e/84h/0h]xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi/0h/1)",
                            0, 0, true, false);
}

static int case_psbt_desc_sh_wpkh(void)
{
    return tpsbt_descriptor("sh(wpkh(xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8/1/*))",
                            0, 2, true, true);
}

static int case_psbt_desc_wsh_multi(void)
{
    return tpsbt_descriptor("wsh(multi(2,xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8/0/*,"
                            "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/0/*))",
                            0, 3, true, false);
}

static int case_psbt_desc_tr_key(void)
{
    return tpsbt_descriptor("tr(xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8/0/*)",
                            0, 1, true, false);
}

static const char TPSBT_TR_SCRIPT[] =
    "tr(xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8/0/*,"
    "{pk(xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/0/*),"
    "pk(79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)})";

static int case_psbt_desc_tr_script(void)
{
    unsigned char hash[SHA256_LEN], cb[1 + EC_XONLY_PUBLIC_KEY_LEN + SHA256_LEN * 2];
    struct wally_descriptor *desc = NULL;
    size_t written;
    uint32_t leaf;
    int ret = tpsbt_descriptor(TPSBT_TR_SCRIPT, 0, 7, true, false);

    if (ret == WALLY_OK)
        ret = wally_descriptor_parse(TPSBT_TR_SCRIPT, NULL,
                                     WALLY_NETWORK_BITCOIN_MAINNET, 0, &desc);
    if (ret == WALLY_OK)
        ret = wally_descriptor_get_taproot_merkle_root(desc, 0, 7, 0, hash, sizeof(hash));
    for (leaf = 0; ret == WALLY_OK && leaf < 2; ++leaf) {
        ret = wally_descriptor_get_taproot_leaf_hash(desc, leaf, 0, 7, 0,
                                                     hash, sizeof(hash));
        if (ret == WALLY_OK)
            ret = wally_descriptor_get_taproot_control_block(desc, leaf, 0, 7, 0,
                                                             cb, sizeof(cb), &written);
        if (ret == WALLY_OK && written > sizeof(cb))
            ret = WALLY_EINVAL;
        if (ret == WALLY_OK)
            ret = wally_bip341_control_block_verify(cb, written);
    }
    wally_descriptor_free(desc);
    return ret;
}

static int case_psbt_desc_addr_base58(void)
{
    int ret = tpsbt_descriptor("addr(1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2)", 0, 0, true, true);
    if (ret == WALLY_OK)
        ret = tpsbt_descriptor("addr(3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy)", 0, 0, true, true);
    return ret;
}

/* bech32/bech32m addresses whose characters are all valid base58 (no '0'
 * or 'l'), for the p2wpkh and p2tr scripts of these public keys */
static int tpsbt_addr_bech32(const char *addr, const char *pub_key_hex, bool is_p2tr)
{
    unsigned char pub_key[EC_PUBLIC_KEY_LEN], expected[WALLY_SCRIPTPUBKEY_P2TR_LEN];
    unsigned char script[WALLY_SCRIPTPUBKEY_P2TR_LEN];
    char desc_str[128];
    struct wally_descriptor *desc = NULL;
    size_t expected_len, written;
    int ret = tpsbt_hex(pub_key_hex, pub_key, sizeof(pub_key));

    if (ret == WALLY_OK)
        ret = (is_p2tr ? wally_scriptpubkey_p2tr_from_bytes(pub_key, sizeof(pub_key), 0,
                                                            expected, sizeof(expected),
                                                            &expected_len)
                       : wally_witness_program_from_bytes(pub_key, sizeof(pub_key),
                                                          WALLY_SCRIPT_HASH160,
                                                          expected, sizeof(expected),
                                                          &expected_len));
    if (ret == WALLY_OK && (size_t)snprintf(desc_str, sizeof(desc_str), "addr(%s)", addr) >= sizeof(desc_str))
        ret = WALLY_EINVAL;
    if (ret == WALLY_OK)
        ret = wally_descriptor_parse(desc_str, NULL, WALLY_NETWORK_BITCOIN_MAINNET, 0, &desc);
    if (ret == WALLY_OK)
        ret = wally_descriptor_to_script(desc, 0, 0, 0, 0, 0, 0,
                                         script, sizeof(script), &written);
    if (ret == WALLY_OK &&
        (written != expected_len || memcmp(script, expected, expected_len)))
        ret = WALLY_EINVAL;
    wally_descriptor_free(desc);
    return ret;
}

static int case_psbt_desc_addr_bech32(void)
{
    int ret = tpsbt_addr_bech32("bc1qh59qynx5hm3t86jchxjzp2yk3ccvyxt6fkdqvx",
                                "02d66846e33e07dd40922a36b004d99be924ede6ff164065b16695394098bca647",
                                false);
    if (ret == WALLY_OK)
        ret = tpsbt_addr_bech32("bc1pmn7u2r3mh7svxfwweufzx5h4pjwfxtggdd2tg33d2enkw3ppx3psjwhk7s",
                                "028ebfb932217d7a14976c4234291906fefbee84083264c2bb81217bb4b5bed5d0",
                                true);
    return ret;
}

static int case_psbt_desc_wif(void)
{
    int ret = tpsbt_descriptor("pkh(L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1)",
                               0, 0, true, true);
    if (ret == WALLY_OK)
        ret = tpsbt_descriptor("wpkh(L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1)",
                               0, 0, true, false);
    return ret;
}

static int case_psbt_desc_checksum(void)
{
    const char *expected = "wvk84d79";
    struct wally_descriptor *desc = NULL;
    char *checksum = NULL, *canonical = NULL;
    int ret = wally_descriptor_parse("wpkh(xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8/0/*)#wvk84d79",
                                     NULL, WALLY_NETWORK_BITCOIN_MAINNET,
                                     WALLY_MINISCRIPT_REQUIRE_CHECKSUM, &desc);
    if (ret == WALLY_OK)
        ret = wally_descriptor_get_checksum(desc, 0, &checksum);
    if (ret == WALLY_OK && strcmp(checksum, expected))
        ret = WALLY_EINVAL;
    if (ret == WALLY_OK)
        ret = wally_descriptor_canonicalize(desc, 0, &canonical);
    wally_free_string(canonical);
    wally_free_string(checksum);
    wally_descriptor_free(desc);
    return ret;
}

static const char TPSBT_DERIVE_DESC[] =
    "wsh(multi(1,[3442193e/48h]xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8/0/*,"
    "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U/1h/*))";

static int case_psbt_desc_derive_key(void)
{
    unsigned char fingerprint[BIP32_KEY_FINGERPRINT_LEN];
    struct wally_descriptor *desc = NULL;
    struct ext_key key;
    int ret = wally_descriptor_parse(TPSBT_DERIVE_DESC, NULL,
                                     WALLY_NETWORK_BITCOIN_MAINNET, 0, &desc);
    if (ret == WALLY_OK)
        ret = wally_descriptor_derive_bip32_key(desc, 0, 0, 0, 3, BIP32_FLAG_KEY_PUBLIC, &key);
    if (ret == WALLY_OK)
        ret = wally_descriptor_derive_bip32_key(desc, 1, 0, 0, 3, 0, &key);
    if (ret == WALLY_OK)
        ret = wally_descriptor_derive_bip32_key(desc, 1, 0, 0, 4, BIP32_FLAG_KEY_PUBLIC, &key);
    if (ret == WALLY_OK)
        ret = wally_descriptor_derive_bip32_key(desc, 0, 0, 0, 5,
                                                BIP32_FLAG_KEY_PUBLIC | BIP32_FLAG_SKIP_HASH, &key);
    if (ret == WALLY_OK)
        ret = bip32_key_get_fingerprint(&key, fingerprint, sizeof(fingerprint));
    wally_descriptor_free(desc);
    wally_clear(&key, sizeof(key));
    return ret;
}

/* A wallet policy: xpubs substituted for @n keys are parsed (and so hashed)
 * both when validating the policy variables and when parsing */
static int case_psbt_desc_policy(void)
{
    static const char *xpubs[2] = {
        "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
        "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB"
    };
    const uint32_t flags = WALLY_MINISCRIPT_POLICY_TEMPLATE | WALLY_MINISCRIPT_UNIQUE_KEYPATHS;
    struct wally_descriptor *desc = NULL;
    struct wally_map *vars = NULL;
    char *addr = NULL;
    int ret = wally_map_init_alloc(2, NULL, &vars);

    if (ret == WALLY_OK)
        ret = wally_map_add(vars, (const unsigned char *)"@0", 2,
                            (const unsigned char *)xpubs[0], strlen(xpubs[0]));
    if (ret == WALLY_OK)
        ret = wally_map_add(vars, (const unsigned char *)"@1", 2,
                            (const unsigned char *)xpubs[1], strlen(xpubs[1]));
    if (ret == WALLY_OK)
        ret = wally_descriptor_parse("wsh(multi(1,@0/<0;1>/*,@1/<0;1>/*))", vars,
                                     WALLY_NETWORK_BITCOIN_MAINNET, flags, &desc);
    if (ret == WALLY_OK)
        ret = wally_descriptor_to_address(desc, 0, 1, 2, 0, &addr);
    wally_free_string(addr);
    wally_descriptor_free(desc);
    wally_map_free(vars);
    return ret;
}

/* Deriving a public key from an xpub with a child path, using flags 0 as
 * for an xpub without a child path or a raw public key */
static int case_psbt_desc_derive_xpub_path(void)
{
    struct wally_descriptor *desc = NULL;
    struct ext_key key;
    int ret = wally_descriptor_parse(TPSBT_DERIVE_DESC, NULL,
                                     WALLY_NETWORK_BITCOIN_MAINNET, 0, &desc);
    if (ret == WALLY_OK)
        ret = wally_descriptor_derive_bip32_key(desc, 0, 0, 0, 3, 0, &key);
    wally_descriptor_free(desc);
    wally_clear(&key, sizeof(key));
    return ret;
}

/*
 * Addresses
 */
static int case_psbt_bip32_key_to_address(void)
{
    struct ext_key key;
    char *addr = NULL;
    int ret = bip32_key_from_base58(TPSBT_XPUB, &key);

    if (ret == WALLY_OK)
        ret = wally_bip32_key_to_address(&key, WALLY_ADDRESS_TYPE_P2PKH,
                                         WALLY_ADDRESS_VERSION_P2PKH_MAINNET, &addr);
    wally_free_string(addr);
    addr = NULL;
    if (ret == WALLY_OK)
        ret = wally_bip32_key_to_address(&key, WALLY_ADDRESS_TYPE_P2SH_P2WPKH,
                                         WALLY_ADDRESS_VERSION_P2SH_MAINNET, &addr);
    wally_free_string(addr);
    addr = NULL;
    if (ret == WALLY_OK)
        ret = wally_bip32_key_to_addr_segwit(&key, "bc", 0, &addr);
    wally_free_string(addr);
    return ret;
}

static int case_psbt_address_roundtrip(void)
{
    static const char *addrs[2] = {
        "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"
    };
    unsigned char spk[WALLY_SCRIPTPUBKEY_P2PKH_LEN];
    char *addr = NULL;
    size_t i, written;
    int ret = WALLY_OK;

    for (i = 0; ret == WALLY_OK && i < 2; ++i) {
        ret = wally_address_to_scriptpubkey(addrs[i], WALLY_NETWORK_BITCOIN_MAINNET,
                                            spk, sizeof(spk), &written);
        if (ret == WALLY_OK && written > sizeof(spk))
            ret = WALLY_EINVAL;
        if (ret == WALLY_OK)
            ret = wally_scriptpubkey_to_address(spk, written,
                                                WALLY_NETWORK_BITCOIN_MAINNET, &addr);
        if (ret == WALLY_OK && strcmp(addr, addrs[i]))
            ret = WALLY_EINVAL;
        wally_free_string(addr);
        addr = NULL;
    }
    return ret;
}

/*
 * Scripts
 */
static int case_psbt_script_hash_flags(void)
{
    unsigned char pub_key[EC_PUBLIC_KEY_LEN], out[64];
    size_t written;
    int ret = tpsbt_hex(TPSBT_PUB_HEX, pub_key, sizeof(pub_key));

    if (ret == WALLY_OK)
        ret = wally_scriptpubkey_p2pkh_from_bytes(pub_key, sizeof(pub_key),
                                                  WALLY_SCRIPT_HASH160,
                                                  out, sizeof(out), &written);
    if (ret == WALLY_OK)
        ret = wally_scriptpubkey_p2sh_from_bytes(pub_key, sizeof(pub_key),
                                                 WALLY_SCRIPT_HASH160,
                                                 out, sizeof(out), &written);
    if (ret == WALLY_OK)
        ret = wally_witness_program_from_bytes(pub_key, sizeof(pub_key),
                                               WALLY_SCRIPT_HASH160,
                                               out, sizeof(out), &written);
    if (ret == WALLY_OK)
        ret = wally_witness_program_from_bytes(pub_key, sizeof(pub_key),
                                               WALLY_SCRIPT_SHA256,
                                               out, sizeof(out), &written);
    if (ret == WALLY_OK)
        ret = wally_script_push_from_bytes(pub_key, sizeof(pub_key),
                                           WALLY_SCRIPT_HASH160,
                                           out, sizeof(out), &written);
    if (ret == WALLY_OK)
        ret = wally_script_push_from_bytes(pub_key, sizeof(pub_key),
                                           WALLY_SCRIPT_SHA256,
                                           out, sizeof(out), &written);
    if (ret == WALLY_OK)
        ret = wally_scriptpubkey_p2tr_from_bytes(pub_key, sizeof(pub_key), 0,
                                                 out, sizeof(out), &written);
    return ret;
}

static int case_psbt_bip341_tweak(void)
{
    unsigned char pub_key[EC_PUBLIC_KEY_LEN], priv_key[EC_PRIVATE_KEY_LEN];
    unsigned char merkle_root[SHA256_LEN], out[EC_PUBLIC_KEY_LEN];
    int ret = tpsbt_hex(TPSBT_PUB_HEX, pub_key, sizeof(pub_key));

    memset(merkle_root, 0x42, sizeof(merkle_root));
    if (ret == WALLY_OK)
        ret = tpsbt_hex(TPSBT_PRIVS[1], priv_key, sizeof(priv_key));
    if (ret == WALLY_OK)
        ret = wally_ec_public_key_bip341_tweak(pub_key, sizeof(pub_key), NULL, 0, 0,
                                               out, sizeof(out));
    if (ret == WALLY_OK)
        ret = wally_ec_public_key_bip341_tweak(pub_key + 1, EC_XONLY_PUBLIC_KEY_LEN,
                                               merkle_root, sizeof(merkle_root), 0,
                                               out, sizeof(out));
#ifdef BUILD_ELEMENTS
    if (ret == WALLY_OK)
        ret = wally_ec_public_key_bip341_tweak(pub_key, sizeof(pub_key),
                                               merkle_root, sizeof(merkle_root),
                                               EC_FLAG_ELEMENTS, out, sizeof(out));
#endif
    if (ret == WALLY_OK)
        ret = wally_ec_private_key_bip341_tweak(priv_key, sizeof(priv_key), NULL, 0, 0,
                                                out, EC_PRIVATE_KEY_LEN);
    if (ret == WALLY_OK)
        ret = wally_ec_private_key_bip341_tweak(priv_key, sizeof(priv_key),
                                                merkle_root, sizeof(merkle_root), 0,
                                                out, EC_PRIVATE_KEY_LEN);
    wally_clear_2(priv_key, sizeof(priv_key), out, sizeof(out));
    return ret;
}

/*
 * Extra checks
 */

/* Signing cache: a failed signature hash computation must not leave bad
 * data in the cache. For every PSA call made computing all sighashes with
 * an empty cache, fail it, then recompute without failure (using whatever
 * the failed call cached) and compare against the uncached results */
static struct wally_psbt *tpsbt_cache_psbt;
static unsigned char tpsbt_cache_hashes[4 * SHA256_LEN];

static int tpsbt_cache_sighashes(void)
{
    return tpsbt_sighashes(tpsbt_cache_psbt, tpsbt_cache_hashes);
}

static bool tpsbt_check_cache(const char *b64)
{
    unsigned char expected[4 * SHA256_LEN];
    size_t i, total;
    bool ok = false;
    int ret;

    fail_at = NO_FAILURE;
    if (wally_psbt_from_base64(b64, 0, &tpsbt_cache_psbt) != WALLY_OK ||
        run_case(tpsbt_cache_sighashes, NO_FAILURE) != WALLY_OK) {
        printf("check_psbt_signing_cache: setup failed\n");
        goto done;
    }
    memcpy(expected, tpsbt_cache_hashes, sizeof(expected));
    if (wally_psbt_signing_cache_enable(tpsbt_cache_psbt, 0) != WALLY_OK ||
        run_case(tpsbt_cache_sighashes, NO_FAILURE) != WALLY_OK ||
        memcmp(expected, tpsbt_cache_hashes, tpsbt_cache_psbt->num_inputs * SHA256_LEN)) {
        printf("check_psbt_signing_cache: cached sighashes differ\n");
        goto done;
    }
    /* Count the calls made with an empty cache */
    wally_psbt_signing_cache_enable(tpsbt_cache_psbt, 0);
    run_case(tpsbt_cache_sighashes, NO_FAILURE);
    total = num_calls;

    for (i = 0; i < total; ++i) {
        wally_psbt_signing_cache_enable(tpsbt_cache_psbt, 0); /* Empty the cache */
        ret = run_case(tpsbt_cache_sighashes, i);
        if (!injected || ret != WALLY_ERROR || ops_leaked()) {
            printf("check_psbt_signing_cache: failing PSA call %zu of %zu returned %d\n",
                   i, total, ret);
            goto done;
        }
        memset(tpsbt_cache_hashes, 0, sizeof(tpsbt_cache_hashes));
        ret = run_case(tpsbt_cache_sighashes, NO_FAILURE);
        if (ret != WALLY_OK ||
            memcmp(expected, tpsbt_cache_hashes, tpsbt_cache_psbt->num_inputs * SHA256_LEN)) {
            printf("check_psbt_signing_cache: cache poisoned by failing PSA call %zu of %zu (%d)\n",
                   i, total, ret);
            goto done;
        }
    }
    ok = true;
done:
    fail_at = NO_FAILURE;
    wally_psbt_free(tpsbt_cache_psbt);
    tpsbt_cache_psbt = NULL;
    return ok;
}

static bool check_psbt_signing_cache(void)
{
    return tpsbt_check_cache(TPSBT_MIXED) && tpsbt_check_cache(TPSBT_TAPROOT);
}

/* A key derived from a descriptor with BIP32_FLAG_SKIP_HASH has its
 * fingerprint computed lazily: a failed computation must not be cached */
static struct ext_key tpsbt_lazy_key;

static int tpsbt_lazy_fingerprint(void)
{
    unsigned char fingerprint[BIP32_KEY_FINGERPRINT_LEN];
    return bip32_key_get_fingerprint(&tpsbt_lazy_key, fingerprint, sizeof(fingerprint));
}

static bool check_psbt_desc_lazy_fingerprint(void)
{
    struct wally_descriptor *desc = NULL;
    struct ext_key full;
    size_t i, total;
    bool ok = false;
    int ret;

    fail_at = NO_FAILURE;
    if (wally_descriptor_parse(TPSBT_DERIVE_DESC, NULL,
                               WALLY_NETWORK_BITCOIN_MAINNET, 0, &desc) != WALLY_OK ||
        wally_descriptor_derive_bip32_key(desc, 0, 0, 0, 9, BIP32_FLAG_KEY_PUBLIC,
                                          &full) != WALLY_OK ||
        wally_descriptor_derive_bip32_key(desc, 0, 0, 0, 9,
                                          BIP32_FLAG_KEY_PUBLIC | BIP32_FLAG_SKIP_HASH,
                                          &tpsbt_lazy_key) != WALLY_OK ||
        !mem_is_zero(tpsbt_lazy_key.hash160, sizeof(tpsbt_lazy_key.hash160))) {
        printf("check_psbt_desc_lazy_fingerprint: setup failed\n");
        goto done;
    }
    /* Count the calls */
    run_case(tpsbt_lazy_fingerprint, NO_FAILURE);
    total = num_calls;
    for (i = 0; i < total; ++i) {
        wally_clear(tpsbt_lazy_key.hash160, sizeof(tpsbt_lazy_key.hash160));
        ret = run_case(tpsbt_lazy_fingerprint, i);
        if (!injected || ret != WALLY_ERROR || ops_leaked() ||
            !mem_is_zero(tpsbt_lazy_key.hash160, sizeof(tpsbt_lazy_key.hash160))) {
            printf("check_psbt_desc_lazy_fingerprint: failing PSA call %zu of %zu returned %d\n",
                   i, total, ret);
            goto done;
        }
        ret = run_case(tpsbt_lazy_fingerprint, NO_FAILURE);
        if (ret != WALLY_OK ||
            memcmp(tpsbt_lazy_key.hash160, full.hash160, sizeof(full.hash160))) {
            printf("check_psbt_desc_lazy_fingerprint: fingerprint poisoned by failing PSA call %zu of %zu\n",
                   i, total);
            goto done;
        }
    }
    ok = true;
done:
    fail_at = NO_FAILURE;
    wally_descriptor_free(desc);
    return ok;
}

#ifdef BUILD_ELEMENTS
/*
 * elements cases
 */
/*
 * Elements test cases.
 */

/* Returned by a case when a result differs from its expected value. This is
 * distinct from WALLY_ERROR so that a call returning WALLY_OK with a bad
 * result after an injected failure is not mistaken for correct reporting */
#define ELEMENTS_MISMATCH (-99)

/* Decode a hex constant; returns WALLY_OK only if it decodes to exactly len bytes */
static int elements_hex(const char *hex, unsigned char *bytes_out, size_t len)
{
    size_t written;
    int ret = wally_hex_to_bytes(hex, bytes_out, len, &written);
    if (ret == WALLY_OK && written != len)
        ret = WALLY_EINVAL;
    return ret;
}

/* Compare a result with its expected hex value */
static int elements_expect_hex(const char *hex, const unsigned char *bytes, size_t len)
{
    unsigned char expected[64];
    int ret;

    if (len > sizeof(expected))
        return WALLY_EINVAL;
    ret = elements_hex(hex, expected, len);
    if (ret == WALLY_OK && memcmp(expected, bytes, len))
        ret = ELEMENTS_MISMATCH;
    return ret;
}

/* Compare a string result with its expected value */
static int elements_expect_str(const char *expected, const char *str)
{
    return str && !strcmp(expected, str) ? WALLY_OK : ELEMENTS_MISMATCH;
}

/* Vectors from src/test/test_elements.py */
static const char ELEMENTS_SENDER_PK[] =
    "0378d8b53305ed6482db0c8f5eb8b0ca3d5c314d7773c584faa8cf587ee8137244";
static const char ELEMENTS_OUR_SK[] =
    "e8ba74f899e6b06da05fb255511c7adcea41f186326ef4fc45290fa8043f7af5";
static const char ELEMENTS_SCRIPT[] =
    "76a9145976d83033bde4f12713ae3706b25e92fb608b9188ac";
static const char ELEMENTS_ASSET_COMMITMENT[] =
    "0b9d043d60286407330e12001e539559f6227c9999abf251b7497bba53ac20cd70";
static const char ELEMENTS_VALUE_COMMITMENT[] =
    "09b67565b370abf41d81fe0ed6378e7228e9ae01d1b72b69582f83db1fca522148";
static const char ELEMENTS_ASSET[] =
    "25b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a";
static const char ELEMENTS_ABF[] =
    "3f2f58e80fbe77e8aad8268f1baebc3548c777ba8271f99ce73210ad993d907d";
static const char ELEMENTS_VBF[] =
    "51f109e34d0282b6efac36d118131060f7f79b867b67a95bebd087eda2ccd796";

/*
 * A small Elements tx: input 0 is a plain input, input 1 an asset issuance.
 * Output 0 pays to a P2WPKH script with (fake) proofs so that
 * SIGHASH_RANGEPROOF hashes the output witness; output 1 is a fee output.
 */
static int elements_make_tx(struct wally_tx **output)
{
    unsigned char txhash[WALLY_TXHASH_LEN], entropy[SHA256_LEN];
    unsigned char asset[WALLY_TX_ASSET_CT_ASSET_LEN];
    unsigned char value[WALLY_TX_ASSET_CT_VALUE_UNBLIND_LEN];
    unsigned char amount[WALLY_TX_ASSET_CT_VALUE_UNBLIND_LEN];
    unsigned char script[22] = { 0x00, 0x14 };
    const unsigned char surjectionproof[3] = { 0x01, 0x00, 0x01 };
    const unsigned char rangeproof[4] = { 0x60, 0x23, 0x00, 0x00 };
    struct wally_tx *tx = NULL;
    int ret;

    *output = NULL;
    memset(txhash, 0x11, sizeof(txhash));
    memset(entropy, 0x22, sizeof(entropy));
    memset(script + 2, 0x33, sizeof(script) - 2);
    asset[0] = 0x01;
    ret = elements_hex(ELEMENTS_ASSET, asset + 1, sizeof(asset) - 1);
    if (ret == WALLY_OK)
        ret = wally_tx_confidential_value_from_satoshi(1000, value, sizeof(value));
    if (ret == WALLY_OK)
        ret = wally_tx_confidential_value_from_satoshi(21000000, amount, sizeof(amount));
    if (ret == WALLY_OK)
        ret = wally_tx_init_alloc(2, 0, 2, 2, &tx);
    if (ret == WALLY_OK)
        ret = wally_tx_add_elements_raw_input(tx, txhash, sizeof(txhash), 0, 0xfffffffd,
                                              NULL, 0, NULL, NULL, 0, NULL, 0,
                                              NULL, 0, NULL, 0, NULL, 0, NULL, 0,
                                              NULL, 0);
    if (ret == WALLY_OK) {
        txhash[0] = 0x44;
        ret = wally_tx_add_elements_raw_input(tx, txhash, sizeof(txhash),
                                              1 | WALLY_TX_ISSUANCE_FLAG, 0xfffffffe,
                                              NULL, 0, NULL, NULL, 0,
                                              entropy, sizeof(entropy),
                                              amount, sizeof(amount),
                                              value, sizeof(value),
                                              NULL, 0, NULL, 0, NULL, 0);
    }
    if (ret == WALLY_OK)
        ret = wally_tx_add_elements_raw_output(tx, script, sizeof(script),
                                               asset, sizeof(asset),
                                               value, sizeof(value), NULL, 0,
                                               surjectionproof, sizeof(surjectionproof),
                                               rangeproof, sizeof(rangeproof), 0);
    if (ret == WALLY_OK)
        ret = wally_tx_add_elements_raw_output(tx, NULL, 0, asset, sizeof(asset),
                                               value, sizeof(value), NULL, 0,
                                               NULL, 0, NULL, 0, 0);
    if (ret == WALLY_OK)
        *output = tx;
    else
        wally_tx_free(tx);
    return ret;
}

/* Segwit v0 and pre-segwit Elements sighashes, using the deprecated call */
static int elements_segwit_v0_sighashes(const struct wally_tx *tx)
{
    static const uint32_t sighashes[] = {
        WALLY_SIGHASH_ALL,
        WALLY_SIGHASH_ALL | WALLY_SIGHASH_RANGEPROOF,
        WALLY_SIGHASH_SINGLE | WALLY_SIGHASH_RANGEPROOF,
        WALLY_SIGHASH_NONE | WALLY_SIGHASH_ANYONECANPAY,
    };
    const unsigned char scriptcode[] = {
        0x76, 0xa9, 0x14, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
        0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x88, 0xac
    };
    unsigned char value[WALLY_TX_ASSET_CT_VALUE_UNBLIND_LEN];
    unsigned char out[SHA256_LEN];
    size_t i, index;
    int ret = wally_tx_confidential_value_from_satoshi(5000, value, sizeof(value));

    for (index = 0; ret == WALLY_OK && index < 2; ++index) {
        for (i = 0; ret == WALLY_OK && i < sizeof(sighashes) / sizeof(sighashes[0]); ++i)
            ret = wally_tx_get_elements_signature_hash(tx, index,
                                                       scriptcode, sizeof(scriptcode),
                                                       value, sizeof(value),
                                                       sighashes[i],
                                                       WALLY_TX_FLAG_USE_WITNESS,
                                                       out, sizeof(out));
        if (ret == WALLY_OK) /* Pre-segwit */
            ret = wally_tx_get_elements_signature_hash(tx, index,
                                                       scriptcode, sizeof(scriptcode),
                                                       NULL, 0, WALLY_SIGHASH_ALL, 0,
                                                       out, sizeof(out));
    }
    return ret;
}

static int case_elements_sighash_segwit_v0(void)
{
    /* Expected SIGHASH_ALL | SIGHASH_RANGEPROOF sighashes for inputs 0 and 1,
     * computed with release_1.3.1 for this tx */
    static const char *expected[2] = {
        "61a2b80c14658eb6a2dfb906047df014ffb4ff3b98040c7bccb6b8dfaa440c21",
        "698c894a80bbc0d539d156f1456d949d6e522379f0330f494610a38eaa4f2c04"
    };
    const unsigned char script[] = { 0x51 };
    unsigned char value[WALLY_TX_ASSET_CT_VALUE_UNBLIND_LEN];
    unsigned char out[SHA256_LEN];
    struct wally_tx *tx;
    size_t i;
    int ret = elements_make_tx(&tx);

    if (ret == WALLY_OK)
        ret = elements_segwit_v0_sighashes(tx);
    if (ret == WALLY_OK)
        ret = wally_tx_confidential_value_from_satoshi(1000, value, sizeof(value));
    for (i = 0; ret == WALLY_OK && i < 2; ++i) {
        ret = wally_tx_get_elements_signature_hash(tx, i, script, sizeof(script),
                                                   value, sizeof(value),
                                                   WALLY_SIGHASH_ALL | WALLY_SIGHASH_RANGEPROOF,
                                                   WALLY_TX_FLAG_USE_WITNESS,
                                                   out, sizeof(out));
        if (ret == WALLY_OK)
            ret = elements_expect_hex(expected[i], out, sizeof(out));
    }
    wally_tx_free(tx);
    return ret;
}

/* Pre-segwit Elements sighashes with SIGHASH_RANGEPROOF, which hash each
 * output's rangeproof and surjection proof (see legacy_signature_hash).
 * The expected values were computed with release_1.3.1 for this tx */
static int case_elements_sighash_legacy_rangeproof(void)
{
    static const struct {
        size_t index;
        uint32_t sighash;
        const char *expected;
    } calls[] = {
        { 0, WALLY_SIGHASH_ALL,
          "19132b957c69e4226fae3bba70be8638312c95e97e6d63b5fbcf9a6ae1693cb6" },
        { 0, WALLY_SIGHASH_ALL | WALLY_SIGHASH_RANGEPROOF,
          "00df3e6f6456883cfd8045a2b0a0aede757b862893a8fb77de5743b749826aae" },
        { 0, WALLY_SIGHASH_SINGLE | WALLY_SIGHASH_RANGEPROOF | WALLY_SIGHASH_ANYONECANPAY,
          "280b0c11e1d1d37016dd94ce69bf505f09938a09e39669359e476d3535237547" },
        { 1, WALLY_SIGHASH_NONE | WALLY_SIGHASH_RANGEPROOF,
          "8815ce77a7d424cac3cd3299a9daa911f699c24d9557fd85580140657588be48" },
        { 1, WALLY_SIGHASH_ALL | WALLY_SIGHASH_RANGEPROOF,
          "2a1e533f730315ec937f9a11ba23a838853a237e4cdd5feaf886389616beda16" },
    };
    const unsigned char script[] = { 0x51 };
    unsigned char out[SHA256_LEN];
    struct wally_tx *tx;
    size_t i;
    int ret = elements_make_tx(&tx);

    for (i = 0; ret == WALLY_OK && i < sizeof(calls) / sizeof(calls[0]); ++i) {
        ret = wally_tx_get_elements_signature_hash(tx, calls[i].index,
                                                   script, sizeof(script),
                                                   NULL, 0, calls[i].sighash, 0,
                                                   out, sizeof(out));
        if (ret == WALLY_OK)
            ret = elements_expect_hex(calls[i].expected, out, sizeof(out));
    }
    wally_tx_free(tx);
    return ret;
}

/* Maps of the P2TR scripts, asset and value commitments spent by each input */
static int elements_make_taproot_maps(struct wally_map **scripts,
                                      struct wally_map **assets,
                                      struct wally_map **values)
{
    unsigned char script[34] = { 0x51, 0x20 };
    unsigned char asset[WALLY_TX_ASSET_CT_ASSET_LEN];
    unsigned char value[WALLY_TX_ASSET_CT_VALUE_LEN];
    uint32_t i;
    int ret;

    *scripts = *assets = *values = NULL;
    ret = elements_hex(ELEMENTS_ASSET_COMMITMENT, asset, sizeof(asset));
    if (ret == WALLY_OK)
        ret = elements_hex(ELEMENTS_VALUE_COMMITMENT, value, sizeof(value));
    if (ret == WALLY_OK)
        ret = wally_map_init_alloc(2, NULL, scripts);
    if (ret == WALLY_OK)
        ret = wally_map_init_alloc(2, NULL, assets);
    if (ret == WALLY_OK)
        ret = wally_map_init_alloc(2, NULL, values);
    for (i = 0; ret == WALLY_OK && i < 2; ++i) {
        memset(script + 2, 0x55 + i, sizeof(script) - 2);
        ret = wally_map_add_integer(*scripts, i, script, sizeof(script));
        if (ret == WALLY_OK)
            ret = wally_map_add_integer(*assets, i, asset, sizeof(asset));
        if (ret == WALLY_OK)
            ret = wally_map_add_integer(*values, i, value, sizeof(value));
    }
    return ret;
}

/* Elements taproot sighashes for key and script path spends */
static int elements_taproot_sighashes(const struct wally_tx *tx,
                                      const struct wally_map *scripts,
                                      const struct wally_map *assets,
                                      const struct wally_map *values,
                                      struct wally_map *cache)
{
    static const struct {
        size_t index;
        uint32_t sighash;
        bool script_path;
        bool with_annex;
    } calls[] = {
        { 0, WALLY_SIGHASH_DEFAULT, false, false },
        { 1, WALLY_SIGHASH_ALL, false, false },
        { 1, WALLY_SIGHASH_SINGLE | WALLY_SIGHASH_ANYONECANPAY, false, false },
        { 0, WALLY_SIGHASH_NONE, true, false },
        { 1, WALLY_SIGHASH_ALL | WALLY_SIGHASH_ANYONECANPAY, true, true },
    };
    /* <x-only pubkey> OP_CHECKSIG */
    unsigned char leaf[34] = { 0x20 };
    const unsigned char annex[3] = { 0x50, 0x01, 0x02 };
    unsigned char genesis[SHA256_LEN];
    unsigned char out[SHA256_LEN];
    size_t i;
    int ret = WALLY_OK;

    memset(leaf + 1, 0x77, 32);
    leaf[33] = 0xac;
    memset(genesis, 0x66, sizeof(genesis));

    for (i = 0; ret == WALLY_OK && i < sizeof(calls) / sizeof(calls[0]); ++i)
        ret = wally_tx_get_input_signature_hash(tx, calls[i].index,
                                                scripts, assets, values,
                                                calls[i].script_path ? leaf : NULL,
                                                calls[i].script_path ? sizeof(leaf) : 0,
                                                calls[i].script_path ? 1 : 0,
                                                WALLY_NO_CODESEPARATOR,
                                                calls[i].with_annex ? annex : NULL,
                                                calls[i].with_annex ? sizeof(annex) : 0,
                                                genesis, sizeof(genesis),
                                                calls[i].sighash, WALLY_SIGTYPE_SW_V1,
                                                cache, out, sizeof(out));
    return ret;
}

static int elements_taproot_case(bool use_cache)
{
    struct wally_tx *tx = NULL;
    struct wally_map *scripts, *assets, *values, *cache = NULL;
    int ret = elements_make_taproot_maps(&scripts, &assets, &values);

    if (ret == WALLY_OK)
        ret = elements_make_tx(&tx);
    if (ret == WALLY_OK && use_cache)
        ret = wally_map_init_alloc(TXIO_CACHE_INITIAL_SIZE, NULL, &cache);
    if (ret == WALLY_OK)
        ret = elements_taproot_sighashes(tx, scripts, assets, values, cache);
    /* The cache may have been partly filled: use it again */
    if (ret == WALLY_OK && use_cache)
        ret = elements_taproot_sighashes(tx, scripts, assets, values, cache);
    wally_map_free(cache);
    wally_tx_free(tx);
    wally_map_free(scripts);
    wally_map_free(assets);
    wally_map_free(values);
    return ret;
}

static int case_elements_sighash_taproot(void)
{
    return elements_taproot_case(false);
}

static int case_elements_sighash_taproot_cached(void)
{
    return elements_taproot_case(true);
}

/*
 * Compute a sequence of Elements sighashes for 'tx', optionally with a
 * signing cache, writing one sighash per call to 'out'.
 * The sequence mixes segwit v0 and taproot sighashes, as a PSBT with mixed
 * inputs would when signing with its signing cache.
 */
#define ELEMENTS_SEQ_LEN 7
static int elements_sighash_sequence(const struct wally_tx *tx,
                                     const struct wally_map *scripts,
                                     const struct wally_map *assets,
                                     const struct wally_map *values,
                                     struct wally_map *cache,
                                     bool with_rangeproof,
                                     unsigned char out[ELEMENTS_SEQ_LEN][SHA256_LEN])
{
    static const struct {
        size_t index;
        uint32_t sighash;
        uint32_t sigtype;
    } calls[ELEMENTS_SEQ_LEN] = {
        { 0, WALLY_SIGHASH_ALL, WALLY_SIGTYPE_SW_V0 },
        { 1, WALLY_SIGHASH_ALL, WALLY_SIGTYPE_SW_V0 },
        { 0, WALLY_SIGHASH_DEFAULT, WALLY_SIGTYPE_SW_V1 },
        { 1, WALLY_SIGHASH_ALL, WALLY_SIGTYPE_SW_V1 },
        { 1, WALLY_SIGHASH_SINGLE, WALLY_SIGTYPE_SW_V0 },
        { 0, WALLY_SIGHASH_ALL | WALLY_SIGHASH_ANYONECANPAY, WALLY_SIGTYPE_SW_V1 },
        { 0, WALLY_SIGHASH_ALL, WALLY_SIGTYPE_SW_V0 },
    };
    const unsigned char scriptcode[] = { 0x51 };
    unsigned char genesis[SHA256_LEN];
    size_t i;
    int ret = WALLY_OK;

    memset(genesis, 0x66, sizeof(genesis));
    for (i = 0; ret == WALLY_OK && i < ELEMENTS_SEQ_LEN; ++i) {
        const bool is_v0 = calls[i].sigtype == WALLY_SIGTYPE_SW_V0;
        uint32_t sighash = calls[i].sighash;
        if (is_v0 && with_rangeproof)
            sighash |= WALLY_SIGHASH_RANGEPROOF;
        ret = wally_tx_get_input_signature_hash(tx, calls[i].index,
                                                scripts, assets, values,
                                                is_v0 ? scriptcode : NULL,
                                                is_v0 ? sizeof(scriptcode) : 0,
                                                0, WALLY_NO_CODESEPARATOR,
                                                NULL, 0,
                                                is_v0 ? NULL : genesis,
                                                is_v0 ? 0 : sizeof(genesis),
                                                sighash, calls[i].sigtype,
                                                cache, out[i], SHA256_LEN);
    }
    return ret;
}

/* Check the signing cache for the sequence above: a cache filled by calls
 * that failed must not change the results of later calls using it */
static bool elements_check_sighash_cache(const char *name, bool with_rangeproof)
{
    unsigned char expected[ELEMENTS_SEQ_LEN][SHA256_LEN];
    unsigned char got[ELEMENTS_SEQ_LEN][SHA256_LEN];
    struct wally_tx *tx = NULL;
    struct wally_map *scripts, *assets, *values, *cache = NULL;
    size_t i, total;
    bool ok = false;
    int ret = elements_make_taproot_maps(&scripts, &assets, &values);

    if (ret == WALLY_OK)
        ret = elements_make_tx(&tx);
    if (ret != WALLY_OK) {
        printf("%s: setup failed (%d)\n", name, ret);
        goto done;
    }

    /* The expected results: no cache, no failure */
    num_calls = 0;
    fail_at = NO_FAILURE;
    ret = elements_sighash_sequence(tx, scripts, assets, values, NULL,
                                    with_rangeproof, expected);
    if (ret != WALLY_OK) {
        printf("%s: uncached sighashes failed (%d)\n", name, ret);
        goto done;
    }

    /* A cache filled without failures must give the same results */
    if ((ret = wally_map_init_alloc(TXIO_CACHE_INITIAL_SIZE, NULL, &cache)) != WALLY_OK) {
        printf("%s: cache allocation failed (%d)\n", name, ret);
        goto done;
    }
    num_calls = 0;
    fail_at = NO_FAILURE;
    ret = elements_sighash_sequence(tx, scripts, assets, values, cache,
                                    with_rangeproof, got);
    total = num_calls;
    if (ret != WALLY_OK) {
        printf("%s: cached sighashes failed (%d)\n", name, ret);
        goto done;
    }
    for (i = 0; i < ELEMENTS_SEQ_LEN; ++i) {
        if (memcmp(expected[i], got[i], SHA256_LEN)) {
            printf("%s: sighash %zu computed with a signing cache differs from"
                   " the uncached sighash (no failure injected)\n", name, i);
            goto done;
        }
    }
    wally_map_free(cache);
    cache = NULL;

    /* Fail each PSA call in turn while filling a fresh cache, then compute
     * all sighashes again using that cache */
    for (i = 0; i < total; ++i) {
        size_t j;
        if ((ret = wally_map_init_alloc(TXIO_CACHE_INITIAL_SIZE, NULL, &cache)) != WALLY_OK) {
            printf("%s: cache allocation failed (%d)\n", name, ret);
            goto done;
        }
        num_calls = 0;
        fail_at = i;
        injected = false;
        ret = elements_sighash_sequence(tx, scripts, assets, values, cache,
                                        with_rangeproof, got);
        if (!injected || ret != WALLY_ERROR) {
            printf("%s: failing PSA call %zu of %zu returned %d, expected %d\n",
                   name, i, total, ret, WALLY_ERROR);
            goto done;
        }
        num_calls = 0;
        fail_at = NO_FAILURE;
        ret = elements_sighash_sequence(tx, scripts, assets, values, cache,
                                        with_rangeproof, got);
        if (ret != WALLY_OK) {
            printf("%s: sighashes after failing PSA call %zu of %zu failed (%d)\n",
                   name, i, total, ret);
            goto done;
        }
        for (j = 0; j < ELEMENTS_SEQ_LEN; ++j) {
            if (memcmp(expected[j], got[j], SHA256_LEN)) {
                printf("%s: sighash %zu is wrong after failing PSA call %zu of %zu:"
                       " the signing cache was poisoned\n", name, j, i, total);
                goto done;
            }
        }
        wally_map_free(cache);
        cache = NULL;
    }
    ok = true;

done:
    fail_at = NO_FAILURE;
    if (ok && ops_leaked()) {
        printf("%s: leaked PSA operations\n", name);
        ok = false;
    }
    wally_map_free(cache);
    wally_tx_free(tx);
    wally_map_free(scripts);
    wally_map_free(assets);
    wally_map_free(values);
    return ok;
}

static bool check_elements_sighash_cache(void)
{
    return elements_check_sighash_cache("check_elements_sighash_cache", false);
}

/* As above, with SIGHASH_RANGEPROOF for the segwit v0 sighashes */
static bool check_elements_sighash_cache_rangeproof(void)
{
    return elements_check_sighash_cache("check_elements_sighash_cache_rangeproof", true);
}

static int case_elements_issuance(void)
{
    unsigned char txhash[WALLY_TXHASH_LEN], contract_hash[SHA256_LEN];
    unsigned char entropy[SHA256_LEN], out[SHA256_LEN];
    int ret;

    memset(txhash, 0x5a, sizeof(txhash));
    memset(contract_hash, 0xa5, sizeof(contract_hash));
    ret = wally_tx_elements_issuance_generate_entropy(txhash, sizeof(txhash), 3,
                                                      contract_hash, sizeof(contract_hash),
                                                      entropy, sizeof(entropy));
    if (ret == WALLY_OK)
        ret = wally_tx_elements_issuance_calculate_asset(entropy, sizeof(entropy),
                                                         out, sizeof(out));
    if (ret == WALLY_OK)
        ret = wally_tx_elements_issuance_calculate_reissuance_token(entropy, sizeof(entropy),
                                                                    0, out, sizeof(out));
    if (ret == WALLY_OK)
        ret = wally_tx_elements_issuance_calculate_reissuance_token(entropy, sizeof(entropy),
                                                                    WALLY_TX_FLAG_BLINDED_INITIAL_ISSUANCE,
                                                                    out, sizeof(out));
    return ret;
}

static int case_elements_elip150(void)
{
    unsigned char priv_key[EC_PRIVATE_KEY_LEN], pub_key[EC_PUBLIC_KEY_LEN];
    unsigned char out_priv[EC_PRIVATE_KEY_LEN], out_pub[EC_PUBLIC_KEY_LEN];
    unsigned char out_pub2[EC_PUBLIC_KEY_LEN], script[40];
    int ret;

    memset(priv_key, 0x66, sizeof(priv_key));
    memset(script, 0x11, sizeof(script));
    ret = wally_ec_public_key_from_private_key(priv_key, sizeof(priv_key),
                                               pub_key, sizeof(pub_key));
    if (ret == WALLY_OK)
        ret = wally_elip150_private_key_to_ec_private_key(priv_key, sizeof(priv_key),
                                                          script, sizeof(script),
                                                          out_priv, sizeof(out_priv));
    if (ret == WALLY_OK)
        ret = wally_elip150_private_key_to_ec_public_key(priv_key, sizeof(priv_key),
                                                         script, sizeof(script),
                                                         out_pub, sizeof(out_pub));
    if (ret == WALLY_OK)
        ret = wally_elip150_public_key_to_ec_public_key(pub_key, sizeof(pub_key),
                                                        script, sizeof(script),
                                                        out_pub2, sizeof(out_pub2));
    if (ret == WALLY_OK && memcmp(out_pub, out_pub2, sizeof(out_pub)))
        ret = ELEMENTS_MISMATCH;
    if (ret == WALLY_OK) {
        /* The tweaked private key must match the tweaked public key */
        ret = wally_ec_public_key_from_private_key(out_priv, sizeof(out_priv),
                                                   out_pub2, sizeof(out_pub2));
        if (ret == WALLY_OK && memcmp(out_pub, out_pub2, sizeof(out_pub)))
            ret = ELEMENTS_MISMATCH;
    }
    return ret;
}

static int case_elements_blinding_key_from_seed(void)
{
    unsigned char seed[BIP32_ENTROPY_LEN_256], out[HMAC_SHA512_LEN];
    size_t i;
    int ret;

    for (i = 0; i < sizeof(seed); ++i)
        seed[i] = (unsigned char)i;
    ret = wally_asset_blinding_key_from_seed(seed, sizeof(seed), out, sizeof(out));
    if (ret == WALLY_OK)
        ret = elements_expect_hex("c324ad6afd66704bcc2ffe1d9025628459d11ca52309d856410eb0946c5094ac"
                                  "f78e2d62012799039ed6d9e812e24ab5fc3a228931ccaba04dd7574bfcf6cc3d",
                                  out, sizeof(out));
    return ret;
}

static int case_elements_blinding_key_to_ec_key(void)
{
    unsigned char master_key[HMAC_SHA512_LEN], script[25];
    unsigned char priv_key[EC_PRIVATE_KEY_LEN], pub_key[EC_PUBLIC_KEY_LEN];
    size_t i;
    int ret = elements_hex(ELEMENTS_SCRIPT, script, sizeof(script));

    for (i = 0; i < sizeof(master_key); ++i)
        master_key[i] = (unsigned char)(i * 7 + 1);
    /* Full 64 byte and 32 byte (last half) master blinding keys */
    for (i = 0; ret == WALLY_OK && i < 2; ++i) {
        const unsigned char *key = i ? master_key + HMAC_SHA512_LEN / 2 : master_key;
        const size_t key_len = i ? HMAC_SHA512_LEN / 2 : HMAC_SHA512_LEN;
        ret = wally_asset_blinding_key_to_ec_private_key(key, key_len,
                                                         script, sizeof(script),
                                                         priv_key, sizeof(priv_key));
        if (ret == WALLY_OK)
            ret = wally_asset_blinding_key_to_ec_public_key(key, key_len,
                                                            script, sizeof(script),
                                                            pub_key, sizeof(pub_key));
    }
    return ret;
}

static int case_elements_blinding_key_to_abf_vbf(void)
{
    /* From src/data/liquid_txn_ledger_compare.json */
    unsigned char master_key[HMAC_SHA512_LEN / 2], hash_prevouts[SHA256_LEN];
    unsigned char out[BLINDING_FACTOR_LEN * 2];
    int ret = elements_hex("afacc503637e85da661ca1706c4ea147f1407868c48d8f92dd339ac272293cdc",
                           master_key, sizeof(master_key));
    if (ret == WALLY_OK)
        ret = elements_hex("7e78263a58236ffd160ee5a2c58c18b71637974aa95e1c72070b08208012144f",
                           hash_prevouts, sizeof(hash_prevouts));
    if (ret == WALLY_OK)
        ret = wally_asset_blinding_key_to_abf_vbf(master_key, sizeof(master_key),
                                                  hash_prevouts, sizeof(hash_prevouts),
                                                  0, out, sizeof(out));
    if (ret == WALLY_OK)
        ret = elements_expect_hex("3596308468699756abf67262166600b472c89b6571d69c3a9b681efc7c49c9ac"
                                  "45d0636c96a4a8a8f502d9117a1a392acc0e25d6d7c18fa7c634688b876fe5da",
                                  out, sizeof(out));
    if (ret == WALLY_OK)
        ret = wally_asset_blinding_key_to_abf(master_key, sizeof(master_key),
                                              hash_prevouts, sizeof(hash_prevouts),
                                              1, out, BLINDING_FACTOR_LEN);
    if (ret == WALLY_OK)
        ret = elements_expect_hex("ec2a5a9979964a041f83ef923da802d72417b87f658a522d6886a3dad1e53105",
                                  out, BLINDING_FACTOR_LEN);
    /* The vector's final VBF is not derived, so check output 0's VBF */
    if (ret == WALLY_OK)
        ret = wally_asset_blinding_key_to_vbf(master_key, sizeof(master_key),
                                              hash_prevouts, sizeof(hash_prevouts),
                                              0, out, BLINDING_FACTOR_LEN);
    if (ret == WALLY_OK)
        ret = elements_expect_hex("45d0636c96a4a8a8f502d9117a1a392acc0e25d6d7c18fa7c634688b876fe5da",
                                  out, BLINDING_FACTOR_LEN);
    return ret;
}

static int case_elements_confidential_addr(void)
{
    /* From src/test/test_confidential_addr.py */
    const char *addr = "Q7qcjTLsYGoMA7TjUp97R6E6AM5VKqBik6";
    const char *addr_c = "VTpz1bNuCALgavJKgbAw9Lpp9A72rJy64XPqgqfnaLpMjRcPh5UHBqyRUE4WMZ3asjqu7YEPVAnWw2EK";
    unsigned char pub_key[EC_PUBLIC_KEY_LEN];
    char *out = NULL, *out_c = NULL;
    int ret = wally_confidential_addr_to_ec_public_key(addr_c, WALLY_CA_PREFIX_LIQUID,
                                                       pub_key, sizeof(pub_key));
    if (ret == WALLY_OK)
        ret = elements_expect_hex("02dce16018bbbb8e36de7b394df5b5166e9adb7498be7d881a85a09aeecf76b623",
                                  pub_key, sizeof(pub_key));
    if (ret == WALLY_OK)
        ret = wally_confidential_addr_to_addr(addr_c, WALLY_CA_PREFIX_LIQUID, &out);
    if (ret == WALLY_OK)
        ret = elements_expect_str(addr, out);
    if (ret == WALLY_OK)
        ret = wally_confidential_addr_from_addr(addr, WALLY_CA_PREFIX_LIQUID,
                                                pub_key, sizeof(pub_key), &out_c);
    if (ret == WALLY_OK)
        ret = elements_expect_str(addr_c, out_c);
    wally_free_string(out);
    wally_free_string(out_c);
    return ret;
}

static int case_elements_ecdh_nonce_hash(void)
{
    unsigned char pub_key[EC_PUBLIC_KEY_LEN], priv_key[EC_PRIVATE_KEY_LEN];
    unsigned char out[SHA256_LEN];
    int ret = elements_hex(ELEMENTS_SENDER_PK, pub_key, sizeof(pub_key));
    if (ret == WALLY_OK)
        ret = elements_hex(ELEMENTS_OUR_SK, priv_key, sizeof(priv_key));
    if (ret == WALLY_OK)
        ret = wally_ecdh_nonce_hash(pub_key, sizeof(pub_key),
                                    priv_key, sizeof(priv_key), out, sizeof(out));
    return ret;
}

static int case_elements_pegin_contract_script(void)
{
    /* OP_IF OP_2 <pk1> <pk2> OP_2 OP_CHECKMULTISIG
     * OP_ELSE <pk3> OP_CHECKSIG OP_ENDIF: pk1 and pk2 are tweaked,
     * pk3 (after OP_ELSE, an emergency key) is not */
    static const char redeem_hex[] =
        "6352"
        "210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        "2102c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
        "52ae67"
        "2102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
        "ac68";
    unsigned char redeem[2 + 34 + 34 + 3 + 34 + 2], out[sizeof(redeem)];
    unsigned char claim_script[22] = { 0x00, 0x14 };
    size_t written;
    int ret = elements_hex(redeem_hex, redeem, sizeof(redeem));

    memset(claim_script + 2, 0xec, sizeof(claim_script) - 2);
    if (ret == WALLY_OK)
        ret = wally_elements_pegin_contract_script_from_bytes(redeem, sizeof(redeem),
                                                              claim_script, sizeof(claim_script),
                                                              0, out, sizeof(out), &written);
    if (ret == WALLY_OK && (written != sizeof(out) ||
                            !memcmp(out, redeem, 2 + 34) || /* pk1 is tweaked */
                            memcmp(out + 2 + 34 + 34, redeem + 2 + 34 + 34,
                                   sizeof(redeem) - 2 - 34 - 34))) /* pk3 is not */
        ret = ELEMENTS_MISMATCH;
    return ret;
}

/* Blind a value with a rangeproof, then unblind it */
static int case_elements_rangeproof(void)
{
    const uint64_t value = 80000000;
    unsigned char pub_key[EC_PUBLIC_KEY_LEN], priv_key[EC_PRIVATE_KEY_LEN];
    unsigned char script[25], asset[ASSET_TAG_LEN], abf[BLINDING_FACTOR_LEN];
    unsigned char vbf[BLINDING_FACTOR_LEN], commitment[ASSET_COMMITMENT_LEN];
    unsigned char generator[ASSET_GENERATOR_LEN];
    unsigned char asset_out[ASSET_TAG_LEN], abf_out[BLINDING_FACTOR_LEN];
    unsigned char vbf_out[BLINDING_FACTOR_LEN];
    unsigned char *proof = NULL;
    uint64_t value_out = 0;
    size_t written = 0;
    int ret = elements_hex(ELEMENTS_SENDER_PK, pub_key, sizeof(pub_key));

    if (ret == WALLY_OK)
        ret = elements_hex(ELEMENTS_OUR_SK, priv_key, sizeof(priv_key));
    if (ret == WALLY_OK)
        ret = elements_hex(ELEMENTS_SCRIPT, script, sizeof(script));
    if (ret == WALLY_OK)
        ret = elements_hex(ELEMENTS_ASSET, asset, sizeof(asset));
    if (ret == WALLY_OK)
        ret = elements_hex(ELEMENTS_ABF, abf, sizeof(abf));
    if (ret == WALLY_OK)
        ret = elements_hex(ELEMENTS_VBF, vbf, sizeof(vbf));
    if (ret == WALLY_OK)
        ret = elements_hex(ELEMENTS_VALUE_COMMITMENT, commitment, sizeof(commitment));
    if (ret == WALLY_OK)
        ret = elements_hex(ELEMENTS_ASSET_COMMITMENT, generator, sizeof(generator));
    if (ret == WALLY_OK && !(proof = wally_malloc(ASSET_RANGEPROOF_MAX_LEN)))
        ret = WALLY_ENOMEM;
    if (ret == WALLY_OK)
        ret = wally_asset_rangeproof(value, pub_key, sizeof(pub_key),
                                     priv_key, sizeof(priv_key),
                                     asset, sizeof(asset), abf, sizeof(abf),
                                     vbf, sizeof(vbf), commitment, sizeof(commitment),
                                     script, sizeof(script),
                                     generator, sizeof(generator),
                                     1, 0, 36, proof, ASSET_RANGEPROOF_MAX_LEN, &written);
    if (ret == WALLY_OK)
        ret = wally_asset_unblind(pub_key, sizeof(pub_key),
                                  priv_key, sizeof(priv_key),
                                  proof, written, commitment, sizeof(commitment),
                                  script, sizeof(script),
                                  generator, sizeof(generator),
                                  asset_out, sizeof(asset_out),
                                  abf_out, sizeof(abf_out),
                                  vbf_out, sizeof(vbf_out), &value_out);
    if (ret == WALLY_OK &&
        (value_out != value || memcmp(asset_out, asset, sizeof(asset)) ||
         memcmp(abf_out, abf, sizeof(abf)) || memcmp(vbf_out, vbf, sizeof(vbf))))
        ret = ELEMENTS_MISMATCH;
    wally_free(proof);
    return ret;
}

/* ct() descriptors, from src/ctest/test_descriptor.c */
static const struct {
    const char *descriptor;
    const char *address;
} elements_ct_descriptors[] = {
    /* SLIP-77 blinding keys */
    {
        "ct(slip77(b2396b3ee20509cdb64fe24180a14a72dbd671728eaa49bac69d2bdecb5f5a04),"
        "elpkh(xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH))",
        "VTq585ahVjWarEwg2nKQ9yYirmYs5F5j74CeYYA9cq1EZD9obm7hwpx6xqq3J1AY9YRaSavEMzYfr6t7"
    }, {
        "ct(slip77(b2396b3ee20509cdb64fe24180a14a72dbd671728eaa49bac69d2bdecb5f5a04),"
        "eltr(xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH))",
        "lq1pq26fndnz8ef6umlz6e2755sm6j5jwxv3tdt2295mr4mx6ux0uf8vcc2tuvwx7k7g9kvhhpux07vqpm3qjj8uwdj94650265ustv0xy8z8wfacw9e5a5t"
    },
    /* ELIP-150 blinding keys */
    {
        "ct(xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL,"
        "elwpkh(xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH))",
        "lq1qqg5s7xj7upzl7h4q2k2wj4vq63nvaktn0egqu09nqcr6d44p4evaqknpl78t02k2xqgdh9ltmfmpy9ssk7qfvghdsfr4mvr9c"
    }, {
        "ct(c25deb86fa11e49d651d7eae27c220ef930fbd86ea023eebfa73e54875647963,"
        "elwpkh(021a8fb6bd5a653b021b98a2a785725b8ddacfe3687bc043aa7f4d25d3a48d40b5))",
        "lq1qq265u4g3k3m3qpyxjwpdrtnm293wuxgvs9xzmzcs2ck0mv5rx23w4d7xfsednsmmxrszfe7s9rs0c6cvf3dfytxax3utlmm46"
    }, {
        "ct(xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL,"
        "elsh(wpkh(xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH)))",
        "VJL8znN4XjXEUKzDaYsqdzRASGLY2KHxC4N6g5b5QvrNjXfeKp83Ci9AW2a8QzbZjpEffoy4PEywpLAZ"
    }
};

static int elements_ct_descriptor_case(size_t first, size_t count)
{
    struct wally_descriptor *descriptor = NULL;
    char *address = NULL;
    size_t i;
    int ret = WALLY_OK;

    for (i = first; ret == WALLY_OK && i < first + count; ++i) {
        ret = wally_descriptor_parse(elements_ct_descriptors[i].descriptor, NULL,
                                     WALLY_NETWORK_LIQUID, 0, &descriptor);
        if (ret == WALLY_OK)
            ret = wally_descriptor_to_address(descriptor, 0, 0, 0, 0, &address);
        if (ret == WALLY_OK)
            ret = elements_expect_str(elements_ct_descriptors[i].address, address);
        wally_free_string(address);
        address = NULL;
        wally_descriptor_free(descriptor);
        descriptor = NULL;
    }
    return ret;
}

static int case_elements_ct_descriptor_slip77(void)
{
    return elements_ct_descriptor_case(0, 2);
}

static int case_elements_ct_descriptor_elip150(void)
{
    return elements_ct_descriptor_case(2, 3);
}

/* Several addresses from ranged ct() descriptors: the addresses generated
 * before a failure must be freed (checked by valgrind/ASAN) */
static int case_elements_ct_descriptor_ranged(void)
{
    static const char *descriptors[] = {
        "ct(slip77(b2396b3ee20509cdb64fe24180a14a72dbd671728eaa49bac69d2bdecb5f5a04),"
        "elwpkh(xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/0/*))",
        "ct(xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL,"
        "elpkh(xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/<0;1>/*))",
    };
    struct wally_descriptor *descriptor = NULL;
    char *addresses[3] = { NULL, NULL, NULL };
    size_t d, i;
    int ret = WALLY_OK;

    for (d = 0; ret == WALLY_OK && d < sizeof(descriptors) / sizeof(descriptors[0]); ++d) {
        ret = wally_descriptor_parse(descriptors[d], NULL, WALLY_NETWORK_LIQUID, 0, &descriptor);
        if (ret == WALLY_OK)
            ret = wally_descriptor_to_addresses(descriptor, 0, d, 5, 0,
                                                addresses, sizeof(addresses) / sizeof(addresses[0]));
        for (i = 0; i < sizeof(addresses) / sizeof(addresses[0]); ++i) {
            if (ret == WALLY_OK && !addresses[i])
                ret = ELEMENTS_MISMATCH;
            else if (ret != WALLY_OK && addresses[i])
                ret = ELEMENTS_MISMATCH; /* Partial results must be freed and NULLed */
            wally_free_string(addresses[i]);
            addresses[i] = NULL;
        }
        wally_descriptor_free(descriptor);
        descriptor = NULL;
    }
    return ret;
}

/* A parsed ct() descriptor must be unaffected by address generation that
 * failed: generating again without failures must give the right address */
static bool check_elements_ct_descriptor_not_poisoned(void)
{
    static const char *name = "check_elements_ct_descriptor_not_poisoned";
    struct wally_descriptor *descriptor = NULL;
    char *address = NULL;
    size_t d, i, total;
    bool ok = true;
    int ret;

    for (d = 0; ok && d < sizeof(elements_ct_descriptors) / sizeof(elements_ct_descriptors[0]); ++d) {
        num_calls = 0;
        fail_at = NO_FAILURE;
        ret = wally_descriptor_parse(elements_ct_descriptors[d].descriptor, NULL,
                                     WALLY_NETWORK_LIQUID, 0, &descriptor);
        if (ret != WALLY_OK) {
            printf("%s: descriptor %zu: parse failed (%d)\n", name, d, ret);
            ok = false;
            break;
        }
        num_calls = 0;
        ret = wally_descriptor_to_address(descriptor, 0, 0, 0, 0, &address);
        total = num_calls;
        if (ret != WALLY_OK || elements_expect_str(elements_ct_descriptors[d].address, address) != WALLY_OK) {
            printf("%s: descriptor %zu: address generation failed (%d)\n", name, d, ret);
            ok = false;
        }
        wally_free_string(address);
        address = NULL;
        for (i = 0; ok && i < total; ++i) {
            num_calls = 0;
            fail_at = i;
            injected = false;
            ret = wally_descriptor_to_address(descriptor, 0, 0, 0, 0, &address);
            fail_at = NO_FAILURE;
            if (!injected || ret != WALLY_ERROR || address) {
                printf("%s: descriptor %zu: failing PSA call %zu of %zu returned %d, expected %d\n",
                       name, d, i, total, ret, WALLY_ERROR);
                ok = false;
            }
            wally_free_string(address);
            address = NULL;
            if (!ok)
                break;
            num_calls = 0;
            ret = wally_descriptor_to_address(descriptor, 0, 0, 0, 0, &address);
            if (ret != WALLY_OK || elements_expect_str(elements_ct_descriptors[d].address, address) != WALLY_OK) {
                printf("%s: descriptor %zu: wrong address (%d) after failing PSA call %zu of %zu\n",
                       name, d, ret, i, total);
                ok = false;
            }
            wally_free_string(address);
            address = NULL;
        }
        wally_descriptor_free(descriptor);
        descriptor = NULL;
    }
    fail_at = NO_FAILURE;
    if (ok && ops_leaked()) {
        printf("%s: leaked PSA operations\n", name);
        ok = false;
    }
    return ok;
}
#endif /* BUILD_ELEMENTS */

static const struct {
    const char *name;
    int (*fn)(void);
    size_t max_runs;
} cases[] = {
#define CASE(fn) { #fn, fn, 1000 }
#define CASE_SAMPLED(fn, n) { #fn, fn, n }
    CASE(case_sha256),
    CASE(case_sha256d),
    CASE(case_sha512),
    CASE(case_hash160),
    CASE(case_bip340_tagged_hash),
    CASE(case_hmac_sha256),
    CASE(case_hmac_sha512),
    CASE(case_pbkdf2_hmac_sha256),
    CASE(case_pbkdf2_hmac_sha512),
    CASE(case_keys_bip39_from_bytes),
    CASE(case_keys_bip39_to_bytes),
    CASE(case_keys_bip39_validate),
    CASE_SAMPLED(case_keys_bip39_to_seed512, 40),
    CASE_SAMPLED(case_keys_bip39_to_seed, 20),
    CASE(case_keys_bip32_from_seed),
    CASE(case_keys_bip32_from_seed_skip_hash),
    CASE(case_keys_bip32_from_seed_custom),
    CASE(case_keys_bip32_from_parent_hardened),
    CASE(case_keys_bip32_from_parent_normal),
    CASE(case_keys_bip32_from_parent_pub),
    CASE(case_keys_bip32_from_parent_path),
    CASE(case_keys_bip32_from_parent_path_pub),
    CASE(case_keys_bip32_with_tweak_path),
    CASE(case_keys_bip32_base58),
    CASE(case_keys_bip32_unserialize),
    CASE(case_keys_bip32_init),
    CASE(case_keys_bip32_fingerprint),
    CASE(case_keys_bip85_bip39_entropy),
    CASE(case_keys_bip85_rsa_entropy),
    CASE(case_keys_symmetric_key),
    CASE(case_keys_aes_ecdh_encrypt),
    CASE(case_keys_aes_ecdh_decrypt),
    CASE(case_keys_base58_checksum),
    CASE(case_keys_wif_from_bytes),
    CASE(case_keys_wif_to_bytes),
    CASE(case_keys_wif_is_uncompressed),
    CASE(case_keys_wif_to_public_key),
    CASE(case_keys_wif_to_address),
    CASE(case_keys_scrypt),
    CASE_SAMPLED(case_keys_scrypt_parallel, 30),
    CASE(case_keys_bip38_quick_check),
    CASE_SAMPLED(case_keys_bip38_raw_from_private_key, 12),
    CASE_SAMPLED(case_keys_bip38_raw_to_private_key, 12),
    CASE_SAMPLED(case_keys_bip38_from_private_key, 12),
    CASE_SAMPLED(case_keys_bip38_to_private_key, 12),
    CASE(case_tx_txid),
    CASE(case_tx_txid_large),
    CASE(case_tx_hash_prevouts),
    CASE(case_tx_legacy_sighash),
    CASE(case_tx_segwit_sighash),
    CASE(case_tx_taproot_keypath_sighash),
    CASE(case_tx_taproot_scriptpath_sighash),
    CASE(case_tx_taproot_annex_sighash),
#ifdef BUILD_ELEMENTS
    CASE(case_tx_elements_segwit_sighash),
    CASE(case_tx_elements_taproot_sighash),
    CASE(case_tx_elements_legacy_rangeproof_sighash),
#endif
    CASE(case_tx_sighash_wrappers),
    CASE(case_tx_bitcoin_message),
    CASE(case_tx_taptree_hashes),
    CASE(case_psbt_parse_extra_base64),
    CASE(case_psbt_parse_extra_bytes),
    CASE(case_psbt_parse_bip174_xpubs),
    CASE(case_psbt_get_id),
    CASE(case_psbt_combine),
    CASE(case_psbt_clone),
    CASE(case_psbt_signing_script),
    CASE(case_psbt_scriptcode),
    CASE(case_psbt_sighash),
    CASE(case_psbt_sighash_cached),
    CASE(case_psbt_sighash_taproot),
    CASE(case_psbt_sign_finalize),
    CASE(case_psbt_sign_bip32),
    CASE(case_psbt_sign_taproot),
    CASE(case_psbt_from_tx),
    CASE(case_psbt_map_preimages),
    CASE(case_psbt_map_keypath_xpub),
    CASE(case_psbt_desc_pkh_xpub),
    CASE(case_psbt_desc_wpkh_xprv),
    CASE(case_psbt_desc_sh_wpkh),
    CASE(case_psbt_desc_wsh_multi),
    CASE(case_psbt_desc_tr_key),
    CASE(case_psbt_desc_tr_script),
    CASE(case_psbt_desc_addr_base58),
    CASE(case_psbt_desc_addr_bech32),
    CASE(case_psbt_desc_wif),
    CASE(case_psbt_desc_checksum),
    CASE(case_psbt_desc_derive_key),
    CASE(case_psbt_desc_policy),
    CASE(case_psbt_desc_derive_xpub_path),
    CASE(case_psbt_bip32_key_to_address),
    CASE(case_psbt_address_roundtrip),
    CASE(case_psbt_script_hash_flags),
    CASE(case_psbt_bip341_tweak),
#ifdef BUILD_ELEMENTS
    CASE(case_elements_sighash_segwit_v0),
    CASE(case_elements_sighash_legacy_rangeproof),
    CASE(case_elements_sighash_taproot),
    CASE(case_elements_sighash_taproot_cached),
    CASE(case_elements_issuance),
    CASE(case_elements_elip150),
    CASE(case_elements_blinding_key_from_seed),
    CASE(case_elements_blinding_key_to_ec_key),
    CASE(case_elements_blinding_key_to_abf_vbf),
    CASE(case_elements_confidential_addr),
    CASE(case_elements_ecdh_nonce_hash),
    CASE(case_elements_pegin_contract_script),
    CASE_SAMPLED(case_elements_rangeproof, 30),
    CASE_SAMPLED(case_elements_ct_descriptor_slip77, 150),
    CASE_SAMPLED(case_elements_ct_descriptor_elip150, 150),
    CASE_SAMPLED(case_elements_ct_descriptor_ranged, 150),
#endif
};

/* Run last: no case or check may have leaked PSA operations */
static bool check_no_ops_leaked(void)
{
    if (!ops_leaked())
        return true;
    printf("check_no_ops_leaked: leaked PSA operations\n");
    return false;
}

/* Extra checks, which print their own failures */
static bool (*const checks[])(void) = {
    check_keys_bip32_fingerprint_retry,
    check_keys_bip32_failure_wipes_key,
    check_keys_bip39_seed_cleared,
    check_keys_bip38_no_unverified_key,
    check_tx_sighash_cache,
#ifdef BUILD_ELEMENTS
    check_tx_elements_rangeproof_cache,
#endif
    check_tx_annex_tapleaf_cache,
    check_psbt_signing_cache,
    check_psbt_desc_lazy_fingerprint,
#ifdef BUILD_ELEMENTS
    check_elements_sighash_cache,
    check_elements_sighash_cache_rangeproof,
    check_elements_ct_descriptor_not_poisoned,
#endif
    check_no_ops_leaked,
};

int main(void)
{
    const size_t num_cases = sizeof(cases) / sizeof(cases[0]);
    const size_t num_checks = sizeof(checks) / sizeof(checks[0]);
    size_t i, failed_cases = 0, failed_checks = 0;

    if (wally_init(0) != WALLY_OK) {
        printf("wally_init failed\n");
        return 1;
    }
    for (i = 0; i < num_cases; ++i)
        if (!check_case(cases[i].name, cases[i].fn, cases[i].max_runs))
            ++failed_cases;
    for (i = 0; i < num_checks; ++i)
        if (!checks[i]())
            ++failed_checks;
    wally_cleanup(0);
    if (failed_cases || failed_checks)
        printf("test_psa_faults: %zu of %zu cases and %zu of %zu checks failed\n",
               failed_cases, num_cases, failed_checks, num_checks);
    return failed_cases || failed_checks ? 1 : 0;
}
