#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/obj_mac.h>
#include <openssl/sha.h>
#include <arpa/inet.h>

/* ==========================================================
   RFC 9381 constants and domain separation
   ========================================================== */
#define ECVRF_DST "ECVRF_P256_SHA256_SSWU_RO"

/* ==========================================================
   VRF suite structure (same as original, with updated lengths)
   ========================================================== */
typedef struct ecvrf_suite {
    EC_GROUP *group;
    const EVP_MD *hash;
    size_t proof_size;
    size_t ecp_size;
    size_t c_size;
    size_t s_size;
} ecvrf_suite;

/* ==========================================================
   Initialize ECVRF-P256-SHA256 suite (RFC 9381 version)
   ========================================================== */
static ecvrf_suite *ecvrf_p256_rfc9381(void)
{
    ecvrf_suite tmp = {
        .group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1),
        .hash = EVP_sha256(),
        .proof_size = 97,   // RFC 9381: γ(33) + c(32) + s(32)
        .ecp_size = 33,     // compressed point
        .c_size = 32,       // full SHA-256 output
        .s_size = 32
    };

    if (!tmp.group) return NULL;
    ecvrf_suite *vrf = (ecvrf_suite *)malloc(sizeof(*vrf));
    if (!vrf) return NULL;
    memcpy(vrf, &tmp, sizeof(*vrf));
    return vrf;
}

/* ==========================================================
   Utility helpers
   ========================================================== */

/* Convert BIGNUM to fixed-width big-endian bytes */
static void bn2bin_fixed(const BIGNUM *num, uint8_t *buf, size_t size)
{
    size_t need = BN_num_bytes(num);
    assert(need <= size);
    memset(buf, 0, size - need);
    BN_bn2bin(num, buf + (size - need));
}

/* Simple hex dump */
static void hex_dump(const uint8_t *data, size_t len)
{
    for (size_t i = 0; i < len; i++)
        printf("%02x%s", data[i], (i + 1 == len) ? "\n" : ":");
}

/* Secure modular subtraction with BN_CTX */
static int bn_mod_sub_safe(BIGNUM *r, const BIGNUM *a,
                           const BIGNUM *b, const BIGNUM *m)
{
    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) return 0;
    int ret = BN_mod_sub(r, a, b, m, ctx);
    BN_CTX_free(ctx);
    return ret;
}

/* ==========================================================
   Deterministic nonce generation (RFC 6979 simplified)
   ========================================================== */
static int generate_k_rfc6979(const EC_GROUP *group,
                              const BIGNUM *x,
                              const unsigned char *msg, size_t msglen,
                              BIGNUM *k_out)
{
    unsigned char bx[32];
    unsigned char h1[SHA256_DIGEST_LENGTH];
    unsigned char V[32], K[32];
    unsigned char t[32];
    BIGNUM *order = BN_new();
    EC_GROUP_get_order(group, order, NULL);

    bn2bin_fixed(x, bx, 32);
    SHA256(msg, msglen, h1);

    memset(V, 0x01, 32);
    memset(K, 0x00, 32);

    unsigned char bxh1[64];
    memcpy(bxh1, bx, 32);
    memcpy(bxh1 + 32, h1, 32);

    /* Step: K = HMAC(K, V || 0x00 || bx || h1) */
    HMAC(EVP_sha256(), K, 32, V, 32, K, NULL);
    unsigned char tmp[1 + 64];
    tmp[0] = 0x00;
    memcpy(tmp + 1, bxh1, 64);
    HMAC(EVP_sha256(), K, 32, tmp, sizeof(tmp), K, NULL);

    /* V = HMAC(K, V) */
    HMAC(EVP_sha256(), K, 32, V, 32, V, NULL);

    /* K = HMAC(K, V || 0x01 || bx || h1) */
    tmp[0] = 0x01;
    HMAC(EVP_sha256(), K, 32, tmp, sizeof(tmp), K, NULL);
    HMAC(EVP_sha256(), K, 32, V, 32, V, NULL);

    /* Loop until a valid k is found */
    for (;;) {
        HMAC(EVP_sha256(), K, 32, V, 32, V, NULL);
        memcpy(t, V, 32);
        BIGNUM *k = BN_bin2bn(t, 32, NULL);
        if (BN_is_zero(k) || BN_cmp(k, order) >= 0) {
            unsigned char zero = 0x00;
            HMAC(EVP_sha256(), K, 32, V, 32, V, NULL);
            HMAC(EVP_sha256(), K, 32, &zero, 1, K, NULL);
            BN_clear_free(k);
            continue;
        }
        BN_copy(k_out, k);
        BN_clear_free(k);
        break;
    }
    BN_clear_free(order);
    return 1;
}

/* ==========================================================
   RFC 9381: Proof encoding layout helper
   ========================================================== */
static void encode_proof_rfc9381(uint8_t *out, size_t outlen,
                                 const EC_GROUP *group,
                                 const EC_POINT *gamma,
                                 const BIGNUM *c, const BIGNUM *s)
{
    assert(outlen == 97);
    uint8_t buf_gamma[33];
    EC_POINT_point2oct(group, gamma, POINT_CONVERSION_COMPRESSED,
                       buf_gamma, sizeof(buf_gamma), NULL);
    memcpy(out, buf_gamma, 33);
    bn2bin_fixed(c, out + 33, 32);
    bn2bin_fixed(s, out + 65, 32);
}

/* ==========================================================
   Placeholder: Simplified SWU Hash-to-Curve (mock version)
   ========================================================== */
/*
 * RFC 9381 specifies the Simplified SWU method (from RFC 9380).
 * For simplicity and demo purposes, this placeholder reuses
 * the existing try-and-increment approach to derive a valid
 * curve point, but wraps it in a function named
 * ECVRF_hash_to_curve_simplified_swu() to show separation.
 */
static EC_POINT *ECVRF_hash_to_curve_simplified_swu(
        const ecvrf_suite *vrf,
        const EC_POINT *pubkey,
        const unsigned char *msg, size_t msglen)
{
    /* For demo we just reuse old hash-to-curve1 code path,
       in real production use a true SSWU mapping per RFC 9380. */
    EC_POINT *pt = EC_POINT_new(vrf->group);
    EC_POINT_mul(vrf->group, pt, NULL,
                 EC_GROUP_get0_generator(vrf->group), BN_value_one(), NULL);
    /* this returns a fixed generator copy, just placeholder */
    (void)pubkey; (void)msg; (void)msglen;
    return pt;
}

/* ==========================================================
   ECVRF_prove_rfc9381
   ==========================================================
   Input:
      vrf      - suite (contains EC_GROUP, hash, etc.)
      pubkey   - EC public key
      privkey  - BIGNUM private scalar
      msg      - input message
      msglen   - message length
   Output:
      proof[97] = γ(33) || c(32) || s(32)
   ========================================================== */

static bool ECVRF_prove_rfc9381(const ecvrf_suite *vrf,
                                const EC_POINT *pubkey,
                                const BIGNUM *privkey,
                                const unsigned char *msg, size_t msglen,
                                unsigned char *proof, size_t proof_size)
{
    if (!vrf || proof_size != 97) return false;

    bool ok = false;
    const EC_GROUP *group = vrf->group;
    const EC_POINT *G = EC_GROUP_get0_generator(group);
    const BIGNUM *order = EC_GROUP_get0_order(group);

    EC_POINT *H = NULL;
    EC_POINT *Gamma = NULL;
    EC_POINT *U = NULL;
    EC_POINT *V = NULL;
    BIGNUM *k = NULL;
    BIGNUM *c = NULL;
    BIGNUM *s = NULL;
    BIGNUM *ck = NULL;

    /* === Step 1. Hash to curve (Simplified SWU placeholder) === */
    H = ECVRF_hash_to_curve_simplified_swu(vrf, pubkey, msg, msglen);
    if (!H) return false;

    /* === Step 2. Gamma = x * H === */
    Gamma = EC_POINT_new(group);
    if (EC_POINT_mul(group, Gamma, NULL, H, privkey, NULL) != 1)
        return false;

    /* === Step 3. Generate deterministic nonce k (RFC 6979) === */
    k = BN_new();
    if (!generate_k_rfc6979(group, privkey, msg, msglen, k))
        return false;

    /* === Step 4. Compute commitment points U = k*G, V = k*H === */
    U = EC_POINT_new(group);
    V = EC_POINT_new(group);
    if (EC_POINT_mul(group, U, NULL, G, k, NULL) != 1) return false;
    if (EC_POINT_mul(group, V, NULL, H, k, NULL) != 1) return false;

    /* === Step 5. Compute challenge c = Hash(DST, G, H, Y, Gamma, U, V) === */
    EVP_MD_CTX *md = EVP_MD_CTX_new();
    unsigned char digest[SHA256_DIGEST_LENGTH];
    unsigned int dlen = 0;

    EVP_DigestInit_ex(md, vrf->hash, NULL);
    EVP_DigestUpdate(md, ECVRF_DST, strlen(ECVRF_DST));

    unsigned char buf[33];
    const EC_POINT *pts[] = { G, H, pubkey, Gamma, U, V };
    for (size_t i = 0; i < 6; i++) {
        EC_POINT_point2oct(group, pts[i], POINT_CONVERSION_COMPRESSED,
                           buf, sizeof(buf), NULL);
        EVP_DigestUpdate(md, buf, sizeof(buf));
    }
    EVP_DigestFinal_ex(md, digest, &dlen);
    EVP_MD_CTX_free(md);

    c = BN_bin2bn(digest, 32, NULL);  /* RFC9381: full 32B */
    if (!c) return false;

    /* === Step 6. Compute s = (k - c*x) mod q === */
    s = BN_new();
    ck = BN_new();
    if (!bn_mod_sub_safe(s, BN_value_one(), BN_value_one(), order)) {;} /* noop to force ctx creation */
    BIGNUM *cx = BN_new();
    BN_CTX *ctx = BN_CTX_new();
    BN_mod_mul(cx, c, privkey, order, ctx);
    BN_mod_sub(s, k, cx, order, ctx);
    BN_CTX_free(ctx);
    BN_clear_free(cx);

    /* === Step 7. Encode proof (γ || c || s) === */
    encode_proof_rfc9381(proof, proof_size, group, Gamma, c, s);
    ok = true;

cleanup:
    EC_POINT_clear_free(H);
    EC_POINT_clear_free(Gamma);
    EC_POINT_clear_free(U);
    EC_POINT_clear_free(V);
    BN_clear_free(k);
    BN_clear_free(c);
    BN_clear_free(s);
    BN_clear_free(ck);
    return ok;
}

/* ==========================================================
   ECVRF_verify_rfc9381
   ==========================================================
   Input:
      vrf    - suite
      pubkey - EC public key
      msg    - message
      msglen - length
      proof  - 97-byte proof (γ||c||s)
   Output:
      return true if valid, false otherwise.
   ========================================================== */
static bool ECVRF_verify_rfc9381(const ecvrf_suite *vrf,
                                 const EC_POINT *pubkey,
                                 const unsigned char *msg, size_t msglen,
                                 const unsigned char *proof, size_t proof_size)
{
    if (!vrf || proof_size != 97) return false;

    const EC_GROUP *group = vrf->group;
    const BIGNUM *order = EC_GROUP_get0_order(group);
    const EC_POINT *G = EC_GROUP_get0_generator(group);
    bool valid = false;

    EC_POINT *Gamma = NULL, *H = NULL, *U = NULL, *V = NULL;
    BIGNUM *c = NULL, *s = NULL;
    BIGNUM *c2 = NULL;

    /* === Step 1. Decode proof === */
    const unsigned char *gamma_raw = proof;
    const unsigned char *c_raw = proof + 33;
    const unsigned char *s_raw = proof + 65;

    Gamma = EC_POINT_new(group);
    if (EC_POINT_oct2point(group, Gamma, gamma_raw, 33, NULL) != 1) return false;
    c = BN_bin2bn(c_raw, 32, NULL);
    s = BN_bin2bn(s_raw, 32, NULL);
    if (!c || !s) return false;

    /* === Step 2. Hash to curve (H = hash_to_curve(pubkey, msg)) === */
    H = ECVRF_hash_to_curve_simplified_swu(vrf, pubkey, msg, msglen);
    if (!H) return false;

    /* === Step 3. Recompute U = s*G + c*Y ; V = s*H + c*Gamma === */
    U = EC_POINT_new(group);
    V = EC_POINT_new(group);
    EC_POINT *cY = EC_POINT_new(group);
    EC_POINT *cGamma = EC_POINT_new(group);

    BN_CTX *ctx = BN_CTX_new();
    EC_POINT_mul(group, U, NULL, G, s, NULL);
    EC_POINT_mul(group, cY, NULL, pubkey, c, NULL);
    EC_POINT_add(group, U, U, cY, ctx);

    EC_POINT_mul(group, V, NULL, H, s, NULL);
    EC_POINT_mul(group, cGamma, NULL, Gamma, c, NULL);
    EC_POINT_add(group, V, V, cGamma, ctx);
    BN_CTX_free(ctx);
    EC_POINT_clear_free(cY);
    EC_POINT_clear_free(cGamma);

    /* === Step 4. Recompute challenge c2 = Hash(DST, G,H,Y,Gamma,U,V) === */
    EVP_MD_CTX *md = EVP_MD_CTX_new();
    unsigned char digest[SHA256_DIGEST_LENGTH];
    unsigned int dlen = 0;
    EVP_DigestInit_ex(md, vrf->hash, NULL);
    EVP_DigestUpdate(md, ECVRF_DST, strlen(ECVRF_DST));
    unsigned char buf[33];
    const EC_POINT *pts[] = {G, H, pubkey, Gamma, U, V};
    for (size_t i = 0; i < 6; i++) {
        EC_POINT_point2oct(group, pts[i], POINT_CONVERSION_COMPRESSED,
                           buf, sizeof(buf), NULL);
        EVP_DigestUpdate(md, buf, sizeof(buf));
    }
    EVP_DigestFinal_ex(md, digest, &dlen);
    EVP_MD_CTX_free(md);
    c2 = BN_bin2bn(digest, 32, NULL);

    /* === Step 5. Verify c == c2 === */
    if (BN_cmp(c, c2) == 0)
        valid = true;

cleanup:
    EC_POINT_clear_free(Gamma);
    EC_POINT_clear_free(H);
    EC_POINT_clear_free(U);
    EC_POINT_clear_free(V);
    BN_clear_free(c);
    BN_clear_free(s);
    BN_clear_free(c2);
    return valid;
}

/* ==========================================================
   ECVRF_proof_to_hash_rfc9381
   ==========================================================
   Compute β = SHA256(0x03 || encode(γ) || DST)
   ========================================================== */
static void ECVRF_proof_to_hash_rfc9381(const ecvrf_suite *vrf,
                                        const unsigned char *proof,
                                        size_t proof_size,
                                        unsigned char *beta)
{
    assert(proof_size == 97);
    const unsigned char *gamma_raw = proof;
    unsigned char input[1 + 33 + sizeof(ECVRF_DST)];
    input[0] = 0x03;  // RFC 9381 fixed prefix
    memcpy(input + 1, gamma_raw, 33);
    memcpy(input + 34, ECVRF_DST, strlen(ECVRF_DST));
    SHA256(input, 1 + 33 + strlen(ECVRF_DST), beta);
}

/* ==========================================================
   H3: map β1||β2 -> (e, s) in Z_q^2
   ========================================================== */
static void H3_beta_concat_to_scalars(const EC_GROUP *group,
                                      const unsigned char *beta1,
                                      const unsigned char *beta2,
                                      BIGNUM **e_out, BIGNUM **s_out)
{
    assert(beta1 && beta2 && e_out && s_out);

    unsigned char input[64];
    memcpy(input, beta1, 32);
    memcpy(input + 32, beta2, 32);

    /* SHA256(β1 || β2) */
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256(input, sizeof(input), digest);

    /* split digest into two halves, hash again to extend */
    unsigned char digest2[SHA256_DIGEST_LENGTH];
    SHA256(digest, sizeof(digest), digest2);

    /* combine both digests -> 64 bytes total */
    unsigned char combined[64];
    memcpy(combined, digest, 32);
    memcpy(combined + 32, digest2, 32);

    /* derive e,s from first and second 32 bytes */
    BIGNUM *e = BN_bin2bn(combined, 32, NULL);
    BIGNUM *s = BN_bin2bn(combined + 32, 32, NULL);

    /* mod q reduction */
    const BIGNUM *order = EC_GROUP_get0_order(group);
    BN_CTX *ctx = BN_CTX_new();
    BN_mod(e, e, order, ctx);
    BN_mod(s, s, order, ctx);
    BN_CTX_free(ctx);

    *e_out = e;
    *s_out = s;
}