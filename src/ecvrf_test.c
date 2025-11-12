// ecvrf_test.c  ← 从原 main() 复制过来
#include "../include/ecvrf_test.h"
#include "ecvrf_p256.c"  // 你如果没拆成 .h/.c，就直接 include .c 也行

int ecvrf_test_demo() {
     printf("=== ECVRF RFC 9381 (P-256 / SHA256 / SSWU / RO) demo ===\n");

    /* create suite */
    ecvrf_suite *vrf = ecvrf_p256_rfc9381();
    if (!vrf) {
        fprintf(stderr, "VRF suite init failed\n");
        return 1;
    }
    /* key pair */
    // static const uint8_t public_key[65] =
    //     "\x04\xdb\x72\x4c\xdd\x2d\x65\xd9\x0d\xe9\x82\xd2\xc6\x94\x3d"
    //     "\x66\x18\x85\x28\xc2\x84\x6b\x1f\xeb\x95\x8d\x25\xf5\xf1\xbb"
    //     "\x2b\xc6\xbe\x16\xab\xce\xbe\x01\xd6\x31\xd3\x4e\x69\xfe\xeb"
    //     "\x87\x49\x1e\x5d\xfd\x1a\x04\xf2\x71\x89\x78\x30\x26\xad\x50"
    //     "\xcd\xcb\xec\x78\x7c";

    // static const uint8_t private_key[33] =
    //     "\x00\xe3\xd3\x78\x92\x71\xe6\x30\x67\x3c\x10\x98\xe7\x67\x00"
    //     "\xc4\x13\xb0\xee\x9a\xd5\x2b\x6a\xe1\x71\x5c\x1e\x8d\x2e\xea"
    //     "\x9b\x2d\xe9";

    // /* load keypair */
    // EC_POINT *pub = EC_POINT_new(vrf->group);
    // if (EC_POINT_oct2point(vrf->group, pub, public_key, sizeof(public_key), NULL) != 1) {
    //     fprintf(stderr, "failed to load public key\n");
    //     return 1;
    // }
    // BIGNUM *priv = BN_bin2bn(private_key, sizeof(private_key), NULL);

    /* === Dynamically generate EC P-256 key pairs === */
    EC_KEY *ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!ec_key) { fprintf(stderr, "EC_KEY_new failed\n"); return 1; }
    if (EC_KEY_generate_key(ec_key) != 1) {
        fprintf(stderr, "EC_KEY_generate_key failed\n");
        EC_KEY_free(ec_key);
        return 1;
    }

    const BIGNUM *priv_bn = EC_KEY_get0_private_key(ec_key);
    const EC_POINT *pub_point = EC_KEY_get0_public_key(ec_key);
    BIGNUM *priv = BN_dup(priv_bn);
    EC_POINT *pub = EC_POINT_dup(pub_point, EC_KEY_get0_group(ec_key));
    printf("Generated dynamic EC P-256 key pair.\n");
    printf("Private key (hex): ");
    BN_print_fp(stdout, priv);
    printf("\n");

    unsigned char pub_bytes[65];
    size_t pub_len = EC_POINT_point2oct(EC_KEY_get0_group(ec_key), pub,
                                        POINT_CONVERSION_UNCOMPRESSED,
                                        pub_bytes, sizeof(pub_bytes), NULL);
    printf("Public key (%zu bytes):\n", pub_len);
    hex_dump(pub_bytes, pub_len);
    EC_KEY_free(ec_key);


    // static const uint8_t message[] = "hello world";
    // size_t msglen = sizeof(message) - 1;

    /* === hash random message vector input === */
    /* === random message vector === */
    size_t msglen = 2; 
    unsigned char *message = malloc(msglen);
    if (!message) { fprintf(stderr, "malloc failed\n"); return 1; }
    if (RAND_bytes(message, msglen) != 1) {
        fprintf(stderr, "RAND_bytes failed\n");
        free(message);
        return 1;
    }
    printf("Generated random message vector (%zu bytes):\n", msglen);
    hex_dump(message, msglen);

    /* === SHA256 (RFC 9381 defines the input field as any non-empty byte string. To ensure consistency, we compress the message vector to a fixed 32 bytes using SHA256.)=== */
    unsigned char msg_hash[SHA256_DIGEST_LENGTH];
    SHA256(message, msglen, msg_hash);
    printf("Hashed message vector (SHA256, 32B):\n");
    hex_dump(msg_hash, sizeof(msg_hash));
    /* === VRF input === */
    const unsigned char *vrf_input = msg_hash;
    size_t vrf_input_len = sizeof(msg_hash);


    /* generate proof */
    unsigned char proof[97];
    memset(proof, 0, sizeof(proof));
    if (!ECVRF_prove_rfc9381(vrf, pub, priv, vrf_input, vrf_input_len, proof, sizeof(proof))) {
        fprintf(stderr, "ECVRF_prove_rfc9381 failed\n");
        free(message);
        return 1;
    }

    /* print proof */
    printf("VRF proof (97 bytes):\n");
    hex_dump(proof, sizeof(proof));

    /* verify proof */
    bool ok = ECVRF_verify_rfc9381(vrf, pub, vrf_input, vrf_input_len, proof, sizeof(proof));
    printf("verify result = %s\n", ok ? "true" : "false");

    /* compute β₂(VRF output) */
    unsigned char beta2[32];
    ECVRF_proof_to_hash_rfc9381(vrf, proof, sizeof(proof), beta2);
    printf("beta2 (VRF output, 32B):\n");
    hex_dump(beta2, sizeof(beta2));

    /* === random beta1, in the same domain as the VRF output beta === */
    unsigned char beta1[32];
    if (RAND_bytes(beta1, sizeof(beta1)) != 1) {
        fprintf(stderr, "RAND_bytes for beta1 failed\n");
        free(message);
        return 1;
    }
    printf("Random beta1 (same domain as beta, 32B):\n");
    hex_dump(beta1, sizeof(beta1));

    /* === H3(β1||β2) → (e, s) ∈ Z_q^2 === */
    BIGNUM *e = NULL, *s = NULL;
    H3_beta_concat_to_scalars(vrf->group, beta1, beta2, &e, &s);
    printf("Computed e = ");
    BN_print_fp(stdout, e);
    printf("\n");
    printf("Computed s = ");
    BN_print_fp(stdout, s);
    printf("\n");


    /* cleanup */
    free(message);
    BN_clear_free(e);
    BN_clear_free(s);
    EC_POINT_clear_free(pub);
    BN_clear_free(priv);
    EC_GROUP_free(vrf->group);
    free(vrf);
    
    printf("=== donessssssssssssssss ===\n");
    return 0;
}