#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <gmssl/sm3.h>
#include <pchs_liu2018.h>

#define CHECK(x) do { \
    if (!(x)) { \
        fprintf(stderr, "CHECK failed %s:%d: %s\n", __FILE__, __LINE__, #x); \
        goto cleanup; \
    } \
} while (0)

static const uint8_t H2_DOMAIN[] = "LIU2018-PCHS-H2";

static void fill_message(uint8_t *buf, size_t len)
{
    size_t i;
    for (i = 0; i < len; i++) {
        buf[i] = (uint8_t)(i * 17u + len);
    }
}

static int test_hash_h2(
    const uint8_t *message,
    size_t message_len,
    const SM2_Z256_POINT *r1,
    sm2_z256_t out)
{
    uint8_t point_octets[65];
    uint8_t digest[SM3_DIGEST_SIZE];
    uint8_t ctr[4];
    uint32_t counter;

    if (sm2_z256_point_to_uncompressed_octets(r1, point_octets) != 1) {
        return 0;
    }
    for (counter = 0; counter != UINT32_MAX; counter++) {
        SM3_CTX ctx;
        ctr[0] = (uint8_t)(counter >> 24);
        ctr[1] = (uint8_t)(counter >> 16);
        ctr[2] = (uint8_t)(counter >> 8);
        ctr[3] = (uint8_t)counter;
        sm3_init(&ctx);
        sm3_update(&ctx, H2_DOMAIN, sizeof(H2_DOMAIN) - 1);
        if (message_len) {
            sm3_update(&ctx, message, message_len);
        }
        sm3_update(&ctx, point_octets, sizeof(point_octets));
        sm3_update(&ctx, ctr, sizeof(ctr));
        sm3_finish(&ctx, digest);
        sm2_z256_from_bytes(out, digest);
        if (!sm2_z256_is_zero(out)
            && sm2_z256_cmp(out, sm2_z256_order()) < 0) {
            return 1;
        }
    }
    return 0;
}

static int check_algebra(
    const PCHS_PUBLIC_PARAMS *pp,
    const PCHS_PKI_KEY *sender,
    const PCHS_CLC_KEY *receiver,
    const PCHS_CIPHERTEXT *ct,
    const uint8_t *message,
    size_t message_len)
{
    SM2_Z256_POINT dP;
    SM2_Z256_POINT gammaPpub;
    SM2_Z256_POINT partial_rhs;
    SM2_Z256_POINT v_minus_dP;
    SM2_Z256_POINT r1;
    SM2_Z256_POINT hP;
    SM2_Z256_POINT uPKp;
    SM2_Z256_POINT verification_rhs;
    SM2_Z256_POINT r2_recovered;
    sm2_z256_t x_c_inv;
    sm2_z256_t h;

    sm2_z256_point_mul_generator(&dP, receiver->d);
    sm2_z256_point_mul(&gammaPpub, receiver->gamma, &pp->P_pub);
    sm2_z256_point_add(&partial_rhs, &receiver->T, &gammaPpub);
    if (sm2_z256_point_equ(&dP, &partial_rhs) != 1) {
        return 0;
    }

    sm2_z256_point_sub(&v_minus_dP, &ct->V, &dP);
    sm2_z256_modn_inv(x_c_inv, receiver->x_c);
    sm2_z256_point_mul(&r1, x_c_inv, &v_minus_dP);
    if (!test_hash_h2(message, message_len, &r1, h)) {
        return 0;
    }
    sm2_z256_point_mul_generator(&hP, h);
    sm2_z256_point_mul(&uPKp, ct->u, &sender->PK_p);
    sm2_z256_point_sub(&verification_rhs, &hP, &uPKp);
    if (sm2_z256_point_equ(&r1, &verification_rhs) != 1) {
        return 0;
    }

    sm2_z256_point_add(&r2_recovered, &r1, &uPKp);
    if (sm2_z256_point_equ(&r2_recovered, &hP) != 1) {
        return 0;
    }
    return 1;
}

static int roundtrip(size_t n)
{
    PCHS_MASTER_KEY msk;
    PCHS_PUBLIC_PARAMS pp;
    PCHS_PKI_KEY sender;
    PCHS_CLC_KEY receiver;
    PCHS_CIPHERTEXT ct;
    static const uint8_t id[] = "Bob";
    uint8_t *m = calloc(n ? n : 1, 1);
    uint8_t *out = calloc(n ? n : 1, 1);
    size_t outlen = n;
    int ok = 0;

    memset(&msk, 0, sizeof(msk));
    memset(&pp, 0, sizeof(pp));
    memset(&sender, 0, sizeof(sender));
    memset(&receiver, 0, sizeof(receiver));
    pchs_ciphertext_init(&ct);

    CHECK(m != NULL && out != NULL);
    fill_message(m, n);
    CHECK(pchs_setup(&msk, &pp) == PCHS_OK);
    CHECK(pchs_pki_keygen(&sender) == PCHS_OK);
    CHECK(pchs_clc_keygen(&msk, &pp, id, sizeof(id) - 1, &receiver) == PCHS_OK);
    CHECK(pchs_signcrypt(&pp, &sender, &receiver, m, n, &ct) == PCHS_OK);
    CHECK(check_algebra(&pp, &sender, &receiver, &ct, m, n));
    CHECK(pchs_unsigncrypt(&pp, &sender, &receiver, &ct, out, &outlen) == PCHS_OK);
    CHECK(outlen == n);
    CHECK(n == 0 || memcmp(m, out, n) == 0);
    ok = 1;

cleanup:
    pchs_ciphertext_cleanup(&ct);
    pchs_clc_key_cleanup(&receiver);
    pchs_pki_key_cleanup(&sender);
    pchs_master_key_cleanup(&msk);
    free(out);
    free(m);
    return ok;
}

static int decrypt_rejects(
    const PCHS_PUBLIC_PARAMS *pp,
    const PCHS_PKI_KEY *sender,
    const PCHS_CLC_KEY *receiver,
    const PCHS_CIPHERTEXT *ct,
    uint8_t *out,
    size_t out_capacity)
{
    size_t outlen = out_capacity;
    memset(out, 0, out_capacity);
    return pchs_unsigncrypt(pp, sender, receiver, ct, out, &outlen) == PCHS_ERR;
}

static int tamper_rejection(void)
{
    enum { N = 128 };
    PCHS_MASTER_KEY msk;
    PCHS_PUBLIC_PARAMS pp;
    PCHS_PKI_KEY sender;
    PCHS_PKI_KEY wrong_sender;
    PCHS_CLC_KEY receiver;
    PCHS_CLC_KEY wrong_receiver;
    PCHS_CIPHERTEXT ct;
    static const uint8_t id[] = "Bob";
    uint8_t message[N];
    uint8_t out[N];
    uint8_t saved_c0;
    sm2_z256_t saved_u;
    sm2_z256_t one;
    SM2_Z256_POINT saved_V;
    SM2_Z256_POINT G;
    int ok = 0;

    memset(&msk, 0, sizeof(msk));
    memset(&pp, 0, sizeof(pp));
    memset(&sender, 0, sizeof(sender));
    memset(&wrong_sender, 0, sizeof(wrong_sender));
    memset(&receiver, 0, sizeof(receiver));
    memset(&wrong_receiver, 0, sizeof(wrong_receiver));
    pchs_ciphertext_init(&ct);
    fill_message(message, sizeof(message));

    CHECK(pchs_setup(&msk, &pp) == PCHS_OK);
    CHECK(pchs_pki_keygen(&sender) == PCHS_OK);
    CHECK(pchs_pki_keygen(&wrong_sender) == PCHS_OK);
    CHECK(pchs_clc_keygen(&msk, &pp, id, sizeof(id) - 1, &receiver) == PCHS_OK);
    CHECK(pchs_signcrypt(&pp, &sender, &receiver,
        message, sizeof(message), &ct) == PCHS_OK);

    saved_c0 = ct.c[0];
    ct.c[0] ^= 0x01;
    CHECK(decrypt_rejects(&pp, &sender, &receiver, &ct, out, sizeof(out)));
    ct.c[0] = saved_c0;

    sm2_z256_set_one(one);
    sm2_z256_copy(saved_u, ct.u);
    sm2_z256_modn_add(ct.u, ct.u, one);
    CHECK(decrypt_rejects(&pp, &sender, &receiver, &ct, out, sizeof(out)));
    sm2_z256_copy(ct.u, saved_u);

    memcpy(&saved_V, &ct.V, sizeof(saved_V));
    sm2_z256_point_mul_generator(&G, one);
    sm2_z256_point_add(&ct.V, &ct.V, &G);
    CHECK(decrypt_rejects(&pp, &sender, &receiver, &ct, out, sizeof(out)));
    memcpy(&ct.V, &saved_V, sizeof(ct.V));

    CHECK(decrypt_rejects(&pp, &wrong_sender, &receiver, &ct, out, sizeof(out)));

    memcpy(&wrong_receiver, &receiver, sizeof(receiver));
    sm2_z256_modn_add(wrong_receiver.x_c, wrong_receiver.x_c, one);
    if (sm2_z256_is_zero(wrong_receiver.x_c)) {
        sm2_z256_modn_add(wrong_receiver.x_c, wrong_receiver.x_c, one);
    }
    CHECK(decrypt_rejects(&pp, &sender, &wrong_receiver, &ct, out, sizeof(out)));

    memcpy(&wrong_receiver, &receiver, sizeof(receiver));
    sm2_z256_modn_add(wrong_receiver.d, wrong_receiver.d, one);
    if (sm2_z256_is_zero(wrong_receiver.d)) {
        sm2_z256_modn_add(wrong_receiver.d, wrong_receiver.d, one);
    }
    CHECK(decrypt_rejects(&pp, &sender, &wrong_receiver, &ct, out, sizeof(out)));

    ok = 1;

cleanup:
    pchs_ciphertext_cleanup(&ct);
    pchs_clc_key_cleanup(&receiver);
    pchs_pki_key_cleanup(&wrong_sender);
    pchs_pki_key_cleanup(&sender);
    pchs_master_key_cleanup(&msk);
    return ok;
}

int main(void)
{
    const size_t sizes[] = {0, 1, 20, 128, 1024, 4096};
    size_t i;

    for (i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
        if (!roundtrip(sizes[i])) {
            return 1;
        }
    }
    if (!tamper_rejection()) {
        return 1;
    }
    puts("test_pchs_liu2018: ok");
    return 0;
}
