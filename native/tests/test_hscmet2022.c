#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <gmssl/sm3.h>
#include <hscmet2022.h>

#define CHECK(x) do { \
    if (!(x)) { \
        fprintf(stderr, "CHECK failed %s:%d: %s\n", __FILE__, __LINE__, #x); \
        goto cleanup; \
    } \
} while (0)

static const uint8_t H1_DOMAIN[] = "HSCMET2022-H1";

static void fill_message(uint8_t *buf, size_t len)
{
    size_t i;
    for (i = 0; i < len; i++) {
        buf[i] = (uint8_t)((i * 37u + len * 11u + 5u) & 0xffu);
    }
}

static void u64be(uint64_t v, uint8_t out[8])
{
    int i;
    for (i = 7; i >= 0; i--) {
        out[i] = (uint8_t)v;
        v >>= 8;
    }
}

static int scalar_valid_nonzero(const sm2_z256_t v)
{
    return !sm2_z256_is_zero(v) && sm2_z256_cmp(v, sm2_z256_order()) < 0;
}

static int test_h1_id(const uint8_t *id, size_t id_len, sm2_z256_t out)
{
    uint32_t counter;
    uint8_t lenbuf[8];
    uint8_t ctr[4];
    uint8_t digest[SM3_DIGEST_SIZE];

    if (id_len && !id) {
        return 0;
    }
    u64be((uint64_t)id_len, lenbuf);
    for (counter = 0; counter != UINT32_MAX; counter++) {
        SM3_CTX ctx;
        ctr[0] = (uint8_t)(counter >> 24);
        ctr[1] = (uint8_t)(counter >> 16);
        ctr[2] = (uint8_t)(counter >> 8);
        ctr[3] = (uint8_t)counter;
        sm3_init(&ctx);
        sm3_update(&ctx, H1_DOMAIN, sizeof(H1_DOMAIN) - 1);
        sm3_update(&ctx, lenbuf, sizeof(lenbuf));
        if (id_len) {
            sm3_update(&ctx, id, id_len);
        }
        sm3_update(&ctx, ctr, sizeof(ctr));
        sm3_finish(&ctx, digest);
        sm2_z256_from_bytes(out, digest);
        if (scalar_valid_nonzero(out)) {
            return 1;
        }
    }
    return 0;
}

static int check_key_algebra(
    const HSCMET2022_PUBLIC_PARAMS *pp,
    const HSCMET2022_PKI_KEY *sender,
    const HSCMET2022_CLC_KEY *receiver,
    const uint8_t *id_c,
    size_t id_c_len)
{
    SM2_Z256_POINT expected_pkp;
    SM2_Z256_POINT skc1P;
    SM2_Z256_POINT hPK;
    SM2_Z256_POINT rhs;
    SM2_Z256_POINT y_sender;
    SM2_Z256_POINT y_receiver;
    sm2_z256_t h_id;

    sm2_z256_point_mul_generator(&expected_pkp, sender->sk_p);
    if (sm2_z256_point_equ(&expected_pkp, &sender->PK_p) != 1) {
        return 0;
    }
    if (!test_h1_id(id_c, id_c_len, h_id)) {
        return 0;
    }
    sm2_z256_point_mul_generator(&skc1P, receiver->sk_c1);
    sm2_z256_point_mul(&hPK, h_id, &pp->PK);
    sm2_z256_point_add(&rhs, &receiver->PK_c1, &hPK);
    if (sm2_z256_point_equ(&skc1P, &rhs) != 1) {
        return 0;
    }
    sm2_z256_point_mul(&y_sender, sender->sk_p, &rhs);
    sm2_z256_point_mul(&y_receiver, receiver->sk_c1, &sender->PK_p);
    if (sm2_z256_point_equ(&y_sender, &y_receiver) != 1) {
        return 0;
    }
    return 1;
}

static int roundtrip(size_t n)
{
    static const uint8_t id_c[] = "Bob";
    HSCMET2022_MASTER_KEY msk;
    HSCMET2022_PUBLIC_PARAMS pp;
    HSCMET2022_PKI_KEY sender;
    HSCMET2022_CLC_KEY receiver;
    HSCMET2022_CIPHERTEXT ct;
    uint8_t *message = calloc(n ? n : 1, 1);
    uint8_t *out = calloc(n ? n : 1, 1);
    size_t outlen = n;
    int ok = 0;

    memset(&msk, 0, sizeof(msk));
    memset(&pp, 0, sizeof(pp));
    memset(&sender, 0, sizeof(sender));
    memset(&receiver, 0, sizeof(receiver));
    hscmet2022_ciphertext_init(&ct);

    CHECK(message != NULL && out != NULL);
    fill_message(message, n);
    CHECK(hscmet2022_setup(&msk, &pp) == HSCMET2022_OK);
    CHECK(pp.n == HSCMET2022_N);
    CHECK(hscmet2022_pki_keygen(&sender) == HSCMET2022_OK);
    CHECK(hscmet2022_clc_keygen(&msk, &pp,
        id_c, sizeof(id_c) - 1, &receiver) == HSCMET2022_OK);
    CHECK(check_key_algebra(&pp, &sender, &receiver,
        id_c, sizeof(id_c) - 1));
    CHECK(hscmet2022_signcrypt(&pp, &sender, &receiver,
        id_c, sizeof(id_c) - 1, message, n, &ct) == HSCMET2022_OK);
    CHECK(ct.k == HSCMET2022_K);
    CHECK(ct.C2_len == n + HSCMET2022_SCALAR_BYTES);
    CHECK(hscmet2022_unsigncrypt(&pp, &sender, &receiver,
        id_c, sizeof(id_c) - 1, &ct, out, &outlen) == HSCMET2022_OK);
    CHECK(outlen == n);
    CHECK(n == 0 || memcmp(message, out, n) == 0);
    ok = 1;

cleanup:
    hscmet2022_ciphertext_cleanup(&ct);
    hscmet2022_clc_key_cleanup(&receiver);
    hscmet2022_pki_key_cleanup(&sender);
    hscmet2022_master_key_cleanup(&msk);
    free(out);
    free(message);
    return ok;
}

static int decrypt_rejects(
    const HSCMET2022_PUBLIC_PARAMS *pp,
    const HSCMET2022_PKI_KEY *sender,
    const HSCMET2022_CLC_KEY *receiver,
    const HSCMET2022_CIPHERTEXT *ct,
    const uint8_t *id_c,
    size_t id_c_len,
    uint8_t *out,
    size_t out_capacity)
{
    size_t outlen = out_capacity;
    memset(out, 0, out_capacity);
    return hscmet2022_unsigncrypt(pp, sender, receiver,
        id_c, id_c_len, ct, out, &outlen) == HSCMET2022_ERR;
}

static int tamper_rejection(void)
{
    enum { N = 128 };
    static const uint8_t id_c[] = "Bob";
    HSCMET2022_MASTER_KEY msk;
    HSCMET2022_PUBLIC_PARAMS pp;
    HSCMET2022_PKI_KEY sender;
    HSCMET2022_PKI_KEY wrong_sender;
    HSCMET2022_CLC_KEY receiver;
    HSCMET2022_CLC_KEY wrong_receiver;
    HSCMET2022_CIPHERTEXT ct;
    uint8_t message[N];
    uint8_t out[N];
    uint8_t saved_byte;
    uint32_t saved_k;
    sm2_z256_t one;
    SM2_Z256_POINT saved_C1;
    SM2_Z256_POINT G;
    int ok = 0;

    memset(&msk, 0, sizeof(msk));
    memset(&pp, 0, sizeof(pp));
    memset(&sender, 0, sizeof(sender));
    memset(&wrong_sender, 0, sizeof(wrong_sender));
    memset(&receiver, 0, sizeof(receiver));
    memset(&wrong_receiver, 0, sizeof(wrong_receiver));
    hscmet2022_ciphertext_init(&ct);
    fill_message(message, sizeof(message));

    CHECK(hscmet2022_setup(&msk, &pp) == HSCMET2022_OK);
    CHECK(hscmet2022_pki_keygen(&sender) == HSCMET2022_OK);
    CHECK(hscmet2022_pki_keygen(&wrong_sender) == HSCMET2022_OK);
    CHECK(hscmet2022_clc_keygen(&msk, &pp,
        id_c, sizeof(id_c) - 1, &receiver) == HSCMET2022_OK);
    CHECK(hscmet2022_signcrypt(&pp, &sender, &receiver,
        id_c, sizeof(id_c) - 1, message, sizeof(message), &ct) == HSCMET2022_OK);

    saved_byte = ct.C2[0];
    ct.C2[0] ^= 0x01;
    CHECK(decrypt_rejects(&pp, &sender, &receiver, &ct,
        id_c, sizeof(id_c) - 1, out, sizeof(out)));
    ct.C2[0] = saved_byte;

    saved_byte = ct.C3[0];
    ct.C3[0] ^= 0x01;
    CHECK(decrypt_rejects(&pp, &sender, &receiver, &ct,
        id_c, sizeof(id_c) - 1, out, sizeof(out)));
    ct.C3[0] = saved_byte;

    saved_byte = ct.C4[0];
    ct.C4[0] ^= 0x01;
    CHECK(decrypt_rejects(&pp, &sender, &receiver, &ct,
        id_c, sizeof(id_c) - 1, out, sizeof(out)));
    ct.C4[0] = saved_byte;

    saved_k = ct.k;
    ct.k = 1;
    CHECK(decrypt_rejects(&pp, &sender, &receiver, &ct,
        id_c, sizeof(id_c) - 1, out, sizeof(out)));
    ct.k = saved_k;

    sm2_z256_set_one(one);
    memcpy(&saved_C1, &ct.C1, sizeof(saved_C1));
    sm2_z256_point_mul_generator(&G, one);
    sm2_z256_point_add(&ct.C1, &ct.C1, &G);
    CHECK(decrypt_rejects(&pp, &sender, &receiver, &ct,
        id_c, sizeof(id_c) - 1, out, sizeof(out)));
    memcpy(&ct.C1, &saved_C1, sizeof(ct.C1));

    CHECK(decrypt_rejects(&pp, &wrong_sender, &receiver, &ct,
        id_c, sizeof(id_c) - 1, out, sizeof(out)));

    memcpy(&wrong_receiver, &receiver, sizeof(receiver));
    sm2_z256_modn_add(wrong_receiver.sk_c1, wrong_receiver.sk_c1, one);
    if (sm2_z256_is_zero(wrong_receiver.sk_c1)) {
        sm2_z256_modn_add(wrong_receiver.sk_c1, wrong_receiver.sk_c1, one);
    }
    CHECK(decrypt_rejects(&pp, &sender, &wrong_receiver, &ct,
        id_c, sizeof(id_c) - 1, out, sizeof(out)));

    memcpy(&wrong_receiver, &receiver, sizeof(receiver));
    sm2_z256_modn_add(wrong_receiver.sk_c2, wrong_receiver.sk_c2, one);
    if (sm2_z256_is_zero(wrong_receiver.sk_c2)) {
        sm2_z256_modn_add(wrong_receiver.sk_c2, wrong_receiver.sk_c2, one);
    }
    CHECK(decrypt_rejects(&pp, &sender, &wrong_receiver, &ct,
        id_c, sizeof(id_c) - 1, out, sizeof(out)));

    ok = 1;

cleanup:
    hscmet2022_ciphertext_cleanup(&ct);
    hscmet2022_clc_key_cleanup(&receiver);
    hscmet2022_pki_key_cleanup(&wrong_sender);
    hscmet2022_pki_key_cleanup(&sender);
    hscmet2022_master_key_cleanup(&msk);
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
    puts("test_hscmet2022: ok");
    return 0;
}
