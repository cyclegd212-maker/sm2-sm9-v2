#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <gmssl/sm3.h>
#include <gong2025_pki_clc.h>

#define CHECK(x) do { \
    if (!(x)) { \
        fprintf(stderr, "CHECK failed %s:%d: %s\n", __FILE__, __LINE__, #x); \
        goto cleanup; \
    } \
} while (0)

static const uint8_t H1_DOMAIN[] = "GONG2025-H1";
static const uint8_t H4_DOMAIN[] = "GONG2025-H4-PKI-CLC";

static void fill_message(uint8_t *buf, size_t len)
{
    size_t i;
    for (i = 0; i < len; i++) {
        buf[i] = (uint8_t)(i * 29u + len * 7u + 3u);
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

static int update_len_bytes(SM3_CTX *ctx, const uint8_t *data, size_t len)
{
    uint8_t n[8];
    if (len && !data) return 0;
    u64be((uint64_t)len, n);
    sm3_update(ctx, n, sizeof(n));
    if (len) sm3_update(ctx, data, len);
    return 1;
}

static int update_point(SM3_CTX *ctx, const SM2_Z256_POINT *point)
{
    uint8_t octets[65];
    if (!point || sm2_z256_point_to_uncompressed_octets(point, octets) != 1) return 0;
    return update_len_bytes(ctx, octets, sizeof(octets));
}

static int digest_to_nonzero_scalar(const uint8_t *domain, size_t domain_len,
    const uint8_t *body, size_t body_len, sm2_z256_t out)
{
    uint32_t counter;
    uint8_t ctr[4];
    uint8_t digest[SM3_DIGEST_SIZE];
    for (counter = 0; counter != UINT32_MAX; counter++) {
        SM3_CTX ctx;
        ctr[0] = (uint8_t)(counter >> 24);
        ctr[1] = (uint8_t)(counter >> 16);
        ctr[2] = (uint8_t)(counter >> 8);
        ctr[3] = (uint8_t)counter;
        sm3_init(&ctx);
        sm3_update(&ctx, domain, domain_len);
        if (body_len) sm3_update(&ctx, body, body_len);
        sm3_update(&ctx, ctr, sizeof(ctr));
        sm3_finish(&ctx, digest);
        sm2_z256_from_bytes(out, digest);
        if (scalar_valid_nonzero(out)) return 1;
    }
    return 0;
}

static int test_h1(const uint8_t *id_r, size_t id_r_len,
    const SM2_Z256_POINT *R_r, const SM2_Z256_POINT *P_r, sm2_z256_t out)
{
    SM3_CTX ctx;
    uint8_t digest[SM3_DIGEST_SIZE];
    uint8_t body[8 + 64 + 8 + 65 + 8 + 65];
    uint8_t *p = body;
    uint8_t n[8];
    uint8_t octets[65];

    if (id_r_len > 64) return 0;
    u64be((uint64_t)id_r_len, n); memcpy(p, n, 8); p += 8;
    if (id_r_len) { memcpy(p, id_r, id_r_len); p += id_r_len; }
    if (sm2_z256_point_to_uncompressed_octets(R_r, octets) != 1) return 0;
    u64be(65, n); memcpy(p, n, 8); p += 8; memcpy(p, octets, 65); p += 65;
    if (sm2_z256_point_to_uncompressed_octets(P_r, octets) != 1) return 0;
    u64be(65, n); memcpy(p, n, 8); p += 8; memcpy(p, octets, 65); p += 65;

    sm3_init(&ctx);
    sm3_update(&ctx, H1_DOMAIN, sizeof(H1_DOMAIN) - 1);
    sm3_update(&ctx, body, (size_t)(p - body));
    sm3_finish(&ctx, digest);
    if (digest_to_nonzero_scalar(H1_DOMAIN, sizeof(H1_DOMAIN)-1,
        body, (size_t)(p-body), out)) return 1;
    return 0;
}

static int test_h4(const uint8_t *id_s, size_t id_s_len,
    const uint8_t *id_r, size_t id_r_len,
    const GONG2025_PKI_KEY *sender,
    const GONG2025_CLC_KEY *receiver,
    const GONG2025_PUBLIC_PARAMS *pp,
    const GONG2025_CIPHERTEXT *ct,
    sm2_z256_t out)
{
    SM3_CTX ctx;
    uint8_t digest[SM3_DIGEST_SIZE];
    uint8_t ctr[4];
    uint32_t counter;
    uint8_t n[8];

    for (counter = 0; counter != UINT32_MAX; counter++) {
        sm3_init(&ctx);
        sm3_update(&ctx, H4_DOMAIN, sizeof(H4_DOMAIN) - 1);
        if (!update_len_bytes(&ctx, id_s, id_s_len)
            || !update_len_bytes(&ctx, id_r, id_r_len)
            || !update_point(&ctx, &sender->P_s)
            || !update_point(&ctx, &receiver->P_r)
            || !update_point(&ctx, &receiver->R_r)
            || !update_point(&ctx, &receiver->X_r)
            || !update_point(&ctx, &pp->P_pub)
            || !update_len_bytes(&ctx, ct->c, ct->c_len)
            || !update_point(&ctx, &ct->T1)) return 0;
        ctr[0] = (uint8_t)(counter >> 24);
        ctr[1] = (uint8_t)(counter >> 16);
        ctr[2] = (uint8_t)(counter >> 8);
        ctr[3] = (uint8_t)counter;
        sm3_update(&ctx, ctr, sizeof(ctr));
        sm3_finish(&ctx, digest);
        sm2_z256_from_bytes(out, digest);
        if (scalar_valid_nonzero(out)) return 1;
    }
    (void)n;
    return 0;
}

static int check_algebra(const GONG2025_PUBLIC_PARAMS *pp,
    const GONG2025_PKI_KEY *sender,
    const uint8_t *id_s, size_t id_s_len,
    const GONG2025_CLC_KEY *receiver,
    const uint8_t *id_r, size_t id_r_len,
    const GONG2025_CIPHERTEXT *ct)
{
    SM2_Z256_POINT dP, hPpub, key_rhs;
    SM2_Z256_POINT sPs, hP, t1_prime;
    SM2_Z256_POINT h_inv_Pr, br1, br;
    SM2_Z256_POINT t2_paper, t2_receiver;
    sm2_z256_t h, hx, a, z, h_inv, xr_plus_dr;

    sm2_z256_point_mul_generator(&dP, receiver->d_r);
    sm2_z256_point_mul(&hPpub, receiver->h_r, &pp->P_pub);
    sm2_z256_point_add(&key_rhs, &receiver->R_r, &hPpub);
    if (sm2_z256_point_equ(&dP, &key_rhs) != 1) return 0;

    if (!test_h4(id_s, id_s_len, id_r, id_r_len,
        sender, receiver, pp, ct, h)) return 0;
    sm2_z256_point_mul(&sPs, ct->S, &sender->P_s);
    sm2_z256_point_mul_generator(&hP, h);
    sm2_z256_point_sub(&t1_prime, &sPs, &hP);
    if (sm2_z256_point_equ(&t1_prime, &ct->T1) != 1) return 0;

    sm2_z256_modn_mul(hx, h, sender->x_s);
    sm2_z256_modn_sub(a, ct->S, hx);
    if (!scalar_valid_nonzero(a)) return 0;
    sm2_z256_modn_inv(h_inv, receiver->h_r);
    sm2_z256_point_mul(&h_inv_Pr, h_inv, &receiver->P_r);
    sm2_z256_point_add(&br1, &h_inv_Pr, &receiver->X_r);
    sm2_z256_point_add(&br, &br1, &pp->P_pub);
    sm2_z256_modn_mul(z, a, receiver->h_r);
    sm2_z256_modn_mul(z, z, sender->x_s_inv);
    sm2_z256_point_mul(&t2_paper, z, &br);

    sm2_z256_modn_add(xr_plus_dr, receiver->x_r, receiver->d_r);
    sm2_z256_point_mul(&t2_receiver, xr_plus_dr, &t1_prime);
    return sm2_z256_point_equ(&t2_paper, &t2_receiver) == 1;
}

static int roundtrip(size_t n)
{
    static const uint8_t id_s[] = "Alice";
    static const uint8_t id_r[] = "Bob";
    GONG2025_MASTER_KEY msk;
    GONG2025_PUBLIC_PARAMS pp;
    GONG2025_PKI_KEY sender;
    GONG2025_CLC_KEY receiver;
    GONG2025_CIPHERTEXT ct;
    uint8_t *m = calloc(n ? n : 1, 1);
    uint8_t *out = calloc(n ? n : 1, 1);
    size_t outlen = n;
    int ok = 0;

    memset(&msk, 0, sizeof(msk));
    memset(&pp, 0, sizeof(pp));
    memset(&sender, 0, sizeof(sender));
    memset(&receiver, 0, sizeof(receiver));
    gong2025_ciphertext_init(&ct);
    CHECK(m && out);
    fill_message(m, n);
    CHECK(gong2025_setup(&msk, &pp) == GONG2025_OK);
    CHECK(gong2025_pki_keygen(&sender) == GONG2025_OK);
    CHECK(gong2025_clc_keygen(&msk, &pp, id_r, sizeof(id_r)-1, &receiver) == GONG2025_OK);
    CHECK(gong2025_signcrypt(&pp, &sender, id_s, sizeof(id_s)-1,
        &receiver, id_r, sizeof(id_r)-1, m, n, &ct) == GONG2025_OK);
    CHECK(check_algebra(&pp, &sender, id_s, sizeof(id_s)-1,
        &receiver, id_r, sizeof(id_r)-1, &ct));
    CHECK(gong2025_unsigncrypt(&pp, &sender, id_s, sizeof(id_s)-1,
        &receiver, id_r, sizeof(id_r)-1, &ct, out, &outlen) == GONG2025_OK);
    CHECK(outlen == n);
    CHECK(n == 0 || memcmp(m, out, n) == 0);
    ok = 1;

cleanup:
    gong2025_ciphertext_cleanup(&ct);
    gong2025_clc_key_cleanup(&receiver);
    gong2025_pki_key_cleanup(&sender);
    gong2025_master_key_cleanup(&msk);
    free(out);
    free(m);
    return ok;
}

int main(void)
{
    const size_t sizes[] = {0, 1, 20, 128, 1024, 4096};
    size_t i;
    for (i = 0; i < sizeof(sizes)/sizeof(sizes[0]); i++) {
        if (!roundtrip(sizes[i])) return 1;
    }
    puts("test_gong2025_pki_clc: ok");
    return 0;
}
