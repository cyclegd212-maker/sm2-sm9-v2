#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <gmssl/mem.h>
#include <gmssl/sm3.h>

#include <gong2025_pki_clc.h>

static const uint8_t H1_DOMAIN[] = "GONG2025-H1";
static const uint8_t H2_DOMAIN[] = "GONG2025-H2";
static const uint8_t H4_DOMAIN[] = "GONG2025-H4-PKI-CLC";

static int scalar_nonzero_random(sm2_z256_t out)
{
    do {
        if (sm2_z256_rand_range(out, sm2_z256_order()) != 1) return 0;
    } while (sm2_z256_is_zero(out));
    return 1;
}

static int scalar_nonzero_valid(const sm2_z256_t v)
{
    return !sm2_z256_is_zero(v) && sm2_z256_cmp(v, sm2_z256_order()) < 0;
}

static int scalar_valid(const sm2_z256_t v)
{
    return sm2_z256_cmp(v, sm2_z256_order()) < 0;
}

static int point_valid(const SM2_Z256_POINT *p)
{
    return p && sm2_z256_point_is_on_curve(p) == 1
        && !sm2_z256_point_is_at_infinity(p);
}

static void u64be(uint64_t v, uint8_t out[8])
{
    int i;
    for (i = 7; i >= 0; i--) {
        out[i] = (uint8_t)v;
        v >>= 8;
    }
}

static int sm3_update_len_bytes(SM3_CTX *ctx, const uint8_t *data, size_t len)
{
    uint8_t n[8];
    if (!ctx || (len && !data)) return 0;
    u64be((uint64_t)len, n);
    sm3_update(ctx, n, sizeof(n));
    if (len) sm3_update(ctx, data, len);
    return 1;
}

static int sm3_update_point(SM3_CTX *ctx, const SM2_Z256_POINT *point)
{
    uint8_t octets[65];
    if (!point_valid(point)) return 0;
    if (sm2_z256_point_to_uncompressed_octets(point, octets) != 1) return 0;
    return sm3_update_len_bytes(ctx, octets, sizeof(octets));
}

static int finish_scalar(SM3_CTX *base, sm2_z256_t out)
{
    uint32_t counter;
    uint8_t ctr[4];
    uint8_t digest[SM3_DIGEST_SIZE];
    for (counter = 0; counter != UINT32_MAX; counter++) {
        SM3_CTX ctx = *base;
        ctr[0] = (uint8_t)(counter >> 24);
        ctr[1] = (uint8_t)(counter >> 16);
        ctr[2] = (uint8_t)(counter >> 8);
        ctr[3] = (uint8_t)counter;
        sm3_update(&ctx, ctr, sizeof(ctr));
        sm3_finish(&ctx, digest);
        sm2_z256_from_bytes(out, digest);
        if (scalar_nonzero_valid(out)) {
            gmssl_secure_clear(digest, sizeof(digest));
            return 1;
        }
    }
    gmssl_secure_clear(digest, sizeof(digest));
    return 0;
}

static int h1_receiver(const uint8_t *id_r, size_t id_r_len,
    const SM2_Z256_POINT *R_r, const SM2_Z256_POINT *P_r,
    sm2_z256_t out)
{
    SM3_CTX ctx;
    sm3_init(&ctx);
    sm3_update(&ctx, H1_DOMAIN, sizeof(H1_DOMAIN) - 1);
    if (!sm3_update_len_bytes(&ctx, id_r, id_r_len)
        || !sm3_update_point(&ctx, R_r)
        || !sm3_update_point(&ctx, P_r)) return 0;
    return finish_scalar(&ctx, out);
}

static int h4_pki_clc(const uint8_t *id_s, size_t id_s_len,
    const uint8_t *id_r, size_t id_r_len,
    const GONG2025_PKI_KEY *sender,
    const GONG2025_CLC_KEY *receiver,
    const GONG2025_PUBLIC_PARAMS *pp,
    const uint8_t *c, size_t c_len,
    const SM2_Z256_POINT *T1,
    sm2_z256_t out)
{
    SM3_CTX ctx;
    sm3_init(&ctx);
    sm3_update(&ctx, H4_DOMAIN, sizeof(H4_DOMAIN) - 1);
    if (!sm3_update_len_bytes(&ctx, id_s, id_s_len)
        || !sm3_update_len_bytes(&ctx, id_r, id_r_len)
        || !sm3_update_point(&ctx, &sender->P_s)
        || !sm3_update_point(&ctx, &receiver->P_r)
        || !sm3_update_point(&ctx, &receiver->R_r)
        || !sm3_update_point(&ctx, &receiver->X_r)
        || !sm3_update_point(&ctx, &pp->P_pub)
        || !sm3_update_len_bytes(&ctx, c, c_len)
        || !sm3_update_point(&ctx, T1)) return 0;
    return finish_scalar(&ctx, out);
}

static int h2_mask(const SM2_Z256_POINT *T2, uint8_t *mask, size_t mask_len)
{
    uint8_t octets[65];
    uint8_t n[8];
    SM3_KDF_CTX ctx;
    if (!point_valid(T2)) return 0;
    if (mask_len == 0) return 1;
    if (!mask) return 0;
    if (sm2_z256_point_to_uncompressed_octets(T2, octets) != 1) return 0;
    u64be((uint64_t)sizeof(octets), n);
    sm3_kdf_init(&ctx, mask_len);
    sm3_kdf_update(&ctx, H2_DOMAIN, sizeof(H2_DOMAIN) - 1);
    sm3_kdf_update(&ctx, n, sizeof(n));
    sm3_kdf_update(&ctx, octets, sizeof(octets));
    sm3_kdf_finish(&ctx, mask);
    return 1;
}

int gong2025_setup(GONG2025_MASTER_KEY *msk, GONG2025_PUBLIC_PARAMS *pp)
{
    if (!msk || !pp) return GONG2025_ERR;
    memset(msk, 0, sizeof(*msk));
    memset(pp, 0, sizeof(*pp));
    if (!scalar_nonzero_random(msk->s)) return GONG2025_ERR;
    sm2_z256_point_mul_generator(&pp->P_pub, msk->s);
    if (!point_valid(&pp->P_pub)) {
        gong2025_master_key_cleanup(msk);
        return GONG2025_ERR;
    }
    return GONG2025_OK;
}

int gong2025_pki_keygen(GONG2025_PKI_KEY *sender)
{
    if (!sender) return GONG2025_ERR;
    memset(sender, 0, sizeof(*sender));
    if (!scalar_nonzero_random(sender->x_s)) return GONG2025_ERR;
    sm2_z256_modn_inv(sender->x_s_inv, sender->x_s);
    if (!scalar_nonzero_valid(sender->x_s_inv)) goto err;
    sm2_z256_point_mul_generator(&sender->P_s, sender->x_s_inv);
    if (!point_valid(&sender->P_s)) goto err;
    return GONG2025_OK;
err:
    gong2025_pki_key_cleanup(sender);
    return GONG2025_ERR;
}

int gong2025_clc_keygen(const GONG2025_MASTER_KEY *msk,
    const GONG2025_PUBLIC_PARAMS *pp,
    const uint8_t *id_r, size_t id_r_len,
    GONG2025_CLC_KEY *receiver)
{
    sm2_z256_t sh;
    sm2_z256_t h_inv;
    sm2_z256_t sum;

    if (!msk || !pp || !receiver || (id_r_len && !id_r)
        || !scalar_nonzero_valid(msk->s) || !point_valid(&pp->P_pub))
        return GONG2025_ERR;

    memset(receiver, 0, sizeof(*receiver));
    for (;;) {
        if (!scalar_nonzero_random(receiver->x_r)
            || !scalar_nonzero_random(receiver->r_r)) goto err;
        sm2_z256_point_mul_generator(&receiver->P_r, receiver->x_r);
        sm2_z256_point_mul_generator(&receiver->R_r, receiver->r_r);
        if (!h1_receiver(id_r, id_r_len, &receiver->R_r,
            &receiver->P_r, receiver->h_r)) goto err;
        sm2_z256_modn_mul(sh, msk->s, receiver->h_r);
        sm2_z256_modn_add(receiver->d_r, receiver->r_r, sh);
        sm2_z256_modn_add(sum, receiver->x_r, receiver->d_r);
        if (!scalar_nonzero_valid(receiver->d_r)
            || !scalar_nonzero_valid(sum)) continue;
        sm2_z256_modn_inv(h_inv, receiver->h_r);
        if (!scalar_nonzero_valid(h_inv)) continue;
        sm2_z256_point_mul(&receiver->X_r, h_inv, &receiver->R_r);
        if (!point_valid(&receiver->P_r) || !point_valid(&receiver->R_r)
            || !point_valid(&receiver->X_r)) continue;
        gmssl_secure_clear(sh, sizeof(sh));
        gmssl_secure_clear(h_inv, sizeof(h_inv));
        gmssl_secure_clear(sum, sizeof(sum));
        return GONG2025_OK;
    }
err:
    gmssl_secure_clear(sh, sizeof(sh));
    gmssl_secure_clear(h_inv, sizeof(h_inv));
    gmssl_secure_clear(sum, sizeof(sum));
    gong2025_clc_key_cleanup(receiver);
    return GONG2025_ERR;
}

int gong2025_signcrypt(const GONG2025_PUBLIC_PARAMS *pp,
    const GONG2025_PKI_KEY *sender,
    const uint8_t *id_s, size_t id_s_len,
    const GONG2025_CLC_KEY *receiver,
    const uint8_t *id_r, size_t id_r_len,
    const uint8_t *message, size_t message_len,
    GONG2025_CIPHERTEXT *ct)
{
    sm2_z256_t a, h_r, h_inv, z, h, hx;
    SM2_Z256_POINT h_inv_Pr, br1, br, T2;
    uint8_t *mask = NULL;
    uint8_t *cipher = NULL;
    size_t i;
    int ret = GONG2025_ERR;

    if (!pp || !sender || !receiver || !ct
        || (id_s_len && !id_s) || (id_r_len && !id_r)
        || (message_len && !message)
        || !point_valid(&pp->P_pub)
        || !scalar_nonzero_valid(sender->x_s)
        || !scalar_nonzero_valid(sender->x_s_inv)
        || !point_valid(&sender->P_s)
        || !scalar_nonzero_valid(receiver->x_r)
        || !scalar_nonzero_valid(receiver->d_r)
        || !scalar_nonzero_valid(receiver->h_r)
        || !point_valid(&receiver->P_r)
        || !point_valid(&receiver->R_r)
        || !point_valid(&receiver->X_r)) return GONG2025_ERR;

    if (!h1_receiver(id_r, id_r_len, &receiver->R_r, &receiver->P_r, h_r)
        || sm2_z256_cmp(h_r, receiver->h_r) != 0
        || !scalar_nonzero_random(a)) goto end;

    sm2_z256_point_mul(&ct->T1, a, &sender->P_s);
    if (!point_valid(&ct->T1)) goto end;

    sm2_z256_modn_inv(h_inv, h_r);
    sm2_z256_point_mul(&h_inv_Pr, h_inv, &receiver->P_r);
    sm2_z256_point_add(&br1, &h_inv_Pr, &receiver->X_r);
    sm2_z256_point_add(&br, &br1, &pp->P_pub);
    if (!point_valid(&br)) goto end;
    sm2_z256_modn_mul(z, a, h_r);
    sm2_z256_modn_mul(z, z, sender->x_s_inv);
    sm2_z256_point_mul(&T2, z, &br);
    if (!point_valid(&T2)) goto end;

    if (message_len) {
        mask = malloc(message_len);
        cipher = malloc(message_len);
        if (!mask || !cipher || !h2_mask(&T2, mask, message_len)) goto end;
        for (i = 0; i < message_len; i++) cipher[i] = message[i] ^ mask[i];
    }

    if (!h4_pki_clc(id_s, id_s_len, id_r, id_r_len, sender, receiver,
        pp, cipher, message_len, &ct->T1, h)) goto end;
    sm2_z256_modn_mul(hx, h, sender->x_s);
    sm2_z256_modn_add(ct->S, a, hx);
    if (!scalar_valid(ct->S)) goto end;

    if (ct->c) {
        gmssl_secure_clear(ct->c, ct->c_len);
        free(ct->c);
    }
    ct->c = cipher;
    ct->c_len = message_len;
    cipher = NULL;
    ret = GONG2025_OK;

end:
    if (mask) { gmssl_secure_clear(mask, message_len); free(mask); }
    if (cipher) { gmssl_secure_clear(cipher, message_len); free(cipher); }
    gmssl_secure_clear(a, sizeof(a));
    gmssl_secure_clear(h_r, sizeof(h_r));
    gmssl_secure_clear(h_inv, sizeof(h_inv));
    gmssl_secure_clear(z, sizeof(z));
    gmssl_secure_clear(h, sizeof(h));
    gmssl_secure_clear(hx, sizeof(hx));
    return ret;
}

int gong2025_unsigncrypt(const GONG2025_PUBLIC_PARAMS *pp,
    const GONG2025_PKI_KEY *sender,
    const uint8_t *id_s, size_t id_s_len,
    const GONG2025_CLC_KEY *receiver,
    const uint8_t *id_r, size_t id_r_len,
    const GONG2025_CIPHERTEXT *ct,
    uint8_t *message, size_t *message_len)
{
    sm2_z256_t h, xr_plus_dr;
    SM2_Z256_POINT sPs, hP, T1_prime, T2_prime;
    uint8_t *mask = NULL;
    size_t i;
    int ret = GONG2025_ERR;

    if (!pp || !sender || !receiver || !ct || !message_len
        || (id_s_len && !id_s) || (id_r_len && !id_r)
        || (ct->c_len && (!ct->c || !message))
        || *message_len < ct->c_len
        || !point_valid(&pp->P_pub) || !point_valid(&sender->P_s)
        || !scalar_valid(ct->S) || !point_valid(&ct->T1)
        || !scalar_nonzero_valid(receiver->x_r)
        || !scalar_nonzero_valid(receiver->d_r)
        || !point_valid(&receiver->P_r)
        || !point_valid(&receiver->R_r)
        || !point_valid(&receiver->X_r)) return GONG2025_ERR;

    if (!h4_pki_clc(id_s, id_s_len, id_r, id_r_len, sender, receiver,
        pp, ct->c, ct->c_len, &ct->T1, h)) goto end;
    sm2_z256_point_mul(&sPs, ct->S, &sender->P_s);
    sm2_z256_point_mul_generator(&hP, h);
    sm2_z256_point_sub(&T1_prime, &sPs, &hP);
    if (!point_valid(&T1_prime)
        || sm2_z256_point_equ(&T1_prime, &ct->T1) != 1) goto end;

    sm2_z256_modn_add(xr_plus_dr, receiver->x_r, receiver->d_r);
    if (!scalar_nonzero_valid(xr_plus_dr)) goto end;
    sm2_z256_point_mul(&T2_prime, xr_plus_dr, &T1_prime);
    if (!point_valid(&T2_prime)) goto end;

    if (ct->c_len) {
        mask = malloc(ct->c_len);
        if (!mask || !h2_mask(&T2_prime, mask, ct->c_len)) goto end;
        for (i = 0; i < ct->c_len; i++) message[i] = ct->c[i] ^ mask[i];
    }
    *message_len = ct->c_len;
    ret = GONG2025_OK;

end:
    if (mask) { gmssl_secure_clear(mask, ct->c_len); free(mask); }
    gmssl_secure_clear(h, sizeof(h));
    gmssl_secure_clear(xr_plus_dr, sizeof(xr_plus_dr));
    if (ret != GONG2025_OK && message && ct->c_len) gmssl_secure_clear(message, ct->c_len);
    return ret;
}

void gong2025_ciphertext_init(GONG2025_CIPHERTEXT *ct)
{
    if (ct) memset(ct, 0, sizeof(*ct));
}

void gong2025_ciphertext_cleanup(GONG2025_CIPHERTEXT *ct)
{
    if (!ct) return;
    if (ct->c) {
        gmssl_secure_clear(ct->c, ct->c_len);
        free(ct->c);
    }
    gmssl_secure_clear(ct, sizeof(*ct));
}

void gong2025_clc_key_cleanup(GONG2025_CLC_KEY *receiver)
{
    if (receiver) gmssl_secure_clear(receiver, sizeof(*receiver));
}

void gong2025_pki_key_cleanup(GONG2025_PKI_KEY *sender)
{
    if (sender) gmssl_secure_clear(sender, sizeof(*sender));
}

void gong2025_master_key_cleanup(GONG2025_MASTER_KEY *msk)
{
    if (msk) gmssl_secure_clear(msk, sizeof(*msk));
}
