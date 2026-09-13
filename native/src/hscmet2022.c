#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <gmssl/mem.h>
#include <gmssl/sm3.h>

#include <hscmet2022.h>

static const uint8_t H1_DOMAIN[] = "HSCMET2022-H1";
static const uint8_t H2_DOMAIN[] = "HSCMET2022-H2";
static const uint8_t H3_DOMAIN[] = "HSCMET2022-H3";
static const uint8_t H4_DOMAIN[] = "HSCMET2022-H4";

static int scalar_valid(const sm2_z256_t value)
{
    return sm2_z256_cmp(value, sm2_z256_order()) < 0;
}

static int scalar_valid_nonzero(const sm2_z256_t value)
{
    return scalar_valid(value) && !sm2_z256_is_zero(value);
}

static int scalar_nonzero_random(sm2_z256_t out)
{
    do {
        if (sm2_z256_rand_range(out, sm2_z256_order()) != 1) {
            return 0;
        }
    } while (sm2_z256_is_zero(out));
    return 1;
}

static int point_valid_nonzero(const SM2_Z256_POINT *point)
{
    return point
        && sm2_z256_point_is_on_curve(point) == 1
        && !sm2_z256_point_is_at_infinity(point);
}

static void u32be(uint32_t value, uint8_t out[4])
{
    out[0] = (uint8_t)(value >> 24);
    out[1] = (uint8_t)(value >> 16);
    out[2] = (uint8_t)(value >> 8);
    out[3] = (uint8_t)value;
}

static void u64be(uint64_t value, uint8_t out[8])
{
    int i;
    for (i = 7; i >= 0; i--) {
        out[i] = (uint8_t)value;
        value >>= 8;
    }
}

static void sm3_update_framed(SM3_CTX *ctx, const uint8_t *data, size_t len)
{
    uint8_t lenbuf[8];
    u64be((uint64_t)len, lenbuf);
    sm3_update(ctx, lenbuf, sizeof(lenbuf));
    if (len) {
        sm3_update(ctx, data, len);
    }
}

static int h1_fields(
    const uint8_t *const *parts,
    const size_t *lengths,
    size_t count,
    sm2_z256_t out)
{
    uint32_t counter;
    uint8_t ctr[4];
    uint8_t digest[SM3_DIGEST_SIZE];
    size_t i;

    if (!parts || !lengths || count == 0) {
        return 0;
    }
    for (i = 0; i < count; i++) {
        if (lengths[i] && !parts[i]) {
            return 0;
        }
    }

    for (counter = 0; counter != UINT32_MAX; counter++) {
        SM3_CTX ctx;
        sm3_init(&ctx);
        sm3_update(&ctx, H1_DOMAIN, sizeof(H1_DOMAIN) - 1);
        for (i = 0; i < count; i++) {
            sm3_update_framed(&ctx, parts[i], lengths[i]);
        }
        u32be(counter, ctr);
        sm3_update(&ctx, ctr, sizeof(ctr));
        sm3_finish(&ctx, digest);
        sm2_z256_from_bytes(out, digest);
        if (scalar_valid_nonzero(out)) {
            gmssl_secure_clear(digest, sizeof(digest));
            return 1;
        }
    }
    gmssl_secure_clear(digest, sizeof(digest));
    return 0;
}

static int h1_id(const uint8_t *id, size_t id_len, sm2_z256_t out)
{
    const uint8_t *parts[1] = {id};
    const size_t lengths[1] = {id_len};
    return h1_fields(parts, lengths, 1, out);
}

static int h1_f0(const uint8_t *message, size_t message_len, sm2_z256_t out)
{
    uint8_t nbuf[4];
    const uint8_t *parts[2];
    size_t lengths[2];

    u32be(HSCMET2022_N, nbuf);
    parts[0] = message;
    lengths[0] = message_len;
    parts[1] = nbuf;
    lengths[1] = sizeof(nbuf);
    return h1_fields(parts, lengths, 2, out);
}

static int h1_f1(
    const uint8_t *message,
    size_t message_len,
    const sm2_z256_t f0,
    sm2_z256_t out)
{
    uint8_t nbuf[4];
    uint8_t f0buf[32];
    const uint8_t *parts[3];
    size_t lengths[3];

    u32be(HSCMET2022_N, nbuf);
    sm2_z256_to_bytes(f0, f0buf);
    parts[0] = message;
    lengths[0] = message_len;
    parts[1] = nbuf;
    lengths[1] = sizeof(nbuf);
    parts[2] = f0buf;
    lengths[2] = sizeof(f0buf);
    return h1_fields(parts, lengths, 3, out);
}

static int point_kdf(
    const uint8_t *domain,
    size_t domain_len,
    const SM2_Z256_POINT *point,
    uint8_t *out,
    size_t out_len)
{
    uint8_t octets[65];
    SM3_KDF_CTX ctx;

    if (!domain || !point_valid_nonzero(point)) {
        return 0;
    }
    if (out_len == 0) {
        return 1;
    }
    if (!out) {
        return 0;
    }
    if (sm2_z256_point_to_uncompressed_octets(point, octets) != 1) {
        return 0;
    }
    sm3_kdf_init(&ctx, out_len);
    sm3_kdf_update(&ctx, domain, domain_len);
    sm3_kdf_update(&ctx, octets, sizeof(octets));
    sm3_kdf_finish(&ctx, out);
    return 1;
}

static int h2_mask(const SM2_Z256_POINT *point, uint8_t *out, size_t out_len)
{
    return point_kdf(H2_DOMAIN, sizeof(H2_DOMAIN) - 1, point, out, out_len);
}

static int h3_mask(const SM2_Z256_POINT *point, uint8_t out[HSCMET2022_C3_BYTES])
{
    return point_kdf(H3_DOMAIN, sizeof(H3_DOMAIN) - 1,
        point, out, HSCMET2022_C3_BYTES);
}

static int h4_digest(
    const HSCMET2022_CIPHERTEXT *ct,
    const sm2_z256_t f0,
    const sm2_z256_t f1,
    const SM2_Z256_POINT *R,
    uint8_t out[HSCMET2022_C4_BYTES])
{
    SM3_CTX ctx;
    uint8_t pointbuf[65];
    uint8_t scalarbuf[32];
    uint8_t kbuf[4];

    if (!ct || !R || !point_valid_nonzero(&ct->C1)
        || !point_valid_nonzero(R) || (ct->C2_len && !ct->C2)) {
        return 0;
    }

    sm3_init(&ctx);
    sm3_update(&ctx, H4_DOMAIN, sizeof(H4_DOMAIN) - 1);

    if (sm2_z256_point_to_uncompressed_octets(&ct->C1, pointbuf) != 1) {
        return 0;
    }
    sm3_update_framed(&ctx, pointbuf, sizeof(pointbuf));
    sm3_update_framed(&ctx, ct->C2, ct->C2_len);
    sm3_update_framed(&ctx, ct->C3, sizeof(ct->C3));

    sm2_z256_to_bytes(f0, scalarbuf);
    sm3_update_framed(&ctx, scalarbuf, sizeof(scalarbuf));
    sm2_z256_to_bytes(f1, scalarbuf);
    sm3_update_framed(&ctx, scalarbuf, sizeof(scalarbuf));

    if (sm2_z256_point_to_uncompressed_octets(R, pointbuf) != 1) {
        return 0;
    }
    sm3_update_framed(&ctx, pointbuf, sizeof(pointbuf));

    u32be(ct->k, kbuf);
    sm3_update_framed(&ctx, kbuf, sizeof(kbuf));
    sm3_finish(&ctx, out);
    gmssl_secure_clear(scalarbuf, sizeof(scalarbuf));
    return 1;
}

int hscmet2022_setup(
    HSCMET2022_MASTER_KEY *msk,
    HSCMET2022_PUBLIC_PARAMS *pp)
{
    if (!msk || !pp) {
        return HSCMET2022_ERR;
    }
    memset(msk, 0, sizeof(*msk));
    memset(pp, 0, sizeof(*pp));
    if (!scalar_nonzero_random(msk->s)) {
        return HSCMET2022_ERR;
    }
    sm2_z256_point_mul_generator(&pp->PK, msk->s);
    if (!point_valid_nonzero(&pp->PK)) {
        hscmet2022_master_key_cleanup(msk);
        return HSCMET2022_ERR;
    }
    pp->n = HSCMET2022_N;
    return HSCMET2022_OK;
}

int hscmet2022_pki_keygen(HSCMET2022_PKI_KEY *sender)
{
    if (!sender) {
        return HSCMET2022_ERR;
    }
    memset(sender, 0, sizeof(*sender));
    if (!scalar_nonzero_random(sender->sk_p)) {
        return HSCMET2022_ERR;
    }
    sm2_z256_point_mul_generator(&sender->PK_p, sender->sk_p);
    if (!point_valid_nonzero(&sender->PK_p)) {
        hscmet2022_pki_key_cleanup(sender);
        return HSCMET2022_ERR;
    }
    return HSCMET2022_OK;
}

int hscmet2022_clc_keygen(
    const HSCMET2022_MASTER_KEY *msk,
    const HSCMET2022_PUBLIC_PARAMS *pp,
    const uint8_t *id_c,
    size_t id_c_len,
    HSCMET2022_CLC_KEY *receiver)
{
    sm2_z256_t h_id;
    sm2_z256_t s1;
    sm2_z256_t sh;

    if (!msk || !pp || !receiver || (id_c_len && !id_c)
        || !scalar_valid_nonzero(msk->s)
        || !point_valid_nonzero(&pp->PK)
        || pp->n != HSCMET2022_N) {
        return HSCMET2022_ERR;
    }
    memset(receiver, 0, sizeof(*receiver));
    if (!h1_id(id_c, id_c_len, h_id)) {
        return HSCMET2022_ERR;
    }
    sm2_z256_modn_mul(sh, msk->s, h_id);

    do {
        if (!scalar_nonzero_random(s1)) {
            goto err;
        }
        sm2_z256_modn_add(receiver->sk_c1, s1, sh);
    } while (sm2_z256_is_zero(receiver->sk_c1));

    sm2_z256_point_mul_generator(&receiver->PK_c1, s1);
    if (!scalar_nonzero_random(receiver->sk_c2)) {
        goto err;
    }
    sm2_z256_point_mul_generator(&receiver->PK_c2, receiver->sk_c2);
    if (!point_valid_nonzero(&receiver->PK_c1)
        || !point_valid_nonzero(&receiver->PK_c2)) {
        goto err;
    }

    gmssl_secure_clear(h_id, sizeof(h_id));
    gmssl_secure_clear(s1, sizeof(s1));
    gmssl_secure_clear(sh, sizeof(sh));
    return HSCMET2022_OK;

err:
    gmssl_secure_clear(h_id, sizeof(h_id));
    gmssl_secure_clear(s1, sizeof(s1));
    gmssl_secure_clear(sh, sizeof(sh));
    hscmet2022_clc_key_cleanup(receiver);
    return HSCMET2022_ERR;
}

int hscmet2022_signcrypt(
    const HSCMET2022_PUBLIC_PARAMS *pp,
    const HSCMET2022_PKI_KEY *sender,
    const HSCMET2022_CLC_KEY *receiver,
    const uint8_t *id_c,
    size_t id_c_len,
    const uint8_t *message,
    size_t message_len,
    HSCMET2022_CIPHERTEXT *ct)
{
    sm2_z256_t h_id;
    sm2_z256_t f0;
    sm2_z256_t f1;
    sm2_z256_t r;
    sm2_z256_t X;
    sm2_z256_t f1x;
    sm2_z256_t f2x;
    SM2_Z256_POINT hPK;
    SM2_Z256_POINT ybase;
    SM2_Z256_POINT Y;
    SM2_Z256_POINT R;
    uint8_t *plain2 = NULL;
    uint8_t *maskY = NULL;
    uint8_t *maskR = NULL;
    uint8_t *cipher2 = NULL;
    uint8_t plain3[HSCMET2022_C3_BYTES];
    uint8_t mask3[HSCMET2022_C3_BYTES];
    size_t c2_len;
    size_t i;
    int ret = HSCMET2022_ERR;

    if (!pp || !sender || !receiver || !ct
        || (id_c_len && !id_c) || (message_len && !message)
        || pp->n != HSCMET2022_N
        || !point_valid_nonzero(&pp->PK)
        || !scalar_valid_nonzero(sender->sk_p)
        || !point_valid_nonzero(&sender->PK_p)
        || !scalar_valid_nonzero(receiver->sk_c1)
        || !scalar_valid_nonzero(receiver->sk_c2)
        || !point_valid_nonzero(&receiver->PK_c1)
        || !point_valid_nonzero(&receiver->PK_c2)
        || message_len > SIZE_MAX - HSCMET2022_SCALAR_BYTES) {
        return HSCMET2022_ERR;
    }

    c2_len = message_len + HSCMET2022_SCALAR_BYTES;
    plain2 = malloc(c2_len);
    maskY = malloc(c2_len);
    maskR = malloc(c2_len);
    cipher2 = malloc(c2_len);
    if (!plain2 || !maskY || !maskR || !cipher2) {
        goto end;
    }

    if (!h1_id(id_c, id_c_len, h_id)
        || !h1_f0(message, message_len, f0)
        || !h1_f1(message, message_len, f0, f1)
        || !scalar_nonzero_random(r)
        || !scalar_nonzero_random(X)) {
        goto end;
    }

    sm2_z256_point_mul(&hPK, h_id, &pp->PK);
    sm2_z256_point_add(&ybase, &hPK, &receiver->PK_c1);
    if (!point_valid_nonzero(&ybase)) {
        goto end;
    }
    sm2_z256_point_mul(&Y, sender->sk_p, &ybase);
    sm2_z256_point_mul(&R, r, &receiver->PK_c2);
    sm2_z256_point_mul_generator(&ct->C1, r);
    if (!point_valid_nonzero(&Y) || !point_valid_nonzero(&R)
        || !point_valid_nonzero(&ct->C1)) {
        goto end;
    }

    if (message_len) {
        memcpy(plain2, message, message_len);
    }
    sm2_z256_to_bytes(r, plain2 + message_len);
    if (!h2_mask(&Y, maskY, c2_len) || !h2_mask(&R, maskR, c2_len)) {
        goto end;
    }
    for (i = 0; i < c2_len; i++) {
        cipher2[i] = (uint8_t)(plain2[i] ^ maskY[i] ^ maskR[i]);
    }

    sm2_z256_modn_mul(f1x, f1, X);
    sm2_z256_modn_add(f2x, f0, f1x);
    sm2_z256_to_bytes(X, plain3);
    sm2_z256_to_bytes(f2x, plain3 + HSCMET2022_SCALAR_BYTES);
    if (!h3_mask(&R, mask3)) {
        goto end;
    }
    for (i = 0; i < sizeof(ct->C3); i++) {
        ct->C3[i] = (uint8_t)(plain3[i] ^ mask3[i]);
    }

    if (ct->C2) {
        gmssl_secure_clear(ct->C2, ct->C2_len);
        free(ct->C2);
    }
    ct->C2 = cipher2;
    ct->C2_len = c2_len;
    ct->k = HSCMET2022_K;
    cipher2 = NULL;

    if (!h4_digest(ct, f0, f1, &R, ct->C4)) {
        goto end;
    }
    ret = HSCMET2022_OK;

end:
    if (ret != HSCMET2022_OK && ct->C2) {
        gmssl_secure_clear(ct->C2, ct->C2_len);
        free(ct->C2);
        ct->C2 = NULL;
        ct->C2_len = 0;
        memset(ct->C3, 0, sizeof(ct->C3));
        memset(ct->C4, 0, sizeof(ct->C4));
        ct->k = 0;
    }
    if (plain2) {
        gmssl_secure_clear(plain2, c2_len);
        free(plain2);
    }
    if (maskY) {
        gmssl_secure_clear(maskY, c2_len);
        free(maskY);
    }
    if (maskR) {
        gmssl_secure_clear(maskR, c2_len);
        free(maskR);
    }
    if (cipher2) {
        gmssl_secure_clear(cipher2, c2_len);
        free(cipher2);
    }
    gmssl_secure_clear(plain3, sizeof(plain3));
    gmssl_secure_clear(mask3, sizeof(mask3));
    gmssl_secure_clear(h_id, sizeof(h_id));
    gmssl_secure_clear(f0, sizeof(f0));
    gmssl_secure_clear(f1, sizeof(f1));
    gmssl_secure_clear(r, sizeof(r));
    gmssl_secure_clear(X, sizeof(X));
    gmssl_secure_clear(f1x, sizeof(f1x));
    gmssl_secure_clear(f2x, sizeof(f2x));
    return ret;
}

int hscmet2022_unsigncrypt(
    const HSCMET2022_PUBLIC_PARAMS *pp,
    const HSCMET2022_PKI_KEY *sender,
    const HSCMET2022_CLC_KEY *receiver,
    const uint8_t *id_c,
    size_t id_c_len,
    const HSCMET2022_CIPHERTEXT *ct,
    uint8_t *message,
    size_t *message_len)
{
    SM2_Z256_POINT Y;
    SM2_Z256_POINT R;
    SM2_Z256_POINT rP;
    sm2_z256_t r;
    sm2_z256_t X;
    sm2_z256_t f2_received;
    sm2_z256_t f0;
    sm2_z256_t f1;
    sm2_z256_t f1x;
    sm2_z256_t f2_calc;
    uint8_t *plain2 = NULL;
    uint8_t *maskY = NULL;
    uint8_t *maskR = NULL;
    uint8_t plain3[HSCMET2022_C3_BYTES];
    uint8_t mask3[HSCMET2022_C3_BYTES];
    uint8_t expected_c4[HSCMET2022_C4_BYTES];
    size_t recovered_len;
    size_t i;
    int ret = HSCMET2022_ERR;

    (void)id_c;
    (void)id_c_len;

    if (!pp || !sender || !receiver || !ct || !message_len
        || pp->n != HSCMET2022_N || ct->k != HSCMET2022_K
        || ct->C2_len < HSCMET2022_SCALAR_BYTES || !ct->C2
        || !point_valid_nonzero(&pp->PK)
        || !point_valid_nonzero(&sender->PK_p)
        || !scalar_valid_nonzero(receiver->sk_c1)
        || !scalar_valid_nonzero(receiver->sk_c2)
        || !point_valid_nonzero(&ct->C1)) {
        return HSCMET2022_ERR;
    }

    recovered_len = ct->C2_len - HSCMET2022_SCALAR_BYTES;
    if (*message_len < recovered_len || (recovered_len && !message)) {
        return HSCMET2022_ERR;
    }

    plain2 = malloc(ct->C2_len);
    maskY = malloc(ct->C2_len);
    maskR = malloc(ct->C2_len);
    if (!plain2 || !maskY || !maskR) {
        goto end;
    }

    sm2_z256_point_mul(&Y, receiver->sk_c1, &sender->PK_p);
    sm2_z256_point_mul(&R, receiver->sk_c2, &ct->C1);
    if (!point_valid_nonzero(&Y) || !point_valid_nonzero(&R)
        || !h2_mask(&Y, maskY, ct->C2_len)
        || !h2_mask(&R, maskR, ct->C2_len)) {
        goto end;
    }
    for (i = 0; i < ct->C2_len; i++) {
        plain2[i] = (uint8_t)(ct->C2[i] ^ maskY[i] ^ maskR[i]);
    }

    sm2_z256_from_bytes(r, plain2 + recovered_len);
    if (!scalar_valid_nonzero(r)) {
        goto end;
    }
    sm2_z256_point_mul_generator(&rP, r);
    if (sm2_z256_point_equ(&rP, &ct->C1) != 1) {
        goto end;
    }

    if (!h1_f0(plain2, recovered_len, f0)
        || !h1_f1(plain2, recovered_len, f0, f1)
        || !h3_mask(&R, mask3)) {
        goto end;
    }
    for (i = 0; i < sizeof(plain3); i++) {
        plain3[i] = (uint8_t)(ct->C3[i] ^ mask3[i]);
    }
    sm2_z256_from_bytes(X, plain3);
    sm2_z256_from_bytes(f2_received, plain3 + HSCMET2022_SCALAR_BYTES);
    if (!scalar_valid_nonzero(X) || !scalar_valid(f2_received)) {
        goto end;
    }
    sm2_z256_modn_mul(f1x, f1, X);
    sm2_z256_modn_add(f2_calc, f0, f1x);
    if (!sm2_z256_equ(f2_calc, f2_received)) {
        goto end;
    }

    if (!h4_digest(ct, f0, f1, &R, expected_c4)
        || memcmp(expected_c4, ct->C4, sizeof(expected_c4)) != 0) {
        goto end;
    }

    if (recovered_len) {
        memcpy(message, plain2, recovered_len);
    }
    *message_len = recovered_len;
    ret = HSCMET2022_OK;

end:
    if (ret != HSCMET2022_OK && message && *message_len) {
        gmssl_secure_clear(message, *message_len);
    }
    if (plain2) {
        gmssl_secure_clear(plain2, ct->C2_len);
        free(plain2);
    }
    if (maskY) {
        gmssl_secure_clear(maskY, ct->C2_len);
        free(maskY);
    }
    if (maskR) {
        gmssl_secure_clear(maskR, ct->C2_len);
        free(maskR);
    }
    gmssl_secure_clear(plain3, sizeof(plain3));
    gmssl_secure_clear(mask3, sizeof(mask3));
    gmssl_secure_clear(expected_c4, sizeof(expected_c4));
    gmssl_secure_clear(r, sizeof(r));
    gmssl_secure_clear(X, sizeof(X));
    gmssl_secure_clear(f2_received, sizeof(f2_received));
    gmssl_secure_clear(f0, sizeof(f0));
    gmssl_secure_clear(f1, sizeof(f1));
    gmssl_secure_clear(f1x, sizeof(f1x));
    gmssl_secure_clear(f2_calc, sizeof(f2_calc));
    return ret;
}

void hscmet2022_ciphertext_init(HSCMET2022_CIPHERTEXT *ct)
{
    if (ct) {
        memset(ct, 0, sizeof(*ct));
    }
}

void hscmet2022_ciphertext_cleanup(HSCMET2022_CIPHERTEXT *ct)
{
    if (!ct) {
        return;
    }
    if (ct->C2) {
        gmssl_secure_clear(ct->C2, ct->C2_len);
        free(ct->C2);
    }
    gmssl_secure_clear(ct, sizeof(*ct));
}

void hscmet2022_clc_key_cleanup(HSCMET2022_CLC_KEY *receiver)
{
    if (receiver) {
        gmssl_secure_clear(receiver, sizeof(*receiver));
    }
}

void hscmet2022_pki_key_cleanup(HSCMET2022_PKI_KEY *sender)
{
    if (sender) {
        gmssl_secure_clear(sender, sizeof(*sender));
    }
}

void hscmet2022_master_key_cleanup(HSCMET2022_MASTER_KEY *msk)
{
    if (msk) {
        gmssl_secure_clear(msk, sizeof(*msk));
    }
}
