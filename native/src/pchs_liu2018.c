#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <gmssl/mem.h>
#include <gmssl/sm3.h>

#include <pchs_liu2018.h>

static const uint8_t H1_DOMAIN[] = "LIU2018-PCHS-H1";
static const uint8_t H2_DOMAIN[] = "LIU2018-PCHS-H2";
static const uint8_t H3_DOMAIN[] = "LIU2018-PCHS-H3";

static int scalar_nonzero_random(sm2_z256_t out)
{
    do {
        if (sm2_z256_rand_range(out, sm2_z256_order()) != 1) {
            return 0;
        }
    } while (sm2_z256_is_zero(out));
    return 1;
}

static int scalar_is_valid_nonzero(const sm2_z256_t value)
{
    return !sm2_z256_is_zero(value)
        && sm2_z256_cmp(value, sm2_z256_order()) < 0;
}

static int point_is_valid_nonzero(const SM2_Z256_POINT *point)
{
    return point
        && sm2_z256_point_is_on_curve(point) == 1
        && !sm2_z256_point_is_at_infinity(point);
}

static int hash_to_scalar(
    const uint8_t *domain,
    size_t domain_len,
    const uint8_t *data,
    size_t data_len,
    const SM2_Z256_POINT *point,
    sm2_z256_t out)
{
    uint8_t point_octets[65];
    uint8_t digest[SM3_DIGEST_SIZE];
    uint8_t ctr[4];
    uint32_t counter;

    if (!domain || !point || !point_is_valid_nonzero(point)) {
        return 0;
    }
    if (data_len && !data) {
        return 0;
    }
    if (sm2_z256_point_to_uncompressed_octets(point, point_octets) != 1) {
        return 0;
    }

    for (counter = 0; counter != UINT32_MAX; counter++) {
        SM3_CTX ctx;
        ctr[0] = (uint8_t)(counter >> 24);
        ctr[1] = (uint8_t)(counter >> 16);
        ctr[2] = (uint8_t)(counter >> 8);
        ctr[3] = (uint8_t)counter;

        sm3_init(&ctx);
        sm3_update(&ctx, domain, domain_len);
        if (data_len) {
            sm3_update(&ctx, data, data_len);
        }
        sm3_update(&ctx, point_octets, sizeof(point_octets));
        sm3_update(&ctx, ctr, sizeof(ctr));
        sm3_finish(&ctx, digest);
        sm2_z256_from_bytes(out, digest);
        if (scalar_is_valid_nonzero(out)) {
            gmssl_secure_clear(digest, sizeof(digest));
            return 1;
        }
    }

    gmssl_secure_clear(digest, sizeof(digest));
    return 0;
}

static int h1(
    const uint8_t *id,
    size_t id_len,
    const SM2_Z256_POINT *T,
    sm2_z256_t gamma)
{
    return hash_to_scalar(
        H1_DOMAIN, sizeof(H1_DOMAIN) - 1,
        id, id_len, T, gamma);
}

static int h2(
    const uint8_t *message,
    size_t message_len,
    const SM2_Z256_POINT *R1,
    sm2_z256_t h)
{
    return hash_to_scalar(
        H2_DOMAIN, sizeof(H2_DOMAIN) - 1,
        message, message_len, R1, h);
}

static int h3_mask(
    const SM2_Z256_POINT *R2,
    uint8_t *mask,
    size_t mask_len)
{
    uint8_t point_octets[65];
    SM3_KDF_CTX ctx;

    if (!point_is_valid_nonzero(R2)) {
        return 0;
    }
    if (mask_len == 0) {
        return 1;
    }
    if (!mask) {
        return 0;
    }
    if (sm2_z256_point_to_uncompressed_octets(R2, point_octets) != 1) {
        return 0;
    }

    sm3_kdf_init(&ctx, mask_len);
    sm3_kdf_update(&ctx, H3_DOMAIN, sizeof(H3_DOMAIN) - 1);
    sm3_kdf_update(&ctx, point_octets, sizeof(point_octets));
    sm3_kdf_finish(&ctx, mask);
    return 1;
}

int pchs_setup(PCHS_MASTER_KEY *msk, PCHS_PUBLIC_PARAMS *pp)
{
    if (!msk || !pp) {
        return PCHS_ERR;
    }
    memset(msk, 0, sizeof(*msk));
    memset(pp, 0, sizeof(*pp));
    if (!scalar_nonzero_random(msk->s)) {
        return PCHS_ERR;
    }
    sm2_z256_point_mul_generator(&pp->P_pub, msk->s);
    if (!point_is_valid_nonzero(&pp->P_pub)) {
        pchs_master_key_cleanup(msk);
        return PCHS_ERR;
    }
    return PCHS_OK;
}

int pchs_pki_keygen(PCHS_PKI_KEY *sender)
{
    if (!sender) {
        return PCHS_ERR;
    }
    memset(sender, 0, sizeof(*sender));
    if (!scalar_nonzero_random(sender->x_p)) {
        return PCHS_ERR;
    }
    sm2_z256_modn_inv(sender->x_p_inv, sender->x_p);
    if (!scalar_is_valid_nonzero(sender->x_p_inv)) {
        pchs_pki_key_cleanup(sender);
        return PCHS_ERR;
    }
    sm2_z256_point_mul_generator(&sender->PK_p, sender->x_p_inv);
    if (!point_is_valid_nonzero(&sender->PK_p)) {
        pchs_pki_key_cleanup(sender);
        return PCHS_ERR;
    }
    return PCHS_OK;
}

int pchs_clc_keygen(
    const PCHS_MASTER_KEY *msk,
    const PCHS_PUBLIC_PARAMS *pp,
    const uint8_t *id,
    size_t id_len,
    PCHS_CLC_KEY *receiver)
{
    sm2_z256_t t;
    sm2_z256_t sgamma;

    if (!msk || !pp || !receiver || (id_len && !id)
        || !scalar_is_valid_nonzero(msk->s)
        || !point_is_valid_nonzero(&pp->P_pub)) {
        return PCHS_ERR;
    }
    memset(receiver, 0, sizeof(*receiver));
    if (!scalar_nonzero_random(t)) {
        return PCHS_ERR;
    }
    sm2_z256_point_mul_generator(&receiver->T, t);
    if (!h1(id, id_len, &receiver->T, receiver->gamma)) {
        gmssl_secure_clear(t, sizeof(t));
        return PCHS_ERR;
    }
    sm2_z256_modn_mul(sgamma, msk->s, receiver->gamma);
    sm2_z256_modn_add(receiver->d, t, sgamma);
    if (!scalar_is_valid_nonzero(receiver->d)) {
        gmssl_secure_clear(t, sizeof(t));
        gmssl_secure_clear(sgamma, sizeof(sgamma));
        pchs_clc_key_cleanup(receiver);
        return PCHS_ERR;
    }
    if (!scalar_nonzero_random(receiver->x_c)) {
        gmssl_secure_clear(t, sizeof(t));
        gmssl_secure_clear(sgamma, sizeof(sgamma));
        pchs_clc_key_cleanup(receiver);
        return PCHS_ERR;
    }
    sm2_z256_point_mul_generator(&receiver->PK_c1, receiver->x_c);

    gmssl_secure_clear(t, sizeof(t));
    gmssl_secure_clear(sgamma, sizeof(sgamma));
    if (!point_is_valid_nonzero(&receiver->T)
        || !point_is_valid_nonzero(&receiver->PK_c1)) {
        pchs_clc_key_cleanup(receiver);
        return PCHS_ERR;
    }
    return PCHS_OK;
}

int pchs_signcrypt(
    const PCHS_PUBLIC_PARAMS *pp,
    const PCHS_PKI_KEY *sender,
    const PCHS_CLC_KEY *receiver,
    const uint8_t *message,
    size_t message_len,
    PCHS_CIPHERTEXT *ct)
{
    sm2_z256_t k;
    sm2_z256_t h;
    sm2_z256_t h_minus_k;
    SM2_Z256_POINT R1;
    SM2_Z256_POINT R2;
    SM2_Z256_POINT kPKc1;
    SM2_Z256_POINT gammaPpub;
    SM2_Z256_POINT tmpV;
    uint8_t *mask = NULL;
    uint8_t *cipher = NULL;
    size_t i;
    int ret = PCHS_ERR;

    if (!pp || !sender || !receiver || !ct || (message_len && !message)
        || !point_is_valid_nonzero(&pp->P_pub)
        || !scalar_is_valid_nonzero(sender->x_p)
        || !point_is_valid_nonzero(&sender->PK_p)
        || !scalar_is_valid_nonzero(receiver->x_c)
        || !scalar_is_valid_nonzero(receiver->d)
        || !scalar_is_valid_nonzero(receiver->gamma)
        || !point_is_valid_nonzero(&receiver->T)
        || !point_is_valid_nonzero(&receiver->PK_c1)) {
        return PCHS_ERR;
    }

    if (!scalar_nonzero_random(k)) {
        return PCHS_ERR;
    }
    sm2_z256_point_mul_generator(&R1, k);
    if (!h2(message, message_len, &R1, h)) {
        goto end;
    }
    sm2_z256_point_mul_generator(&R2, h);

    if (message_len) {
        mask = malloc(message_len);
        cipher = malloc(message_len);
        if (!mask || !cipher) {
            goto end;
        }
        if (!h3_mask(&R2, mask, message_len)) {
            goto end;
        }
        for (i = 0; i < message_len; i++) {
            cipher[i] = (uint8_t)(message[i] ^ mask[i]);
        }
    }

    sm2_z256_modn_sub(h_minus_k, h, k);
    sm2_z256_modn_mul(ct->u, h_minus_k, sender->x_p);

    sm2_z256_point_mul(&kPKc1, k, &receiver->PK_c1);
    sm2_z256_point_mul(&gammaPpub, receiver->gamma, &pp->P_pub);
    sm2_z256_point_add(&tmpV, &kPKc1, &receiver->T);
    sm2_z256_point_add(&ct->V, &tmpV, &gammaPpub);
    if (!point_is_valid_nonzero(&ct->V)) {
        goto end;
    }

    if (ct->c) {
        gmssl_secure_clear(ct->c, ct->c_len);
        free(ct->c);
    }
    ct->c = cipher;
    ct->c_len = message_len;
    cipher = NULL;
    ret = PCHS_OK;

end:
    if (mask) {
        gmssl_secure_clear(mask, message_len);
        free(mask);
    }
    if (cipher) {
        gmssl_secure_clear(cipher, message_len);
        free(cipher);
    }
    gmssl_secure_clear(k, sizeof(k));
    gmssl_secure_clear(h, sizeof(h));
    gmssl_secure_clear(h_minus_k, sizeof(h_minus_k));
    return ret;
}

int pchs_unsigncrypt(
    const PCHS_PUBLIC_PARAMS *pp,
    const PCHS_PKI_KEY *sender,
    const PCHS_CLC_KEY *receiver,
    const PCHS_CIPHERTEXT *ct,
    uint8_t *message,
    size_t *message_len)
{
    SM2_Z256_POINT dP;
    SM2_Z256_POINT v_minus_dP;
    SM2_Z256_POINT R1;
    SM2_Z256_POINT uPKp;
    SM2_Z256_POINT R2;
    SM2_Z256_POINT hP;
    SM2_Z256_POINT verify_rhs;
    sm2_z256_t x_c_inv;
    sm2_z256_t h;
    uint8_t *mask = NULL;
    size_t i;
    int ret = PCHS_ERR;

    if (!pp || !sender || !receiver || !ct || !message_len
        || (ct->c_len && (!ct->c || !message))
        || *message_len < ct->c_len
        || !point_is_valid_nonzero(&pp->P_pub)
        || !point_is_valid_nonzero(&sender->PK_p)
        || !scalar_is_valid_nonzero(receiver->x_c)
        || !scalar_is_valid_nonzero(receiver->d)
        || !point_is_valid_nonzero(&ct->V)) {
        return PCHS_ERR;
    }

    sm2_z256_point_mul_generator(&dP, receiver->d);
    sm2_z256_point_sub(&v_minus_dP, &ct->V, &dP);
    if (!point_is_valid_nonzero(&v_minus_dP)) {
        goto end;
    }
    sm2_z256_modn_inv(x_c_inv, receiver->x_c);
    if (!scalar_is_valid_nonzero(x_c_inv)) {
        goto end;
    }
    sm2_z256_point_mul(&R1, x_c_inv, &v_minus_dP);
    if (!point_is_valid_nonzero(&R1)) {
        goto end;
    }

    sm2_z256_point_mul(&uPKp, ct->u, &sender->PK_p);
    sm2_z256_point_add(&R2, &R1, &uPKp);
    if (!point_is_valid_nonzero(&R2)) {
        goto end;
    }

    if (ct->c_len) {
        mask = malloc(ct->c_len);
        if (!mask || !h3_mask(&R2, mask, ct->c_len)) {
            goto end;
        }
        for (i = 0; i < ct->c_len; i++) {
            message[i] = (uint8_t)(ct->c[i] ^ mask[i]);
        }
    }

    if (!h2(message, ct->c_len, &R1, h)) {
        goto end;
    }
    sm2_z256_point_mul_generator(&hP, h);
    sm2_z256_point_sub(&verify_rhs, &hP, &uPKp);
    if (sm2_z256_point_equ(&R1, &verify_rhs) != 1) {
        if (ct->c_len) {
            gmssl_secure_clear(message, ct->c_len);
        }
        goto end;
    }

    *message_len = ct->c_len;
    ret = PCHS_OK;

end:
    if (mask) {
        gmssl_secure_clear(mask, ct->c_len);
        free(mask);
    }
    gmssl_secure_clear(x_c_inv, sizeof(x_c_inv));
    gmssl_secure_clear(h, sizeof(h));
    return ret;
}

void pchs_ciphertext_init(PCHS_CIPHERTEXT *ct)
{
    if (ct) {
        memset(ct, 0, sizeof(*ct));
    }
}

void pchs_ciphertext_cleanup(PCHS_CIPHERTEXT *ct)
{
    if (!ct) {
        return;
    }
    if (ct->c) {
        gmssl_secure_clear(ct->c, ct->c_len);
        free(ct->c);
    }
    gmssl_secure_clear(ct, sizeof(*ct));
}

void pchs_clc_key_cleanup(PCHS_CLC_KEY *receiver)
{
    if (receiver) {
        gmssl_secure_clear(receiver, sizeof(*receiver));
    }
}

void pchs_pki_key_cleanup(PCHS_PKI_KEY *sender)
{
    if (sender) {
        gmssl_secure_clear(sender, sizeof(*sender));
    }
}

void pchs_master_key_cleanup(PCHS_MASTER_KEY *msk)
{
    if (msk) {
        gmssl_secure_clear(msk, sizeof(*msk));
    }
}
