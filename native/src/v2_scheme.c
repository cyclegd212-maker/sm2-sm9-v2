#include <limits.h>
#include <string.h>

#include <gmssl/mem.h>
#include <gmssl/sm2_z256.h>
#include <v2_scheme.h>

static const uint8_t V2_CTX_DOMAIN[] = "SM2-SM9-V2/CTX/v1";

static void store_u32_be(uint8_t out[4], uint32_t v)
{
    out[0] = (uint8_t)(v >> 24);
    out[1] = (uint8_t)(v >> 16);
    out[2] = (uint8_t)(v >> 8);
    out[3] = (uint8_t)v;
}

static int append_bytes(uint8_t **out, size_t *remain, const uint8_t *in, size_t inlen)
{
    if (*remain < inlen) {
        return -1;
    }
    if (inlen != 0) {
        memcpy(*out, in, inlen);
        *out += inlen;
        *remain -= inlen;
    }
    return 1;
}

static int append_lp(uint8_t **out, size_t *remain, const uint8_t *in, size_t inlen)
{
    uint8_t lenbuf[4];

    if (inlen > UINT32_MAX) {
        return -1;
    }
    store_u32_be(lenbuf, (uint32_t)inlen);
    if (append_bytes(out, remain, lenbuf, sizeof(lenbuf)) != 1) {
        return -1;
    }
    return append_bytes(out, remain, in, inlen);
}

int v2_setup(V2_KGC *kgc, V2_PUBLIC_PARAMS *pp)
{
    if (!kgc || !pp) {
        return -1;
    }
    memset(kgc, 0, sizeof(*kgc));
    memset(pp, 0, sizeof(*pp));

    if (sm9_enc_master_key_generate(&kgc->master) != 1) {
        return -1;
    }
    pp->Ppube = kgc->master.Ppube;
    sm9_z256_pairing(pp->g, sm9_z256_twist_generator(), &pp->Ppube);
    return 1;
}

int v2_compute_qb(
    const V2_PUBLIC_PARAMS *pp,
    const char *id_b,
    size_t id_b_len,
    SM9_Z256_POINT *q_b)
{
    sm9_z256_t h1;
    SM9_Z256_POINT h1_p1;
    int ret = -1;

    if (!pp || !id_b || !q_b) {
        return -1;
    }
    if (sm9_z256_hash1(h1, id_b, id_b_len, SM9_HID_ENC) != 1) {
        goto end;
    }
    sm9_z256_point_mul(&h1_p1, h1, sm9_z256_generator());
    sm9_z256_point_add(q_b, &h1_p1, &pp->Ppube);
    if (!sm9_z256_point_is_on_curve(q_b) || sm9_z256_point_is_at_infinity(q_b)) {
        goto end;
    }
    ret = 1;

end:
    gmssl_secure_clear(h1, sizeof(h1));
    gmssl_secure_clear(&h1_p1, sizeof(h1_p1));
    return ret;
}

int v2_receiver_keygen(
    V2_KGC *kgc,
    const V2_PUBLIC_PARAMS *pp,
    const char *id_b,
    size_t id_b_len,
    V2_RECEIVER_KEY *receiver)
{
    SM9_Z256_POINT q_b;
    int ret = -1;

    if (!kgc || !pp || !id_b || !receiver) {
        return -1;
    }
    memset(receiver, 0, sizeof(*receiver));

    if (sm9_enc_master_key_extract_key(&kgc->master, id_b, id_b_len, &receiver->identity_key) != 1) {
        goto end;
    }
    if (v2_compute_qb(pp, id_b, id_b_len, &q_b) != 1) {
        goto end;
    }
    do {
        if (sm9_z256_rand_range(receiver->x_b, sm9_z256_order()) != 1) {
            goto end;
        }
    } while (sm9_z256_is_zero(receiver->x_b));

    sm9_z256_point_mul(&receiver->X_b, receiver->x_b, &q_b);
    if (!sm9_z256_point_is_on_curve(&receiver->X_b)
        || sm9_z256_point_is_at_infinity(&receiver->X_b)) {
        goto end;
    }
    ret = 1;

end:
    gmssl_secure_clear(&q_b, sizeof(q_b));
    if (ret != 1) {
        v2_receiver_key_cleanup(receiver);
    }
    return ret;
}

int v2_encode_context(
    const uint8_t *id_a,
    size_t id_a_len,
    const SM2_KEY *sender_key,
    const char *id_b,
    size_t id_b_len,
    const SM9_Z256_POINT *x_b_pub,
    const SM9_Z256_POINT *u,
    uint8_t *out,
    size_t *outlen)
{
    uint8_t sm2_pub[65];
    uint8_t x_bytes[65];
    uint8_t u_bytes[65];
    uint8_t *p;
    size_t remain;
    size_t capacity;

    if ((!id_a && id_a_len) || !sender_key || !id_b || !x_b_pub || !u || !out || !outlen) {
        return -1;
    }
    if (!sm9_z256_point_is_on_curve(x_b_pub) || sm9_z256_point_is_at_infinity(x_b_pub)
        || !sm9_z256_point_is_on_curve(u) || sm9_z256_point_is_at_infinity(u)) {
        return -1;
    }
    if (sm2_z256_point_to_uncompressed_octets(&sender_key->public_key, sm2_pub) != 1
        || sm9_z256_point_to_uncompressed_octets(x_b_pub, x_bytes) != 1
        || sm9_z256_point_to_uncompressed_octets(u, u_bytes) != 1) {
        return -1;
    }

    capacity = *outlen;
    p = out;
    remain = capacity;
    if (append_bytes(&p, &remain, V2_CTX_DOMAIN, sizeof(V2_CTX_DOMAIN) - 1) != 1
        || append_lp(&p, &remain, id_a, id_a_len) != 1
        || append_lp(&p, &remain, sm2_pub, sizeof(sm2_pub)) != 1
        || append_lp(&p, &remain, (const uint8_t *)id_b, id_b_len) != 1
        || append_lp(&p, &remain, x_bytes, sizeof(x_bytes)) != 1
        || append_lp(&p, &remain, u_bytes, sizeof(u_bytes)) != 1) {
        gmssl_secure_clear(sm2_pub, sizeof(sm2_pub));
        gmssl_secure_clear(x_bytes, sizeof(x_bytes));
        gmssl_secure_clear(u_bytes, sizeof(u_bytes));
        return -1;
    }
    *outlen = capacity - remain;
    gmssl_secure_clear(sm2_pub, sizeof(sm2_pub));
    gmssl_secure_clear(x_bytes, sizeof(x_bytes));
    gmssl_secure_clear(u_bytes, sizeof(u_bytes));
    return 1;
}

void v2_receiver_key_cleanup(V2_RECEIVER_KEY *receiver)
{
    if (receiver) {
        gmssl_secure_clear(receiver, sizeof(*receiver));
    }
}

void v2_kgc_cleanup(V2_KGC *kgc)
{
    if (kgc) {
        gmssl_secure_clear(kgc, sizeof(*kgc));
    }
}
