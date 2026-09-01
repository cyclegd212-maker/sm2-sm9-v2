#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include <gmssl/mem.h>
#include <gmssl/sm2_z256.h>
#include <gmssl/sm3.h>
#include <v2_scheme.h>

static const uint8_t ENC_DOMAIN[] = "SM2-SM9-V2/ENC/v1";
static const uint8_t SC_DOMAIN[] = "SM2-SM9-V2/SC/v1";
static const uint8_t MAC_DOMAIN[] = "SM2-SM9-V2/MAC/v1";
static const size_t CTX_DOMAIN_LEN = sizeof("SM2-SM9-V2/CTX/v1") - 1;

static void store_u32_be(uint8_t out[4], uint32_t v)
{
    out[0] = (uint8_t)(v >> 24);
    out[1] = (uint8_t)(v >> 16);
    out[2] = (uint8_t)(v >> 8);
    out[3] = (uint8_t)v;
}

static uint32_t load_u32_be(const uint8_t in[4])
{
    return ((uint32_t)in[0] << 24)
        | ((uint32_t)in[1] << 16)
        | ((uint32_t)in[2] << 8)
        | (uint32_t)in[3];
}

static int safe_add_size(size_t *acc, size_t v)
{
    if (SIZE_MAX - *acc < v) {
        return V2_ERR;
    }
    *acc += v;
    return V2_OK;
}

static int append_bytes(uint8_t **p, size_t *remain, const uint8_t *in, size_t inlen)
{
    if (*remain < inlen) {
        return V2_ERR;
    }
    if (inlen) {
        memcpy(*p, in, inlen);
        *p += inlen;
        *remain -= inlen;
    }
    return V2_OK;
}

static int append_lp(uint8_t **p, size_t *remain, const uint8_t *in, size_t inlen)
{
    uint8_t lenbuf[4];
    if (inlen > UINT32_MAX) {
        return V2_ERR;
    }
    store_u32_be(lenbuf, (uint32_t)inlen);
    if (append_bytes(p, remain, lenbuf, sizeof(lenbuf)) != V2_OK) {
        return V2_ERR;
    }
    return append_bytes(p, remain, in, inlen);
}

static int kdf_update_lp(SM3_KDF_CTX *ctx, const uint8_t *in, size_t inlen)
{
    uint8_t lenbuf[4];
    if (inlen > UINT32_MAX) {
        return V2_ERR;
    }
    store_u32_be(lenbuf, (uint32_t)inlen);
    sm3_kdf_update(ctx, lenbuf, sizeof(lenbuf));
    if (inlen) {
        sm3_kdf_update(ctx, in, inlen);
    }
    return V2_OK;
}

static void hmac_update_lp(SM3_HMAC_CTX *ctx, const uint8_t *in, size_t inlen)
{
    uint8_t lenbuf[4];
    store_u32_be(lenbuf, (uint32_t)inlen);
    sm3_hmac_update(ctx, lenbuf, sizeof(lenbuf));
    if (inlen) {
        sm3_hmac_update(ctx, in, inlen);
    }
}

static int context_size(size_t id_a_len, size_t id_b_len, size_t *out)
{
    size_t n = CTX_DOMAIN_LEN;
    if (id_a_len > UINT32_MAX || id_b_len > UINT32_MAX) {
        return V2_ERR;
    }
    if (safe_add_size(&n, 4 + id_a_len) != V2_OK
        || safe_add_size(&n, 4 + 65) != V2_OK
        || safe_add_size(&n, 4 + id_b_len) != V2_OK
        || safe_add_size(&n, 4 + 65) != V2_OK
        || safe_add_size(&n, 4 + 65) != V2_OK) {
        return V2_ERR;
    }
    *out = n;
    return V2_OK;
}

static int build_context(
    const V2_SENDER_KEY *sender,
    const uint8_t *id_a,
    size_t id_a_len,
    const char *id_b,
    size_t id_b_len,
    const SM9_Z256_POINT *x_b,
    const SM9_Z256_POINT *u,
    uint8_t **ctx,
    size_t *ctx_len)
{
    size_t len;
    uint8_t *buf;

    if (context_size(id_a_len, id_b_len, &len) != V2_OK) {
        return V2_ERR;
    }
    buf = malloc(len);
    if (!buf) {
        return V2_ERR;
    }
    *ctx_len = len;
    if (v2_encode_context(id_a, id_a_len, &sender->key,
        id_b, id_b_len, x_b, u, buf, ctx_len) != V2_OK) {
        gmssl_secure_clear(buf, len);
        free(buf);
        return V2_ERR;
    }
    *ctx = buf;
    return V2_OK;
}

static int build_mu(
    const uint8_t *id_a,
    size_t id_a_len,
    const char *id_b,
    size_t id_b_len,
    const SM9_Z256_POINT *x_b,
    const SM9_Z256_POINT *u,
    const uint8_t *c,
    size_t c_len,
    uint8_t **mu,
    size_t *mu_len)
{
    size_t n = sizeof(SC_DOMAIN) - 1;
    uint8_t x_bytes[65];
    uint8_t u_bytes[65];
    uint8_t *buf = NULL;
    uint8_t *p;
    size_t remain;
    int ret = V2_ERR;

    if ((!id_a && id_a_len) || !id_b || !x_b || !u || (!c && c_len)
        || id_a_len > UINT32_MAX || id_b_len > UINT32_MAX || c_len > UINT32_MAX) {
        return V2_ERR;
    }
    if (sm9_z256_point_to_uncompressed_octets(x_b, x_bytes) != 1
        || sm9_z256_point_to_uncompressed_octets(u, u_bytes) != 1) {
        goto end;
    }
    if (safe_add_size(&n, 4 + id_a_len) != V2_OK
        || safe_add_size(&n, 4 + id_b_len) != V2_OK
        || safe_add_size(&n, 4 + sizeof(x_bytes)) != V2_OK
        || safe_add_size(&n, 4 + sizeof(u_bytes)) != V2_OK
        || safe_add_size(&n, 4 + c_len) != V2_OK) {
        goto end;
    }
    buf = malloc(n);
    if (!buf) {
        goto end;
    }
    p = buf;
    remain = n;
    if (append_bytes(&p, &remain, SC_DOMAIN, sizeof(SC_DOMAIN) - 1) != V2_OK
        || append_lp(&p, &remain, id_a, id_a_len) != V2_OK
        || append_lp(&p, &remain, (const uint8_t *)id_b, id_b_len) != V2_OK
        || append_lp(&p, &remain, x_bytes, sizeof(x_bytes)) != V2_OK
        || append_lp(&p, &remain, u_bytes, sizeof(u_bytes)) != V2_OK
        || append_lp(&p, &remain, c, c_len) != V2_OK
        || remain != 0) {
        goto end;
    }
    *mu = buf;
    *mu_len = n;
    buf = NULL;
    ret = V2_OK;

end:
    if (buf) {
        gmssl_secure_clear(buf, n);
        free(buf);
    }
    gmssl_secure_clear(x_bytes, sizeof(x_bytes));
    gmssl_secure_clear(u_bytes, sizeof(u_bytes));
    return ret;
}

static int sm2_digest_mu(
    const V2_SENDER_KEY *sender,
    const uint8_t *id_a,
    size_t id_a_len,
    const uint8_t *mu,
    size_t mu_len,
    uint8_t dgst[32])
{
    SM3_CTX ctx;
    uint8_t z[32];

    if (!sender || (!id_a && id_a_len) || (!mu && mu_len) || !dgst
        || id_a_len > SM2_MAX_ID_LENGTH) {
        return V2_ERR;
    }
    if (sm2_compute_z(z, &sender->key.public_key, (const char *)id_a, id_a_len) != 1) {
        return V2_ERR;
    }
    sm3_init(&ctx);
    sm3_update(&ctx, z, sizeof(z));
    if (mu_len) {
        sm3_update(&ctx, mu, mu_len);
    }
    sm3_finish(&ctx, dgst);
    gmssl_secure_clear(&ctx, sizeof(ctx));
    gmssl_secure_clear(z, sizeof(z));
    return V2_OK;
}

static int stream_xor(
    const uint8_t key[V2_SESSION_KEY_SIZE],
    const uint8_t *ctx,
    size_t ctx_len,
    const uint8_t *in,
    size_t inlen,
    uint8_t *out)
{
    SM3_KDF_CTX kdf;
    uint8_t *stream = NULL;
    int ret = V2_ERR;

    if (!key || (!ctx && ctx_len) || (!in && inlen) || (!out && inlen)) {
        return V2_ERR;
    }
    if (inlen == 0) {
        return V2_OK;
    }
    stream = malloc(inlen);
    if (!stream) {
        return V2_ERR;
    }
    sm3_kdf_init(&kdf, inlen);
    sm3_kdf_update(&kdf, ENC_DOMAIN, sizeof(ENC_DOMAIN) - 1);
    if (kdf_update_lp(&kdf, key, V2_SESSION_KEY_SIZE) != V2_OK
        || kdf_update_lp(&kdf, ctx, ctx_len) != V2_OK) {
        goto end;
    }
    sm3_kdf_finish(&kdf, stream);
    gmssl_memxor(out, in, stream, inlen);
    ret = V2_OK;

end:
    gmssl_secure_clear(&kdf, sizeof(kdf));
    if (stream) {
        gmssl_secure_clear(stream, inlen);
        free(stream);
    }
    return ret;
}

static int compute_tag(
    const uint8_t k_m[V2_SESSION_KEY_SIZE],
    const uint8_t *mu,
    size_t mu_len,
    const SM2_SIGNATURE *sig,
    uint8_t tag[V2_HMAC_SIZE])
{
    SM3_HMAC_CTX hctx;
    uint8_t sigbuf[64];

    if (!k_m || (!mu && mu_len) || !sig || !tag || mu_len > UINT32_MAX) {
        return V2_ERR;
    }
    memcpy(sigbuf, sig->r, 32);
    memcpy(sigbuf + 32, sig->s, 32);
    sm3_hmac_init(&hctx, k_m, V2_SESSION_KEY_SIZE);
    sm3_hmac_update(&hctx, MAC_DOMAIN, sizeof(MAC_DOMAIN) - 1);
    hmac_update_lp(&hctx, mu, mu_len);
    hmac_update_lp(&hctx, sigbuf, sizeof(sigbuf));
    sm3_hmac_finish(&hctx, tag);
    gmssl_secure_clear(&hctx, sizeof(hctx));
    gmssl_secure_clear(sigbuf, sizeof(sigbuf));
    return V2_OK;
}

static void token_clear_sensitive(V2_OFFLINE_TOKEN *token)
{
    gmssl_secure_clear(token->K_E, sizeof(token->K_E));
    gmssl_secure_clear(token->K_M, sizeof(token->K_M));
    v2_sm2_precomp_cleanup(&token->sm2_pre);
}

void v2_offline_token_init(V2_OFFLINE_TOKEN *token)
{
    if (token) {
        memset(token, 0, sizeof(*token));
        token->state = V2_TOKEN_EMPTY;
    }
}

int v2_offline_signcrypt(
    const V2_PUBLIC_PARAMS *pp,
    const V2_SENDER_KEY *sender,
    const uint8_t *id_a,
    size_t id_a_len,
    const char *id_b,
    size_t id_b_len,
    const SM9_Z256_POINT *x_b_pub,
    V2_OFFLINE_TOKEN *token)
{
    V2_KEM_MATERIAL material;
    int ret = V2_ERR;

    if (!pp || !sender || (!id_a && id_a_len) || !id_b || !x_b_pub || !token) {
        return V2_ERR;
    }
    v2_offline_token_cleanup(token);
    if (v2_kem_encapsulate(pp, sender, id_a, id_a_len,
        id_b, id_b_len, x_b_pub, &material) != V2_OK) {
        return V2_ERR;
    }
    token->X_b = *x_b_pub;
    token->U = material.U;
    memcpy(token->K_E, material.K_E, sizeof(token->K_E));
    memcpy(token->K_M, material.K_M, sizeof(token->K_M));
    if (v2_sm2_precompute(&token->sm2_pre) != V2_OK) {
        goto end;
    }
    token->state = V2_TOKEN_READY;
    ret = V2_OK;

end:
    v2_kem_material_cleanup(&material);
    if (ret != V2_OK) {
        v2_offline_token_cleanup(token);
    }
    return ret;
}

void v2_ciphertext_init(V2_CIPHERTEXT *ct)
{
    if (ct) {
        memset(ct, 0, sizeof(*ct));
    }
}

int v2_online_signcrypt(
    const V2_SENDER_KEY *sender,
    const uint8_t *id_a,
    size_t id_a_len,
    const char *id_b,
    size_t id_b_len,
    V2_OFFLINE_TOKEN *token,
    const uint8_t *message,
    size_t message_len,
    V2_CIPHERTEXT *ct)
{
    uint8_t *ctx = NULL;
    size_t ctx_len = 0;
    uint8_t *mu = NULL;
    size_t mu_len = 0;
    uint8_t dgst[32];
    int ret = V2_ERR;

    if (!sender || (!id_a && id_a_len) || !id_b || !token || (!message && message_len) || !ct) {
        return V2_ERR;
    }
    if (token->state != V2_TOKEN_READY) {
        return V2_ERR_TOKEN_USED;
    }
    v2_ciphertext_cleanup(ct);

    /* Consume before any message-dependent cryptographic computation. */
    token->state = V2_TOKEN_CONSUMED;
    ct->X_b = token->X_b;
    ct->U = token->U;
    ct->C_len = message_len;
    if (message_len) {
        ct->C = malloc(message_len);
        if (!ct->C) {
            goto end;
        }
    }
    if (build_context(sender, id_a, id_a_len, id_b, id_b_len,
        &token->X_b, &token->U, &ctx, &ctx_len) != V2_OK) {
        goto end;
    }
    if (stream_xor(token->K_E, ctx, ctx_len, message, message_len, ct->C) != V2_OK) {
        goto end;
    }
    if (build_mu(id_a, id_a_len, id_b, id_b_len,
        &token->X_b, &token->U, ct->C, ct->C_len, &mu, &mu_len) != V2_OK) {
        goto end;
    }
    if (sm2_digest_mu(sender, id_a, id_a_len, mu, mu_len, dgst) != V2_OK) {
        goto end;
    }
    ret = v2_sm2_sign_precomputed(sender, &token->sm2_pre, dgst, &ct->sigma);
    if (ret != V2_OK) {
        goto end;
    }
    if (compute_tag(token->K_M, mu, mu_len, &ct->sigma, ct->tau) != V2_OK) {
        ret = V2_ERR;
        goto end;
    }
    ret = V2_OK;

end:
    token_clear_sensitive(token);
    gmssl_secure_clear(dgst, sizeof(dgst));
    if (ctx) {
        gmssl_secure_clear(ctx, ctx_len);
        free(ctx);
    }
    if (mu) {
        gmssl_secure_clear(mu, mu_len);
        free(mu);
    }
    if (ret != V2_OK) {
        v2_ciphertext_cleanup(ct);
    }
    return ret;
}

int v2_unsigncrypt(
    const V2_PUBLIC_PARAMS *pp,
    const V2_SENDER_KEY *sender,
    const uint8_t *id_a,
    size_t id_a_len,
    const char *id_b,
    size_t id_b_len,
    const V2_RECEIVER_KEY *receiver,
    const V2_CIPHERTEXT *ct,
    uint8_t *message,
    size_t *message_len)
{
    uint8_t *mu = NULL;
    size_t mu_len = 0;
    uint8_t dgst[32];
    V2_KEM_MATERIAL material;
    uint8_t expected[V2_HMAC_SIZE];
    uint8_t *ctx = NULL;
    size_t ctx_len = 0;
    int ret = V2_ERR;

    if (!pp || !sender || (!id_a && id_a_len) || !id_b || !receiver || !ct || !message_len
        || (!message && ct->C_len)) {
        return V2_ERR;
    }
    if (*message_len < ct->C_len) {
        *message_len = ct->C_len;
        return V2_ERR;
    }
    if (!sm9_z256_point_is_on_curve(&ct->X_b) || sm9_z256_point_is_at_infinity(&ct->X_b)
        || !sm9_z256_point_is_on_curve(&ct->U) || sm9_z256_point_is_at_infinity(&ct->U)
        || !sm9_z256_point_equ(&ct->X_b, &receiver->X_b)) {
        return V2_ERR;
    }
    if (build_mu(id_a, id_a_len, id_b, id_b_len,
        &ct->X_b, &ct->U, ct->C, ct->C_len, &mu, &mu_len) != V2_OK) {
        goto end;
    }
    if (sm2_digest_mu(sender, id_a, id_a_len, mu, mu_len, dgst) != V2_OK
        || sm2_do_verify(&sender->key, dgst, &ct->sigma) != 1) {
        goto end;
    }
    if (v2_kem_decapsulate(pp, sender, id_a, id_a_len,
        id_b, id_b_len, receiver, &ct->U, &material) != V2_OK) {
        goto end;
    }
    if (compute_tag(material.K_M, mu, mu_len, &ct->sigma, expected) != V2_OK
        || gmssl_secure_memcmp(expected, ct->tau, sizeof(expected)) != 0) {
        goto end_material;
    }
    if (build_context(sender, id_a, id_a_len, id_b, id_b_len,
        &ct->X_b, &ct->U, &ctx, &ctx_len) != V2_OK) {
        goto end_material;
    }
    if (stream_xor(material.K_E, ctx, ctx_len, ct->C, ct->C_len, message) != V2_OK) {
        goto end_material;
    }
    *message_len = ct->C_len;
    ret = V2_OK;

end_material:
    v2_kem_material_cleanup(&material);
end:
    gmssl_secure_clear(dgst, sizeof(dgst));
    gmssl_secure_clear(expected, sizeof(expected));
    if (ctx) {
        gmssl_secure_clear(ctx, ctx_len);
        free(ctx);
    }
    if (mu) {
        gmssl_secure_clear(mu, mu_len);
        free(mu);
    }
    return ret;
}

int v2_ciphertext_serialize(const V2_CIPHERTEXT *ct, uint8_t *out, size_t *outlen)
{
    size_t required = V2_CIPHERTEXT_FIXED_BYTES;
    size_t capacity;
    uint8_t x_bytes[65];
    uint8_t u_bytes[65];
    uint8_t *p;

    if (!ct || !outlen || ct->C_len > UINT32_MAX || (!ct->C && ct->C_len)) {
        return V2_ERR;
    }
    if (safe_add_size(&required, ct->C_len) != V2_OK) {
        return V2_ERR;
    }
    if (!out) {
        *outlen = required;
        return V2_OK;
    }
    capacity = *outlen;
    if (capacity < required
        || sm9_z256_point_to_uncompressed_octets(&ct->X_b, x_bytes) != 1
        || sm9_z256_point_to_uncompressed_octets(&ct->U, u_bytes) != 1) {
        *outlen = required;
        return V2_ERR;
    }
    p = out;
    *p++ = V2_CIPHERTEXT_VERSION;
    memcpy(p, x_bytes, sizeof(x_bytes)); p += sizeof(x_bytes);
    memcpy(p, u_bytes, sizeof(u_bytes)); p += sizeof(u_bytes);
    store_u32_be(p, (uint32_t)ct->C_len); p += 4;
    if (ct->C_len) { memcpy(p, ct->C, ct->C_len); p += ct->C_len; }
    memcpy(p, ct->sigma.r, 32); p += 32;
    memcpy(p, ct->sigma.s, 32); p += 32;
    memcpy(p, ct->tau, V2_HMAC_SIZE);
    *outlen = required;
    gmssl_secure_clear(x_bytes, sizeof(x_bytes));
    gmssl_secure_clear(u_bytes, sizeof(u_bytes));
    return V2_OK;
}

int v2_ciphertext_parse(V2_CIPHERTEXT *ct, const uint8_t *in, size_t inlen)
{
    const uint8_t *p = in;
    uint32_t c_len;
    size_t required;

    if (!ct || !in || inlen < V2_CIPHERTEXT_FIXED_BYTES) {
        return V2_ERR;
    }
    v2_ciphertext_cleanup(ct);
    if (*p++ != V2_CIPHERTEXT_VERSION) {
        return V2_ERR;
    }
    if (sm9_z256_point_from_uncompressed_octets(&ct->X_b, p) != 1) {
        goto err;
    }
    p += 65;
    if (sm9_z256_point_from_uncompressed_octets(&ct->U, p) != 1) {
        goto err;
    }
    p += 65;
    c_len = load_u32_be(p); p += 4;
    required = V2_CIPHERTEXT_FIXED_BYTES;
    if (safe_add_size(&required, (size_t)c_len) != V2_OK || required != inlen) {
        goto err;
    }
    if (!sm9_z256_point_is_on_curve(&ct->X_b) || sm9_z256_point_is_at_infinity(&ct->X_b)
        || !sm9_z256_point_is_on_curve(&ct->U) || sm9_z256_point_is_at_infinity(&ct->U)) {
        goto err;
    }
    ct->C_len = c_len;
    if (ct->C_len) {
        ct->C = malloc(ct->C_len);
        if (!ct->C) {
            goto err;
        }
        memcpy(ct->C, p, ct->C_len);
        p += ct->C_len;
    }
    memcpy(ct->sigma.r, p, 32); p += 32;
    memcpy(ct->sigma.s, p, 32); p += 32;
    memcpy(ct->tau, p, V2_HMAC_SIZE);
    return V2_OK;

err:
    v2_ciphertext_cleanup(ct);
    return V2_ERR;
}

void v2_ciphertext_cleanup(V2_CIPHERTEXT *ct)
{
    if (!ct) {
        return;
    }
    if (ct->C) {
        gmssl_secure_clear(ct->C, ct->C_len);
        free(ct->C);
    }
    gmssl_secure_clear(ct, sizeof(*ct));
}

void v2_offline_token_cleanup(V2_OFFLINE_TOKEN *token)
{
    if (token) {
        gmssl_secure_clear(token, sizeof(*token));
        token->state = V2_TOKEN_EMPTY;
    }
}
