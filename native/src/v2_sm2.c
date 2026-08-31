#include <string.h>

#include <gmssl/mem.h>
#include <gmssl/sm2_z256.h>
#include <v2_scheme.h>

int v2_sm2_precompute(V2_SM2_PRECOMP *pre)
{
    SM2_Z256_POINT point;
    sm2_z256_t x;
    int ret = V2_ERR;

    if (!pre) {
        return V2_ERR;
    }
    memset(pre, 0, sizeof(*pre));

    do {
        if (sm2_z256_rand_range(pre->k, sm2_z256_order()) != 1) {
            goto end;
        }
    } while (sm2_z256_is_zero(pre->k));

    sm2_z256_point_mul_generator(&point, pre->k);
    if (sm2_z256_point_get_xy(&point, x, NULL) != 1) {
        goto end;
    }
    if (sm2_z256_cmp(x, sm2_z256_order()) >= 0) {
        sm2_z256_sub(x, x, sm2_z256_order());
    }
    sm2_z256_copy(pre->x1_modn, x);
    ret = V2_OK;

end:
    gmssl_secure_clear(&point, sizeof(point));
    gmssl_secure_clear(x, sizeof(x));
    if (ret != V2_OK) {
        v2_sm2_precomp_cleanup(pre);
    }
    return ret;
}

int v2_sm2_sign_precomputed(
    const V2_SENDER_KEY *sender,
    const V2_SM2_PRECOMP *pre,
    const uint8_t dgst[32],
    SM2_SIGNATURE *sig)
{
    V2_SM2_PRECOMP local_pre;
    sm2_z256_t r;
    sm2_z256_t s;
    sm2_z256_t r_plus_k;
    int ret = V2_ERR;

    if (!sender || !pre || !dgst || !sig) {
        return V2_ERR;
    }
    memcpy(&local_pre, pre, sizeof(local_pre));
    memset(sig, 0, sizeof(*sig));

    if (sm2_fast_sign(sender->fast_private, &local_pre, dgst, sig) != 1) {
        goto end;
    }

    sm2_z256_from_bytes(r, sig->r);
    sm2_z256_from_bytes(s, sig->s);
    (void)sm2_z256_add(r_plus_k, r, pre->k);

    if (sm2_z256_is_zero(r)
        || sm2_z256_cmp(r, sm2_z256_order()) >= 0
        || sm2_z256_cmp(r_plus_k, sm2_z256_order()) == 0
        || sm2_z256_is_zero(s)
        || sm2_z256_cmp(s, sm2_z256_order()) >= 0) {
        ret = V2_ERR_RETRY_TOKEN;
        goto end;
    }
    ret = V2_OK;

end:
    gmssl_secure_clear(&local_pre, sizeof(local_pre));
    gmssl_secure_clear(r, sizeof(r));
    gmssl_secure_clear(s, sizeof(s));
    gmssl_secure_clear(r_plus_k, sizeof(r_plus_k));
    if (ret != V2_OK) {
        gmssl_secure_clear(sig, sizeof(*sig));
    }
    return ret;
}

void v2_sm2_precomp_cleanup(V2_SM2_PRECOMP *pre)
{
    if (pre) {
        gmssl_secure_clear(pre, sizeof(*pre));
    }
}
