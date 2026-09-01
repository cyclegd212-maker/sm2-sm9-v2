#ifndef V2_SCHEME_H
#define V2_SCHEME_H

#include <stddef.h>
#include <stdint.h>

#include <gmssl/sm2.h>
#include <gmssl/sm9.h>
#include <gmssl/sm9_z256.h>

#ifdef __cplusplus
extern "C" {
#endif

#define V2_SESSION_KEY_SIZE 32
#define V2_HMAC_SIZE 32
#define V2_CIPHERTEXT_VERSION 1
#define V2_CIPHERTEXT_FIXED_BYTES (1u + 65u + 65u + 4u + 64u + V2_HMAC_SIZE)
#define V2_OK 1
#define V2_ERR (-1)
#define V2_ERR_RETRY_TOKEN (-2)
#define V2_ERR_TOKEN_USED (-3)

typedef struct {
    SM9_ENC_MASTER_KEY master;
} V2_KGC;

typedef struct {
    SM9_Z256_POINT Ppube;
    sm9_z256_fp12_t g;
} V2_PUBLIC_PARAMS;

typedef struct {
    SM2_KEY key;
    sm2_z256_t fast_private;
} V2_SENDER_KEY;

typedef struct {
    SM9_ENC_KEY identity_key;
    sm9_z256_t x_b;
    SM9_Z256_POINT X_b;
} V2_RECEIVER_KEY;

typedef struct {
    SM9_Z256_POINT U;
    sm9_z256_fp12_t Z1;
    SM9_Z256_POINT Z2;
    uint8_t K_E[V2_SESSION_KEY_SIZE];
    uint8_t K_M[V2_SESSION_KEY_SIZE];
} V2_KEM_MATERIAL;

typedef SM2_SIGN_PRE_COMP V2_SM2_PRECOMP;

typedef enum {
    V2_TOKEN_EMPTY = 0,
    V2_TOKEN_READY = 1,
    V2_TOKEN_CONSUMED = 2
} V2_TOKEN_STATE;

typedef struct {
    V2_TOKEN_STATE state;
    SM9_Z256_POINT X_b;
    SM9_Z256_POINT U;
    uint8_t K_E[V2_SESSION_KEY_SIZE];
    uint8_t K_M[V2_SESSION_KEY_SIZE];
    V2_SM2_PRECOMP sm2_pre;
} V2_OFFLINE_TOKEN;

typedef struct {
    SM9_Z256_POINT X_b;
    SM9_Z256_POINT U;
    uint8_t *C;
    size_t C_len;
    SM2_SIGNATURE sigma;
    uint8_t tau[V2_HMAC_SIZE];
} V2_CIPHERTEXT;

int v2_setup(V2_KGC *kgc, V2_PUBLIC_PARAMS *pp);
int v2_compute_qb(
    const V2_PUBLIC_PARAMS *pp,
    const char *id_b,
    size_t id_b_len,
    SM9_Z256_POINT *q_b);
int v2_sender_keygen(V2_SENDER_KEY *sender);
int v2_receiver_keygen(
    V2_KGC *kgc,
    const V2_PUBLIC_PARAMS *pp,
    const char *id_b,
    size_t id_b_len,
    V2_RECEIVER_KEY *receiver);
int v2_encode_context(
    const uint8_t *id_a,
    size_t id_a_len,
    const SM2_KEY *sender_key,
    const char *id_b,
    size_t id_b_len,
    const SM9_Z256_POINT *x_b_pub,
    const SM9_Z256_POINT *u,
    uint8_t *out,
    size_t *outlen);
int v2_kem_encapsulate(
    const V2_PUBLIC_PARAMS *pp,
    const V2_SENDER_KEY *sender,
    const uint8_t *id_a,
    size_t id_a_len,
    const char *id_b,
    size_t id_b_len,
    const SM9_Z256_POINT *x_b_pub,
    V2_KEM_MATERIAL *material);
int v2_kem_decapsulate(
    const V2_PUBLIC_PARAMS *pp,
    const V2_SENDER_KEY *sender,
    const uint8_t *id_a,
    size_t id_a_len,
    const char *id_b,
    size_t id_b_len,
    const V2_RECEIVER_KEY *receiver,
    const SM9_Z256_POINT *u,
    V2_KEM_MATERIAL *material);
int v2_sm2_precompute(V2_SM2_PRECOMP *pre);
int v2_sm2_sign_precomputed(
    const V2_SENDER_KEY *sender,
    const V2_SM2_PRECOMP *pre,
    const uint8_t dgst[32],
    SM2_SIGNATURE *sig);

void v2_offline_token_init(V2_OFFLINE_TOKEN *token);
int v2_offline_signcrypt(
    const V2_PUBLIC_PARAMS *pp,
    const V2_SENDER_KEY *sender,
    const uint8_t *id_a,
    size_t id_a_len,
    const char *id_b,
    size_t id_b_len,
    const SM9_Z256_POINT *x_b_pub,
    V2_OFFLINE_TOKEN *token);
void v2_ciphertext_init(V2_CIPHERTEXT *ct);
int v2_online_signcrypt(
    const V2_SENDER_KEY *sender,
    const uint8_t *id_a,
    size_t id_a_len,
    const char *id_b,
    size_t id_b_len,
    V2_OFFLINE_TOKEN *token,
    const uint8_t *message,
    size_t message_len,
    V2_CIPHERTEXT *ct);
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
    size_t *message_len);
int v2_ciphertext_serialize(const V2_CIPHERTEXT *ct, uint8_t *out, size_t *outlen);
int v2_ciphertext_parse(V2_CIPHERTEXT *ct, const uint8_t *in, size_t inlen);

void v2_ciphertext_cleanup(V2_CIPHERTEXT *ct);
void v2_offline_token_cleanup(V2_OFFLINE_TOKEN *token);
void v2_sm2_precomp_cleanup(V2_SM2_PRECOMP *pre);
void v2_kem_material_cleanup(V2_KEM_MATERIAL *material);
void v2_receiver_key_cleanup(V2_RECEIVER_KEY *receiver);
void v2_sender_key_cleanup(V2_SENDER_KEY *sender);
void v2_kgc_cleanup(V2_KGC *kgc);

#ifdef __cplusplus
}
#endif

#endif /* V2_SCHEME_H */
