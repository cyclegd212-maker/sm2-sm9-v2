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

void v2_kem_material_cleanup(V2_KEM_MATERIAL *material);
void v2_receiver_key_cleanup(V2_RECEIVER_KEY *receiver);
void v2_sender_key_cleanup(V2_SENDER_KEY *sender);
void v2_kgc_cleanup(V2_KGC *kgc);

#ifdef __cplusplus
}
#endif

#endif /* V2_SCHEME_H */
