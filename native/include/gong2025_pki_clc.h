#ifndef GONG2025_PKI_CLC_H
#define GONG2025_PKI_CLC_H

#include <stddef.h>
#include <stdint.h>

#include <gmssl/sm2_z256.h>

#ifdef __cplusplus
extern "C" {
#endif

#define GONG2025_OK 1
#define GONG2025_ERR (-1)

typedef struct {
    sm2_z256_t s;
} GONG2025_MASTER_KEY;

typedef struct {
    SM2_Z256_POINT P_pub;
} GONG2025_PUBLIC_PARAMS;

typedef struct {
    sm2_z256_t x_s;
    sm2_z256_t x_s_inv;
    SM2_Z256_POINT P_s;
} GONG2025_PKI_KEY;

typedef struct {
    sm2_z256_t x_r;
    sm2_z256_t r_r;
    sm2_z256_t d_r;
    sm2_z256_t h_r;
    SM2_Z256_POINT P_r;
    SM2_Z256_POINT R_r;
    SM2_Z256_POINT X_r;
} GONG2025_CLC_KEY;

typedef struct {
    uint8_t *c;
    size_t c_len;
    sm2_z256_t S;
    SM2_Z256_POINT T1;
} GONG2025_CIPHERTEXT;

int gong2025_setup(
    GONG2025_MASTER_KEY *msk,
    GONG2025_PUBLIC_PARAMS *pp);

int gong2025_pki_keygen(GONG2025_PKI_KEY *sender);

int gong2025_clc_keygen(
    const GONG2025_MASTER_KEY *msk,
    const GONG2025_PUBLIC_PARAMS *pp,
    const uint8_t *id_r,
    size_t id_r_len,
    GONG2025_CLC_KEY *receiver);

int gong2025_signcrypt(
    const GONG2025_PUBLIC_PARAMS *pp,
    const GONG2025_PKI_KEY *sender,
    const uint8_t *id_s,
    size_t id_s_len,
    const GONG2025_CLC_KEY *receiver,
    const uint8_t *id_r,
    size_t id_r_len,
    const uint8_t *message,
    size_t message_len,
    GONG2025_CIPHERTEXT *ct);

int gong2025_unsigncrypt(
    const GONG2025_PUBLIC_PARAMS *pp,
    const GONG2025_PKI_KEY *sender,
    const uint8_t *id_s,
    size_t id_s_len,
    const GONG2025_CLC_KEY *receiver,
    const uint8_t *id_r,
    size_t id_r_len,
    const GONG2025_CIPHERTEXT *ct,
    uint8_t *message,
    size_t *message_len);

void gong2025_ciphertext_init(GONG2025_CIPHERTEXT *ct);
void gong2025_ciphertext_cleanup(GONG2025_CIPHERTEXT *ct);
void gong2025_clc_key_cleanup(GONG2025_CLC_KEY *receiver);
void gong2025_pki_key_cleanup(GONG2025_PKI_KEY *sender);
void gong2025_master_key_cleanup(GONG2025_MASTER_KEY *msk);

#ifdef __cplusplus
}
#endif

#endif /* GONG2025_PKI_CLC_H */
