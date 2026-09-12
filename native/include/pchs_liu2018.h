#ifndef PCHS_LIU2018_H
#define PCHS_LIU2018_H

#include <stddef.h>
#include <stdint.h>

#include <gmssl/sm2_z256.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PCHS_OK 1
#define PCHS_ERR (-1)

typedef struct {
    sm2_z256_t s;
} PCHS_MASTER_KEY;

typedef struct {
    SM2_Z256_POINT P_pub;
} PCHS_PUBLIC_PARAMS;

typedef struct {
    sm2_z256_t x_p;
    sm2_z256_t x_p_inv;
    SM2_Z256_POINT PK_p;
} PCHS_PKI_KEY;

typedef struct {
    sm2_z256_t x_c;
    sm2_z256_t d;
    SM2_Z256_POINT T;
    SM2_Z256_POINT PK_c1;
    sm2_z256_t gamma;
} PCHS_CLC_KEY;

typedef struct {
    uint8_t *c;
    size_t c_len;
    sm2_z256_t u;
    SM2_Z256_POINT V;
} PCHS_CIPHERTEXT;

int pchs_setup(PCHS_MASTER_KEY *msk, PCHS_PUBLIC_PARAMS *pp);
int pchs_pki_keygen(PCHS_PKI_KEY *sender);
int pchs_clc_keygen(
    const PCHS_MASTER_KEY *msk,
    const PCHS_PUBLIC_PARAMS *pp,
    const uint8_t *id,
    size_t id_len,
    PCHS_CLC_KEY *receiver);
int pchs_signcrypt(
    const PCHS_PUBLIC_PARAMS *pp,
    const PCHS_PKI_KEY *sender,
    const PCHS_CLC_KEY *receiver,
    const uint8_t *message,
    size_t message_len,
    PCHS_CIPHERTEXT *ct);
int pchs_unsigncrypt(
    const PCHS_PUBLIC_PARAMS *pp,
    const PCHS_PKI_KEY *sender,
    const PCHS_CLC_KEY *receiver,
    const PCHS_CIPHERTEXT *ct,
    uint8_t *message,
    size_t *message_len);

void pchs_ciphertext_init(PCHS_CIPHERTEXT *ct);
void pchs_ciphertext_cleanup(PCHS_CIPHERTEXT *ct);
void pchs_clc_key_cleanup(PCHS_CLC_KEY *receiver);
void pchs_pki_key_cleanup(PCHS_PKI_KEY *sender);
void pchs_master_key_cleanup(PCHS_MASTER_KEY *msk);

#ifdef __cplusplus
}
#endif

#endif /* PCHS_LIU2018_H */
