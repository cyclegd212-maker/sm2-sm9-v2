#ifndef HSCMET2022_H
#define HSCMET2022_H

#include <stddef.h>
#include <stdint.h>

#include <gmssl/sm2_z256.h>

#ifdef __cplusplus
extern "C" {
#endif

#define HSCMET2022_OK 1
#define HSCMET2022_ERR (-1)
#define HSCMET2022_N 2u
#define HSCMET2022_K 2u
#define HSCMET2022_SCALAR_BYTES 32u
#define HSCMET2022_C3_BYTES 64u
#define HSCMET2022_C4_BYTES 32u

typedef struct {
    sm2_z256_t s;
} HSCMET2022_MASTER_KEY;

typedef struct {
    SM2_Z256_POINT PK;
    uint32_t n;
} HSCMET2022_PUBLIC_PARAMS;

typedef struct {
    sm2_z256_t sk_p;
    SM2_Z256_POINT PK_p;
} HSCMET2022_PKI_KEY;

typedef struct {
    sm2_z256_t sk_c1;
    sm2_z256_t sk_c2;
    SM2_Z256_POINT PK_c1;
    SM2_Z256_POINT PK_c2;
} HSCMET2022_CLC_KEY;

typedef struct {
    SM2_Z256_POINT C1;
    uint8_t *C2;
    size_t C2_len;
    uint8_t C3[HSCMET2022_C3_BYTES];
    uint8_t C4[HSCMET2022_C4_BYTES];
    uint32_t k;
} HSCMET2022_CIPHERTEXT;

int hscmet2022_setup(
    HSCMET2022_MASTER_KEY *msk,
    HSCMET2022_PUBLIC_PARAMS *pp);

int hscmet2022_pki_keygen(HSCMET2022_PKI_KEY *sender);

int hscmet2022_clc_keygen(
    const HSCMET2022_MASTER_KEY *msk,
    const HSCMET2022_PUBLIC_PARAMS *pp,
    const uint8_t *id_c,
    size_t id_c_len,
    HSCMET2022_CLC_KEY *receiver);

int hscmet2022_signcrypt(
    const HSCMET2022_PUBLIC_PARAMS *pp,
    const HSCMET2022_PKI_KEY *sender,
    const HSCMET2022_CLC_KEY *receiver,
    const uint8_t *id_c,
    size_t id_c_len,
    const uint8_t *message,
    size_t message_len,
    HSCMET2022_CIPHERTEXT *ct);

int hscmet2022_unsigncrypt(
    const HSCMET2022_PUBLIC_PARAMS *pp,
    const HSCMET2022_PKI_KEY *sender,
    const HSCMET2022_CLC_KEY *receiver,
    const uint8_t *id_c,
    size_t id_c_len,
    const HSCMET2022_CIPHERTEXT *ct,
    uint8_t *message,
    size_t *message_len);

void hscmet2022_ciphertext_init(HSCMET2022_CIPHERTEXT *ct);
void hscmet2022_ciphertext_cleanup(HSCMET2022_CIPHERTEXT *ct);
void hscmet2022_clc_key_cleanup(HSCMET2022_CLC_KEY *receiver);
void hscmet2022_pki_key_cleanup(HSCMET2022_PKI_KEY *sender);
void hscmet2022_master_key_cleanup(HSCMET2022_MASTER_KEY *msk);

#ifdef __cplusplus
}
#endif

#endif /* HSCMET2022_H */
