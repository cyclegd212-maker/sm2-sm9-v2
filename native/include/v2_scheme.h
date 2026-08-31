#ifndef V2_SCHEME_H
#define V2_SCHEME_H

#include <gmssl/sm2.h>
#include <gmssl/sm9.h>
#include <gmssl/sm9_z256.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    SM9_Z256_POINT Ppube;
    sm9_z256_fp12_t g;
} V2_PUBLIC_PARAMS;

#ifdef __cplusplus
}
#endif

#endif /* V2_SCHEME_H */
