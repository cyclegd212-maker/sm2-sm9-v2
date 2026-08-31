#include <stdint.h>
#include <stdio.h>

#include <gmssl/sm2.h>
#include <v2_scheme.h>

#define CHECK(expr) do { \
    if (!(expr)) { \
        fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, #expr); \
        return 1; \
    } \
} while (0)

int main(void)
{
    V2_SENDER_KEY sender;
    V2_SM2_PRECOMP pre;
    SM2_SIGNATURE sig;
    uint8_t dgst[32];
    size_t i;

    for (i = 0; i < sizeof(dgst); i++) {
        dgst[i] = (uint8_t)(i * 7u + 3u);
    }

    CHECK(v2_sender_keygen(&sender) == 1);
    CHECK(v2_sm2_precompute(&pre) == 1);
    CHECK(v2_sm2_sign_precomputed(&sender, &pre, dgst, &sig) == 1);
    CHECK(sm2_do_verify(&sender.key, dgst, &sig) == 1);

    v2_sm2_precomp_cleanup(&pre);
    v2_sender_key_cleanup(&sender);
    puts("test_sm2_precomp: ok");
    return 0;
}
