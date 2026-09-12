#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pchs_liu2018.h>

#define CHECK(x) do { \
    if (!(x)) { \
        fprintf(stderr, "CHECK failed %s:%d: %s\n", __FILE__, __LINE__, #x); \
        goto cleanup; \
    } \
} while (0)

static void fill_message(uint8_t *buf, size_t len)
{
    size_t i;
    for (i = 0; i < len; i++) {
        buf[i] = (uint8_t)(i * 17u + len);
    }
}

static int roundtrip(size_t n)
{
    PCHS_MASTER_KEY msk;
    PCHS_PUBLIC_PARAMS pp;
    PCHS_PKI_KEY sender;
    PCHS_CLC_KEY receiver;
    PCHS_CIPHERTEXT ct;
    static const uint8_t id[] = "Bob";
    uint8_t *m = calloc(n ? n : 1, 1);
    uint8_t *out = calloc(n ? n : 1, 1);
    size_t outlen = n;
    int ok = 0;

    memset(&msk, 0, sizeof(msk));
    memset(&pp, 0, sizeof(pp));
    memset(&sender, 0, sizeof(sender));
    memset(&receiver, 0, sizeof(receiver));
    pchs_ciphertext_init(&ct);

    CHECK(m != NULL && out != NULL);
    fill_message(m, n);
    CHECK(pchs_setup(&msk, &pp) == PCHS_OK);
    CHECK(pchs_pki_keygen(&sender) == PCHS_OK);
    CHECK(pchs_clc_keygen(&msk, &pp, id, sizeof(id) - 1, &receiver) == PCHS_OK);
    CHECK(pchs_signcrypt(&pp, &sender, &receiver, m, n, &ct) == PCHS_OK);
    CHECK(pchs_unsigncrypt(&pp, &sender, &receiver, &ct, out, &outlen) == PCHS_OK);
    CHECK(outlen == n);
    CHECK(n == 0 || memcmp(m, out, n) == 0);
    ok = 1;

cleanup:
    pchs_ciphertext_cleanup(&ct);
    pchs_clc_key_cleanup(&receiver);
    pchs_pki_key_cleanup(&sender);
    pchs_master_key_cleanup(&msk);
    free(out);
    free(m);
    return ok;
}

int main(void)
{
    const size_t sizes[] = {0, 1, 20, 128, 1024, 4096};
    size_t i;

    for (i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
        if (!roundtrip(sizes[i])) {
            return 1;
        }
    }
    puts("test_pchs_liu2018: ok");
    return 0;
}
