#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <v2_scheme.h>

#define CHECK(expr) do { \
    if (!(expr)) { \
        fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, #expr); \
        return 0; \
    } \
} while (0)

static void fill_message(uint8_t *buf, size_t len)
{
    size_t i;
    for (i = 0; i < len; i++) {
        buf[i] = (uint8_t)((i * 131u + len * 17u + 9u) & 0xffu);
    }
}

static int run_roundtrip(size_t message_len)
{
    V2_KGC kgc;
    V2_PUBLIC_PARAMS pp;
    V2_SENDER_KEY sender;
    V2_RECEIVER_KEY receiver;
    V2_OFFLINE_TOKEN token;
    V2_CIPHERTEXT ct;
    V2_CIPHERTEXT parsed;
    uint8_t *message = NULL;
    uint8_t *recovered = NULL;
    uint8_t *wire = NULL;
    size_t recovered_len;
    size_t wire_len = 0;
    const uint8_t id_a[] = "Alice";
    const char *id_b = "Bob";
    int ret = 0;

    if (message_len) {
        message = malloc(message_len);
        recovered = malloc(message_len);
        CHECK(message != NULL && recovered != NULL);
        fill_message(message, message_len);
    }

    CHECK(v2_setup(&kgc, &pp) == V2_OK);
    CHECK(v2_sender_keygen(&sender) == V2_OK);
    CHECK(v2_receiver_keygen(&kgc, &pp, id_b, strlen(id_b), &receiver) == V2_OK);
    v2_offline_token_init(&token);
    v2_ciphertext_init(&ct);
    v2_ciphertext_init(&parsed);

    CHECK(v2_offline_signcrypt(&pp, &sender,
        id_a, sizeof(id_a) - 1, id_b, strlen(id_b),
        &receiver.X_b, &token) == V2_OK);
    CHECK(token.state == V2_TOKEN_READY);

    CHECK(v2_online_signcrypt(&sender,
        id_a, sizeof(id_a) - 1, id_b, strlen(id_b),
        &token, message, message_len, &ct) == V2_OK);
    CHECK(token.state == V2_TOKEN_CONSUMED);

    CHECK(v2_online_signcrypt(&sender,
        id_a, sizeof(id_a) - 1, id_b, strlen(id_b),
        &token, message, message_len, &parsed) == V2_ERR_TOKEN_USED);

    CHECK(v2_ciphertext_serialize(&ct, NULL, &wire_len) == V2_OK);
    CHECK(wire_len >= V2_CIPHERTEXT_FIXED_BYTES + message_len);
    wire = malloc(wire_len);
    CHECK(wire != NULL);
    CHECK(v2_ciphertext_serialize(&ct, wire, &wire_len) == V2_OK);
    CHECK(v2_ciphertext_parse(&parsed, wire, wire_len) == V2_OK);

    recovered_len = message_len;
    CHECK(v2_unsigncrypt(&pp, &sender,
        id_a, sizeof(id_a) - 1, id_b, strlen(id_b),
        &receiver, &parsed, recovered, &recovered_len) == V2_OK);
    CHECK(recovered_len == message_len);
    CHECK(message_len == 0 || memcmp(message, recovered, message_len) == 0);
    ret = 1;

    v2_ciphertext_cleanup(&parsed);
    v2_ciphertext_cleanup(&ct);
    v2_offline_token_cleanup(&token);
    v2_receiver_key_cleanup(&receiver);
    v2_sender_key_cleanup(&sender);
    v2_kgc_cleanup(&kgc);
    free(wire);
    free(recovered);
    free(message);
    return ret;
}

int main(void)
{
    const size_t sizes[] = {0, 1, 20, 128, 1024, 4096};
    size_t i;

    for (i = 0; i < sizeof(sizes)/sizeof(sizes[0]); i++) {
        if (!run_roundtrip(sizes[i])) {
            return 1;
        }
    }
    puts("test_signcryption: ok");
    return 0;
}
