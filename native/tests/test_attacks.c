#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <gmssl/sm9_z256.h>
#include <v2_scheme.h>

#define CHECK(expr) do { \
    if (!(expr)) { \
        fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, #expr); \
        return 0; \
    } \
} while (0)

typedef struct {
    V2_KGC kgc;
    V2_PUBLIC_PARAMS pp;
    V2_SENDER_KEY sender;
    V2_RECEIVER_KEY receiver;
    V2_CIPHERTEXT ct;
    const uint8_t *id_a;
    size_t id_a_len;
    const char *id_b;
    size_t id_b_len;
} FIXTURE;

static const uint8_t ID_A[] = "Alice";
static const char ID_B[] = "Bob";
static const uint8_t MESSAGE[] = "adversarial-negative-test";

static int fixture_init(FIXTURE *f)
{
    V2_OFFLINE_TOKEN token;

    memset(f, 0, sizeof(*f));
    f->id_a = ID_A;
    f->id_a_len = sizeof(ID_A) - 1;
    f->id_b = ID_B;
    f->id_b_len = sizeof(ID_B) - 1;
    v2_ciphertext_init(&f->ct);
    v2_offline_token_init(&token);

    CHECK(v2_setup(&f->kgc, &f->pp) == V2_OK);
    CHECK(v2_sender_keygen(&f->sender) == V2_OK);
    CHECK(v2_receiver_keygen(&f->kgc, &f->pp, f->id_b, f->id_b_len, &f->receiver) == V2_OK);
    CHECK(v2_offline_signcrypt(&f->pp, &f->sender,
        f->id_a, f->id_a_len, f->id_b, f->id_b_len,
        &f->receiver.X_b, &token) == V2_OK);
    CHECK(v2_online_signcrypt(&f->sender,
        f->id_a, f->id_a_len, f->id_b, f->id_b_len,
        &token, MESSAGE, sizeof(MESSAGE) - 1, &f->ct) == V2_OK);
    v2_offline_token_cleanup(&token);
    return 1;
}

static void fixture_cleanup(FIXTURE *f)
{
    v2_ciphertext_cleanup(&f->ct);
    v2_receiver_key_cleanup(&f->receiver);
    v2_sender_key_cleanup(&f->sender);
    v2_kgc_cleanup(&f->kgc);
}

static int clone_ciphertext(const V2_CIPHERTEXT *src, V2_CIPHERTEXT *dst)
{
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    int ret = 0;

    v2_ciphertext_init(dst);
    CHECK(v2_ciphertext_serialize(src, NULL, &wire_len) == V2_OK);
    wire = malloc(wire_len);
    CHECK(wire != NULL);
    CHECK(v2_ciphertext_serialize(src, wire, &wire_len) == V2_OK);
    CHECK(v2_ciphertext_parse(dst, wire, wire_len) == V2_OK);
    ret = 1;
    free(wire);
    return ret;
}

static int must_reject(FIXTURE *f, V2_CIPHERTEXT *ct, const V2_RECEIVER_KEY *receiver)
{
    uint8_t out[sizeof(MESSAGE)];
    size_t outlen = sizeof(out);
    return v2_unsigncrypt(&f->pp, &f->sender,
        f->id_a, f->id_a_len, f->id_b, f->id_b_len,
        receiver, ct, out, &outlen) != V2_OK;
}

static int test_tamper_rejection(void)
{
    FIXTURE f;
    V2_CIPHERTEXT t;
    V2_RECEIVER_KEY wrong;

    CHECK(fixture_init(&f));

    CHECK(clone_ciphertext(&f.ct, &t));
    sm9_z256_point_dbl(&t.X_b, &t.X_b);
    CHECK(must_reject(&f, &t, &f.receiver));
    v2_ciphertext_cleanup(&t);

    CHECK(clone_ciphertext(&f.ct, &t));
    sm9_z256_point_dbl(&t.U, &t.U);
    CHECK(must_reject(&f, &t, &f.receiver));
    v2_ciphertext_cleanup(&t);

    CHECK(clone_ciphertext(&f.ct, &t));
    t.C[0] ^= 0x01;
    CHECK(must_reject(&f, &t, &f.receiver));
    v2_ciphertext_cleanup(&t);

    CHECK(clone_ciphertext(&f.ct, &t));
    t.sigma.r[0] ^= 0x01;
    CHECK(must_reject(&f, &t, &f.receiver));
    v2_ciphertext_cleanup(&t);

    CHECK(clone_ciphertext(&f.ct, &t));
    t.sigma.s[31] ^= 0x01;
    CHECK(must_reject(&f, &t, &f.receiver));
    v2_ciphertext_cleanup(&t);

    CHECK(clone_ciphertext(&f.ct, &t));
    t.tau[7] ^= 0x80;
    CHECK(must_reject(&f, &t, &f.receiver));
    v2_ciphertext_cleanup(&t);

    memcpy(&wrong, &f.receiver, sizeof(wrong));
    sm9_z256_set_zero(wrong.x_b);
    wrong.x_b[0] = 2;
    CHECK(must_reject(&f, &f.ct, &wrong));
    v2_receiver_key_cleanup(&wrong);

    memcpy(&wrong, &f.receiver, sizeof(wrong));
    wrong.identity_key.de = *sm9_z256_twist_generator();
    CHECK(must_reject(&f, &f.ct, &wrong));
    v2_receiver_key_cleanup(&wrong);

    CHECK(clone_ciphertext(&f.ct, &t));
    sm9_z256_point_set_infinity(&t.X_b);
    CHECK(must_reject(&f, &t, &f.receiver));
    v2_ciphertext_cleanup(&t);

    CHECK(clone_ciphertext(&f.ct, &t));
    sm9_z256_point_set_infinity(&t.U);
    CHECK(must_reject(&f, &t, &f.receiver));
    v2_ciphertext_cleanup(&t);

    fixture_cleanup(&f);
    return 1;
}

static int test_wire_rejection(void)
{
    FIXTURE f;
    V2_CIPHERTEXT parsed;
    uint8_t *wire = NULL;
    size_t wire_len = 0;

    CHECK(fixture_init(&f));
    CHECK(v2_ciphertext_serialize(&f.ct, NULL, &wire_len) == V2_OK);
    wire = malloc(wire_len);
    CHECK(wire != NULL);
    CHECK(v2_ciphertext_serialize(&f.ct, wire, &wire_len) == V2_OK);

    v2_ciphertext_init(&parsed);
    wire[0] = 0xff;
    CHECK(v2_ciphertext_parse(&parsed, wire, wire_len) != V2_OK);
    wire[0] = V2_CIPHERTEXT_VERSION;

    CHECK(v2_ciphertext_parse(&parsed, wire, wire_len - 1) != V2_OK);

    wire[1] = 0x02;
    CHECK(v2_ciphertext_parse(&parsed, wire, wire_len) != V2_OK);
    wire[1] = 0x04;

    wire[1 + 65 + 65 + 0] = 0xff;
    wire[1 + 65 + 65 + 1] = 0xff;
    wire[1 + 65 + 65 + 2] = 0xff;
    wire[1 + 65 + 65 + 3] = 0xff;
    CHECK(v2_ciphertext_parse(&parsed, wire, wire_len) != V2_OK);

    v2_ciphertext_cleanup(&parsed);
    fixture_cleanup(&f);
    free(wire);
    return 1;
}

static int test_type_i_ksr_knowledge_path(void)
{
    FIXTURE f;
    V2_KEM_MATERIAL encap;
    SM9_Z256_POINT q_b;
    SM9_Z256_POINT x_prime_pub;
    SM9_Z256_POINT attacker_z2;
    sm9_z256_t x_prime;

    CHECK(fixture_init(&f));
    CHECK(v2_compute_qb(&f.pp, f.id_b, f.id_b_len, &q_b) == V2_OK);
    do {
        CHECK(sm9_z256_rand_range(x_prime, sm9_z256_order()) == 1);
    } while (sm9_z256_is_zero(x_prime));
    sm9_z256_point_mul(&x_prime_pub, x_prime, &q_b);

    CHECK(v2_kem_encapsulate(&f.pp, &f.sender,
        f.id_a, f.id_a_len, f.id_b, f.id_b_len,
        &x_prime_pub, &encap) == V2_OK);
    sm9_z256_point_mul(&attacker_z2, x_prime, &encap.U);
    CHECK(sm9_z256_point_equ(&attacker_z2, &encap.Z2) == 1);

    v2_kem_material_cleanup(&encap);
    fixture_cleanup(&f);
    return 1;
}

static int test_type_ii_kgc_knowledge_path(void)
{
    FIXTURE f;
    V2_KEM_MATERIAL encap;
    sm9_z256_fp12_t kgc_z1;

    CHECK(fixture_init(&f));
    CHECK(v2_kem_encapsulate(&f.pp, &f.sender,
        f.id_a, f.id_a_len, f.id_b, f.id_b_len,
        &f.receiver.X_b, &encap) == V2_OK);
    sm9_z256_pairing(kgc_z1, &f.receiver.identity_key.de, &encap.U);
    CHECK(sm9_z256_fp12_equ(kgc_z1, encap.Z1) == 1);

    v2_kem_material_cleanup(&encap);
    fixture_cleanup(&f);
    return 1;
}

int main(void)
{
    if (!test_tamper_rejection()
        || !test_wire_rejection()
        || !test_type_i_ksr_knowledge_path()
        || !test_type_ii_kgc_knowledge_path()) {
        return 1;
    }
    puts("test_attacks: ok");
    return 0;
}
