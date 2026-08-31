#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <gmssl/sm2.h>
#include <gmssl/sm9.h>
#include <gmssl/sm9_z256.h>
#include <v2_scheme.h>

static void assert_distinct_context(
    const uint8_t *base, size_t base_len,
    const uint8_t *other, size_t other_len)
{
    assert(base_len != other_len || memcmp(base, other, base_len) != 0);
}

static int test_setup_and_receiver_keygen(void)
{
    V2_KGC kgc;
    V2_PUBLIC_PARAMS pp;
    V2_RECEIVER_KEY receiver;
    SM9_Z256_POINT q_b;
    SM9_Z256_POINT expected_x_b;
    sm9_z256_fp12_t expected_g;
    const char *id_b = "Bob";

    assert(v2_setup(&kgc, &pp) == 1);
    assert(v2_receiver_keygen(&kgc, &pp, id_b, strlen(id_b), &receiver) == 1);
    assert(v2_compute_qb(&pp, id_b, strlen(id_b), &q_b) == 1);

    assert(sm9_z256_point_is_on_curve(&q_b) == 1);
    assert(sm9_z256_point_is_at_infinity(&q_b) == 0);
    assert(sm9_z256_point_is_on_curve(&receiver.X_b) == 1);
    assert(sm9_z256_point_is_at_infinity(&receiver.X_b) == 0);

    sm9_z256_point_mul(&expected_x_b, receiver.x_b, &q_b);
    assert(sm9_z256_point_equ(&expected_x_b, &receiver.X_b) == 1);

    sm9_z256_pairing(expected_g, sm9_z256_twist_generator(), &pp.Ppube);
    assert(sm9_z256_fp12_equ(expected_g, pp.g) == 1);

    v2_receiver_key_cleanup(&receiver);
    v2_kgc_cleanup(&kgc);
    return 1;
}

static int test_context_binding(void)
{
    V2_KGC kgc;
    V2_PUBLIC_PARAMS pp;
    V2_RECEIVER_KEY receiver;
    V2_RECEIVER_KEY receiver2;
    SM2_KEY sender1;
    SM2_KEY sender2;
    SM9_Z256_POINT q_b;
    SM9_Z256_POINT u1;
    SM9_Z256_POINT u2;
    sm9_z256_t two;
    uint8_t base[1024], changed[1024];
    size_t base_len = sizeof(base), changed_len = sizeof(changed);
    const uint8_t id_a[] = "Alice";
    const uint8_t id_a2[] = "Alice-2";
    const char *id_b = "Bob";
    const char *id_b2 = "Bob-2";

    assert(v2_setup(&kgc, &pp) == 1);
    assert(v2_receiver_keygen(&kgc, &pp, id_b, strlen(id_b), &receiver) == 1);
    assert(v2_receiver_keygen(&kgc, &pp, id_b2, strlen(id_b2), &receiver2) == 1);
    assert(sm2_key_generate(&sender1) == 1);
    assert(sm2_key_generate(&sender2) == 1);
    assert(v2_compute_qb(&pp, id_b, strlen(id_b), &q_b) == 1);

    sm9_z256_set_zero(two);
    two[0] = 2;
    sm9_z256_point_mul(&u1, two, &q_b);
    sm9_z256_point_dbl(&u2, &u1);

    assert(v2_encode_context(id_a, sizeof(id_a) - 1, &sender1,
        id_b, strlen(id_b), &receiver.X_b, &u1, base, &base_len) == 1);

    changed_len = sizeof(changed);
    assert(v2_encode_context(id_a2, sizeof(id_a2) - 1, &sender1,
        id_b, strlen(id_b), &receiver.X_b, &u1, changed, &changed_len) == 1);
    assert_distinct_context(base, base_len, changed, changed_len);

    changed_len = sizeof(changed);
    assert(v2_encode_context(id_a, sizeof(id_a) - 1, &sender2,
        id_b, strlen(id_b), &receiver.X_b, &u1, changed, &changed_len) == 1);
    assert_distinct_context(base, base_len, changed, changed_len);

    changed_len = sizeof(changed);
    assert(v2_encode_context(id_a, sizeof(id_a) - 1, &sender1,
        id_b2, strlen(id_b2), &receiver.X_b, &u1, changed, &changed_len) == 1);
    assert_distinct_context(base, base_len, changed, changed_len);

    changed_len = sizeof(changed);
    assert(v2_encode_context(id_a, sizeof(id_a) - 1, &sender1,
        id_b, strlen(id_b), &receiver2.X_b, &u1, changed, &changed_len) == 1);
    assert_distinct_context(base, base_len, changed, changed_len);

    changed_len = sizeof(changed);
    assert(v2_encode_context(id_a, sizeof(id_a) - 1, &sender1,
        id_b, strlen(id_b), &receiver.X_b, &u2, changed, &changed_len) == 1);
    assert_distinct_context(base, base_len, changed, changed_len);

    v2_receiver_key_cleanup(&receiver2);
    v2_receiver_key_cleanup(&receiver);
    v2_kgc_cleanup(&kgc);
    return 1;
}

int main(void)
{
    assert(test_setup_and_receiver_keygen() == 1);
    assert(test_context_binding() == 1);
    puts("test_v2: ok");
    return 0;
}
