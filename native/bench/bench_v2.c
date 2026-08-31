#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <time.h>
#endif

#include <gmssl/mem.h>
#include <gmssl/sm2_z256.h>
#include <gmssl/sm9_z256.h>
#include <v2_scheme.h>

typedef struct {
    const char *run_id;
    const char *commit;
    const char *gmssl_commit;
    const char *raw_path;
    size_t message_bytes;
    unsigned warmup;
    unsigned iterations;
} OPTIONS;

static uint64_t now_ns(void)
{
#ifdef _WIN32
    LARGE_INTEGER counter;
    LARGE_INTEGER freq;
    QueryPerformanceCounter(&counter);
    QueryPerformanceFrequency(&freq);
    return (uint64_t)((long double)counter.QuadPart * 1000000000.0L / (long double)freq.QuadPart);
#else
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0;
    }
    return (uint64_t)ts.tv_sec * UINT64_C(1000000000) + (uint64_t)ts.tv_nsec;
#endif
}

static int safe_csv_atom(const char *s)
{
    return s && *s && !strchr(s, ',') && !strchr(s, '\n') && !strchr(s, '\r');
}

static int parse_unsigned(const char *s, unsigned *out)
{
    char *end = NULL;
    unsigned long value;

    if (!s || !out || *s == '-') {
        return 0;
    }
    errno = 0;
    value = strtoul(s, &end, 10);
    if (errno || !end || *end != '\0' || value > UINT32_MAX) {
        return 0;
    }
    *out = (unsigned)value;
    return 1;
}

static int parse_size(const char *s, size_t *out)
{
    char *end = NULL;
    unsigned long long value;

    if (!s || !out || *s == '-') {
        return 0;
    }
    errno = 0;
    value = strtoull(s, &end, 10);
    if (errno || !end || *end != '\0' || value > (unsigned long long)SIZE_MAX) {
        return 0;
    }
    *out = (size_t)value;
    return 1;
}

static int parse_options(int argc, char **argv, OPTIONS *opt)
{
    int i;
    memset(opt, 0, sizeof(*opt));
    opt->message_bytes = 128;
    opt->warmup = 100;
    opt->iterations = 1000;

    for (i = 1; i < argc; i++) {
        if (i + 1 >= argc) {
            return 0;
        }
        if (strcmp(argv[i], "--run-id") == 0) {
            opt->run_id = argv[++i];
        } else if (strcmp(argv[i], "--commit") == 0) {
            opt->commit = argv[++i];
        } else if (strcmp(argv[i], "--gmssl-commit") == 0) {
            opt->gmssl_commit = argv[++i];
        } else if (strcmp(argv[i], "--message-bytes") == 0) {
            if (!parse_size(argv[++i], &opt->message_bytes)) return 0;
        } else if (strcmp(argv[i], "--warmup") == 0) {
            if (!parse_unsigned(argv[++i], &opt->warmup)) return 0;
        } else if (strcmp(argv[i], "--iterations") == 0) {
            if (!parse_unsigned(argv[++i], &opt->iterations)) return 0;
        } else if (strcmp(argv[i], "--raw") == 0) {
            opt->raw_path = argv[++i];
        } else {
            return 0;
        }
    }
    return safe_csv_atom(opt->run_id)
        && safe_csv_atom(opt->commit)
        && safe_csv_atom(opt->gmssl_commit)
        && opt->raw_path && *opt->raw_path
        && opt->iterations > 0;
}

static int file_nonempty(const char *path)
{
    FILE *fp = fopen(path, "rb");
    long size;
    if (!fp) {
        return 0;
    }
    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return 0;
    }
    size = ftell(fp);
    fclose(fp);
    return size > 0;
}

static FILE *open_raw(const OPTIONS *opt)
{
    int has_header = file_nonempty(opt->raw_path);
    FILE *fp = fopen(opt->raw_path, "ab");
    if (!fp) {
        return NULL;
    }
    if (!has_header) {
        if (fprintf(fp, "run_id,commit,gmssl_commit,message_bytes,phase,iteration,ns\n") < 0) {
            fclose(fp);
            return NULL;
        }
    }
    return fp;
}

static int row(FILE *fp, const OPTIONS *opt, const char *phase, unsigned iteration, uint64_t ns)
{
    return fprintf(fp, "%s,%s,%s,%zu,%s,%u,%" PRIu64 "\n",
        opt->run_id, opt->commit, opt->gmssl_commit,
        opt->message_bytes, phase, iteration, ns) > 0;
}

static void fill_message(uint8_t *message, size_t len)
{
    size_t i;
    for (i = 0; i < len; i++) {
        message[i] = (uint8_t)((i * 193u + len * 17u + 11u) & 0xffu);
    }
}

static int scalar_nonzero_sm9(sm9_z256_t k)
{
    do {
        if (sm9_z256_rand_range(k, sm9_z256_order()) != 1) {
            return 0;
        }
    } while (sm9_z256_is_zero(k));
    return 1;
}

static int scalar_nonzero_sm2(sm2_z256_t k)
{
    do {
        if (sm2_z256_rand_range(k, sm2_z256_order()) != 1) {
            return 0;
        }
    } while (sm2_z256_is_zero(k));
    return 1;
}

static int protocol_warmup(
    const V2_PUBLIC_PARAMS *pp,
    const V2_SENDER_KEY *sender,
    const V2_RECEIVER_KEY *receiver,
    const uint8_t *message,
    size_t message_len,
    unsigned count)
{
    static const uint8_t id_a[] = "Alice";
    static const char id_b[] = "Bob";
    unsigned i;
    uint8_t *out = malloc(message_len ? message_len : 1);
    if (!out) return 0;

    for (i = 0; i < count; i++) {
        V2_OFFLINE_TOKEN token;
        V2_CIPHERTEXT ct;
        size_t outlen = message_len;
        v2_offline_token_init(&token);
        v2_ciphertext_init(&ct);
        if (v2_offline_signcrypt(pp, sender, id_a, sizeof(id_a) - 1,
                id_b, sizeof(id_b) - 1, &receiver->X_b, &token) != V2_OK
            || v2_online_signcrypt(sender, id_a, sizeof(id_a) - 1,
                id_b, sizeof(id_b) - 1, &token, message, message_len, &ct) != V2_OK
            || v2_unsigncrypt(pp, sender, id_a, sizeof(id_a) - 1,
                id_b, sizeof(id_b) - 1, receiver, &ct, out, &outlen) != V2_OK
            || outlen != message_len
            || (message_len && memcmp(message, out, message_len) != 0)) {
            v2_ciphertext_cleanup(&ct);
            v2_offline_token_cleanup(&token);
            gmssl_secure_clear(out, message_len ? message_len : 1);
            free(out);
            return 0;
        }
        v2_ciphertext_cleanup(&ct);
        v2_offline_token_cleanup(&token);
    }
    gmssl_secure_clear(out, message_len ? message_len : 1);
    free(out);
    return 1;
}

int main(int argc, char **argv)
{
    OPTIONS opt;
    V2_KGC kgc;
    V2_PUBLIC_PARAMS pp;
    V2_SENDER_KEY sender;
    V2_RECEIVER_KEY receiver;
    SM9_Z256_POINT q_b;
    sm9_z256_t sm9_scalar;
    sm2_z256_t sm2_scalar;
    uint8_t *message = NULL;
    uint8_t *out = NULL;
    FILE *fp = NULL;
    unsigned i;
    int exit_code = 1;
    static const uint8_t id_a[] = "Alice";
    static const char id_b[] = "Bob";

    if (!parse_options(argc, argv, &opt)) {
        fprintf(stderr, "invalid arguments\n");
        return 2;
    }
    message = malloc(opt.message_bytes ? opt.message_bytes : 1);
    out = malloc(opt.message_bytes ? opt.message_bytes : 1);
    if (!message || !out) {
        fprintf(stderr, "allocation failure\n");
        goto end;
    }
    fill_message(message, opt.message_bytes);

    if (v2_setup(&kgc, &pp) != V2_OK
        || v2_sender_keygen(&sender) != V2_OK
        || v2_receiver_keygen(&kgc, &pp, id_b, sizeof(id_b) - 1, &receiver) != V2_OK
        || v2_compute_qb(&pp, id_b, sizeof(id_b) - 1, &q_b) != V2_OK
        || !scalar_nonzero_sm9(sm9_scalar)
        || !scalar_nonzero_sm2(sm2_scalar)) {
        fprintf(stderr, "benchmark setup failure\n");
        goto end;
    }
    if (!protocol_warmup(&pp, &sender, &receiver, message, opt.message_bytes, opt.warmup)) {
        fprintf(stderr, "warmup correctness failure\n");
        goto end_keys;
    }
    fp = open_raw(&opt);
    if (!fp) {
        fprintf(stderr, "cannot open raw CSV: %s\n", opt.raw_path);
        goto end_keys;
    }

    for (i = 0; i < opt.iterations; i++) {
        V2_RECEIVER_KEY tmp_receiver;
        V2_OFFLINE_TOKEN token;
        V2_OFFLINE_TOKEN total_token;
        V2_CIPHERTEXT ct;
        V2_CIPHERTEXT total_ct;
        SM2_Z256_POINT sm2_point;
        SM9_Z256_POINT sm9_point;
        sm9_z256_fp12_t gt;
        size_t outlen = opt.message_bytes;
        uint64_t t0, t1;

        v2_offline_token_init(&token);
        v2_offline_token_init(&total_token);
        v2_ciphertext_init(&ct);
        v2_ciphertext_init(&total_ct);
        memset(&tmp_receiver, 0, sizeof(tmp_receiver));

        t0 = now_ns();
        if (v2_receiver_keygen(&kgc, &pp, id_b, sizeof(id_b) - 1, &tmp_receiver) != V2_OK) goto iteration_error;
        t1 = now_ns();
        if (!row(fp, &opt, "receiver_keygen", i, t1 - t0)) goto iteration_error;
        v2_receiver_key_cleanup(&tmp_receiver);

        t0 = now_ns();
        if (v2_offline_signcrypt(&pp, &sender, id_a, sizeof(id_a) - 1,
                id_b, sizeof(id_b) - 1, &receiver.X_b, &token) != V2_OK) goto iteration_error;
        t1 = now_ns();
        if (!row(fp, &opt, "offline_signcrypt", i, t1 - t0)) goto iteration_error;

        t0 = now_ns();
        if (v2_online_signcrypt(&sender, id_a, sizeof(id_a) - 1,
                id_b, sizeof(id_b) - 1, &token, message, opt.message_bytes, &ct) != V2_OK) goto iteration_error;
        t1 = now_ns();
        if (!row(fp, &opt, "online_signcrypt", i, t1 - t0)) goto iteration_error;

        t0 = now_ns();
        if (v2_offline_signcrypt(&pp, &sender, id_a, sizeof(id_a) - 1,
                id_b, sizeof(id_b) - 1, &receiver.X_b, &total_token) != V2_OK
            || v2_online_signcrypt(&sender, id_a, sizeof(id_a) - 1,
                id_b, sizeof(id_b) - 1, &total_token, message, opt.message_bytes, &total_ct) != V2_OK) goto iteration_error;
        t1 = now_ns();
        if (!row(fp, &opt, "sender_total", i, t1 - t0)) goto iteration_error;

        t0 = now_ns();
        if (v2_unsigncrypt(&pp, &sender, id_a, sizeof(id_a) - 1,
                id_b, sizeof(id_b) - 1, &receiver, &ct, out, &outlen) != V2_OK) goto iteration_error;
        t1 = now_ns();
        if (outlen != opt.message_bytes || (opt.message_bytes && memcmp(message, out, opt.message_bytes) != 0)) goto iteration_error;
        if (!row(fp, &opt, "unsigncrypt", i, t1 - t0)) goto iteration_error;

        t0 = now_ns();
        sm2_z256_point_mul_generator(&sm2_point, sm2_scalar);
        t1 = now_ns();
        if (!row(fp, &opt, "sm2_fixed_base_mul", i, t1 - t0)) goto iteration_error;

        t0 = now_ns();
        sm9_z256_point_mul(&sm9_point, sm9_scalar, &q_b);
        t1 = now_ns();
        if (!row(fp, &opt, "sm9_g1_mul", i, t1 - t0)) goto iteration_error;

        t0 = now_ns();
        sm9_z256_pairing(gt, &receiver.identity_key.de, &ct.U);
        t1 = now_ns();
        if (!row(fp, &opt, "sm9_pairing", i, t1 - t0)) goto iteration_error;

        t0 = now_ns();
        sm9_z256_fp12_pow(gt, pp.g, sm9_scalar);
        t1 = now_ns();
        if (!row(fp, &opt, "sm9_gt_exp", i, t1 - t0)) goto iteration_error;

        v2_ciphertext_cleanup(&total_ct);
        v2_ciphertext_cleanup(&ct);
        v2_offline_token_cleanup(&total_token);
        v2_offline_token_cleanup(&token);
        gmssl_secure_clear(&sm2_point, sizeof(sm2_point));
        gmssl_secure_clear(&sm9_point, sizeof(sm9_point));
        gmssl_secure_clear(gt, sizeof(gt));
        continue;

iteration_error:
        fprintf(stderr, "benchmark correctness/write failure at iteration %u\n", i);
        v2_receiver_key_cleanup(&tmp_receiver);
        v2_ciphertext_cleanup(&total_ct);
        v2_ciphertext_cleanup(&ct);
        v2_offline_token_cleanup(&total_token);
        v2_offline_token_cleanup(&token);
        gmssl_secure_clear(&sm2_point, sizeof(sm2_point));
        gmssl_secure_clear(&sm9_point, sizeof(sm9_point));
        gmssl_secure_clear(gt, sizeof(gt));
        goto end_fp;
    }
    if (fflush(fp) != 0) {
        fprintf(stderr, "raw CSV flush failure\n");
        goto end_fp;
    }
    exit_code = 0;

end_fp:
    fclose(fp);
end_keys:
    v2_receiver_key_cleanup(&receiver);
    v2_sender_key_cleanup(&sender);
    v2_kgc_cleanup(&kgc);
    gmssl_secure_clear(sm9_scalar, sizeof(sm9_scalar));
    gmssl_secure_clear(sm2_scalar, sizeof(sm2_scalar));
end:
    if (out) {
        gmssl_secure_clear(out, opt.message_bytes ? opt.message_bytes : 1);
        free(out);
    }
    if (message) {
        gmssl_secure_clear(message, opt.message_bytes ? opt.message_bytes : 1);
        free(message);
    }
    return exit_code;
}
