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
#include <pchs_liu2018.h>

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
    return (uint64_t)((long double)counter.QuadPart * 1000000000.0L
        / (long double)freq.QuadPart);
#else
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0;
    }
    return (uint64_t)ts.tv_sec * UINT64_C(1000000000)
        + (uint64_t)ts.tv_nsec;
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
    if (errno || !end || *end != '\0'
        || value > (unsigned long long)SIZE_MAX) {
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
        if (fprintf(fp,
            "run_id,commit,gmssl_commit,message_bytes,phase,iteration,ns\n") < 0) {
            fclose(fp);
            return NULL;
        }
    }
    return fp;
}

static int row(
    FILE *fp,
    const OPTIONS *opt,
    const char *phase,
    unsigned iteration,
    uint64_t ns)
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

static int warmup_roundtrips(
    const PCHS_PUBLIC_PARAMS *pp,
    const PCHS_PKI_KEY *sender,
    const PCHS_CLC_KEY *receiver,
    const uint8_t *message,
    size_t message_len,
    unsigned count)
{
    uint8_t *out = malloc(message_len ? message_len : 1);
    unsigned i;

    if (!out) {
        return 0;
    }
    for (i = 0; i < count; i++) {
        PCHS_CIPHERTEXT ct;
        size_t outlen = message_len;
        pchs_ciphertext_init(&ct);
        if (pchs_signcrypt(pp, sender, receiver,
                message, message_len, &ct) != PCHS_OK
            || pchs_unsigncrypt(pp, sender, receiver,
                &ct, out, &outlen) != PCHS_OK
            || outlen != message_len
            || (message_len && memcmp(message, out, message_len) != 0)) {
            pchs_ciphertext_cleanup(&ct);
            gmssl_secure_clear(out, message_len ? message_len : 1);
            free(out);
            return 0;
        }
        pchs_ciphertext_cleanup(&ct);
    }
    gmssl_secure_clear(out, message_len ? message_len : 1);
    free(out);
    return 1;
}

int main(int argc, char **argv)
{
    OPTIONS opt;
    PCHS_MASTER_KEY msk;
    PCHS_PUBLIC_PARAMS pp;
    PCHS_PKI_KEY sender;
    PCHS_CLC_KEY receiver;
    static const uint8_t id_b[] = "Bob";
    uint8_t *message = NULL;
    uint8_t *out = NULL;
    FILE *fp = NULL;
    unsigned i;
    int exit_code = 1;

    memset(&msk, 0, sizeof(msk));
    memset(&pp, 0, sizeof(pp));
    memset(&sender, 0, sizeof(sender));
    memset(&receiver, 0, sizeof(receiver));

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

    if (pchs_setup(&msk, &pp) != PCHS_OK
        || pchs_pki_keygen(&sender) != PCHS_OK
        || pchs_clc_keygen(&msk, &pp,
            id_b, sizeof(id_b) - 1, &receiver) != PCHS_OK) {
        fprintf(stderr, "PCHS setup/key generation failure\n");
        goto end;
    }

    if (!warmup_roundtrips(&pp, &sender, &receiver,
            message, opt.message_bytes, opt.warmup)) {
        fprintf(stderr, "PCHS warmup/correctness failure\n");
        goto end;
    }

    fp = open_raw(&opt);
    if (!fp) {
        fprintf(stderr, "unable to open raw CSV\n");
        goto end;
    }

    for (i = 0; i < opt.iterations; i++) {
        PCHS_CIPHERTEXT ct;
        size_t outlen = opt.message_bytes;
        uint64_t t0;
        uint64_t t1;

        pchs_ciphertext_init(&ct);

        t0 = now_ns();
        if (pchs_signcrypt(&pp, &sender, &receiver,
                message, opt.message_bytes, &ct) != PCHS_OK) {
            fprintf(stderr, "PCHS signcrypt failure at iteration %u\n", i);
            pchs_ciphertext_cleanup(&ct);
            goto end;
        }
        t1 = now_ns();
        if (t1 < t0
            || !row(fp, &opt, "pchs_sender_signcrypt", i, t1 - t0)) {
            pchs_ciphertext_cleanup(&ct);
            goto end;
        }

        t0 = now_ns();
        if (pchs_unsigncrypt(&pp, &sender, &receiver,
                &ct, out, &outlen) != PCHS_OK) {
            fprintf(stderr, "PCHS unsigncrypt failure at iteration %u\n", i);
            pchs_ciphertext_cleanup(&ct);
            goto end;
        }
        t1 = now_ns();
        if (t1 < t0
            || !row(fp, &opt, "pchs_unsigncrypt", i, t1 - t0)) {
            pchs_ciphertext_cleanup(&ct);
            goto end;
        }

        if (outlen != opt.message_bytes
            || (opt.message_bytes
                && memcmp(message, out, opt.message_bytes) != 0)) {
            fprintf(stderr, "PCHS correctness failure at iteration %u\n", i);
            pchs_ciphertext_cleanup(&ct);
            goto end;
        }
        pchs_ciphertext_cleanup(&ct);
    }

    if (fflush(fp) != 0) {
        goto end;
    }
    exit_code = 0;

end:
    if (fp) {
        fclose(fp);
    }
    pchs_clc_key_cleanup(&receiver);
    pchs_pki_key_cleanup(&sender);
    pchs_master_key_cleanup(&msk);
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
