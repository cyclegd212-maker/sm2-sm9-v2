# Liu 2018 PCHS Benchmark Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 在现有 V2 native/GmSSL 工程中新增一个独立的 Liu et al. 2018 PCHS（PKI→CLC）忠实实现与同机 benchmark，并生成可与 2026-09-09 V2 正式数据公平比较的原始计时结果。

**Architecture:** PCHS 作为独立静态库 target 实现，不修改 V2 算法路径。先用单元测试锁定论文中的密钥关系、Signcrypt/Unsigncrypt 正确性和篡改拒绝，再新增独立 benchmark 和 Windows 运行脚本；比较脚本只消费 raw CSV，不手工录入毫秒数。

**Tech Stack:** C11, GmSSL commit `24ae482701a7b124826c382fffc55c19f76d475d`, CMake, MSYS2 UCRT64 GCC, Python 3.13 for CSV statistics, Windows QueryPerformanceCounter.

**Spec:** `docs/superpowers/specs/2026-09-12-liu2018-pchs-benchmark-design.md`

## Global Constraints

- 基线源码分支从 V2 commit `aab3316ea1a53146d4b24821b8ee3998e1b950c1` 派生。
- 不修改或覆盖 `artifacts/ryzen8845h-ieee-20260909-152244/`。
- PCHS 第一轮必须忠实实现 Liu 2018 原文，不增加 online/offline 改造。
- 使用 SM2 256-bit 曲线作为论文抽象群 G 的具体实例；在论文中必须标记为工程实例化。
- `H1/H2` 使用 SM3 + domain separation 后归约到非零 SM2 标量；`H3` 使用 SM3-KDF 输出消息等长掩码。
- 所有点哈希输入使用规范编码，禁止直接哈希 C 结构体内存。
- Windows 正式 benchmark：warmup=1000，iterations=1000，消息长度 20/128/1024/4096 B。
- 没有 Ryzen 7 8845H 原始样本时不得生成跨方案性能提升百分比。

---

### Task 1: 定义 PCHS API 并锁定论文代数关系

**Files:**
- Create: `native/include/pchs_liu2018.h`
- Create: `native/tests/test_pchs_liu2018.c`
- Modify: `native/CMakeLists.txt`

**Interfaces:**
- Produces:
  - `int pchs_setup(PCHS_MASTER_KEY *, PCHS_PUBLIC_PARAMS *)`
  - `int pchs_pki_keygen(PCHS_PKI_KEY *)`
  - `int pchs_clc_keygen(const PCHS_MASTER_KEY *, const PCHS_PUBLIC_PARAMS *, const uint8_t *, size_t, PCHS_CLC_KEY *)`
  - `int pchs_signcrypt(const PCHS_PUBLIC_PARAMS *, const PCHS_PKI_KEY *, const PCHS_CLC_KEY *, const uint8_t *, size_t, PCHS_CIPHERTEXT *)`
  - `int pchs_unsigncrypt(const PCHS_PUBLIC_PARAMS *, const PCHS_PKI_KEY *, const PCHS_CLC_KEY *, const PCHS_CIPHERTEXT *, uint8_t *, size_t *)`
  - cleanup/init helpers.

- [ ] **Step 1: Write the failing public API test**

Create `native/tests/test_pchs_liu2018.c` with a compile-time/roundtrip skeleton that includes the new header and calls the API for message sizes `0,1,20,128,1024,4096`.

```c
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pchs_liu2018.h>

#define CHECK(x) do { if (!(x)) { \
    fprintf(stderr, "CHECK failed %s:%d: %s\n", __FILE__, __LINE__, #x); \
    return 0; \
} } while (0)

static int roundtrip(size_t n)
{
    PCHS_MASTER_KEY msk;
    PCHS_PUBLIC_PARAMS pp;
    PCHS_PKI_KEY sender;
    PCHS_CLC_KEY receiver;
    PCHS_CIPHERTEXT ct;
    uint8_t id[] = "Bob";
    uint8_t *m = calloc(n ? n : 1, 1);
    uint8_t *out = calloc(n ? n : 1, 1);
    size_t outlen = n;
    size_t i;
    CHECK(m && out);
    for (i = 0; i < n; i++) m[i] = (uint8_t)(i * 17u + n);
    CHECK(pchs_setup(&msk, &pp) == PCHS_OK);
    CHECK(pchs_pki_keygen(&sender) == PCHS_OK);
    CHECK(pchs_clc_keygen(&msk, &pp, id, sizeof(id)-1, &receiver) == PCHS_OK);
    pchs_ciphertext_init(&ct);
    CHECK(pchs_signcrypt(&pp, &sender, &receiver, m, n, &ct) == PCHS_OK);
    CHECK(pchs_unsigncrypt(&pp, &sender, &receiver, &ct, out, &outlen) == PCHS_OK);
    CHECK(outlen == n);
    CHECK(n == 0 || memcmp(m, out, n) == 0);
    pchs_ciphertext_cleanup(&ct);
    pchs_clc_key_cleanup(&receiver);
    pchs_pki_key_cleanup(&sender);
    pchs_master_key_cleanup(&msk);
    free(out); free(m);
    return 1;
}
```

- [ ] **Step 2: Add the test target and verify expected failure**

Modify `native/CMakeLists.txt` to add `test_pchs_liu2018` but do not yet add production source.

Run:

```bash
cmake --build build --target test_pchs_liu2018
```

Expected: compilation/link failure because `pchs_liu2018.h`/symbols are absent.

- [ ] **Step 3: Create the header with exact data types**

Use GmSSL low-level SM2 point/scalar types from public headers. The header must expose structures sufficient for tests and benchmark, but no V2 types.

Required logical fields:

```c
typedef struct { sm2_z256_t s; } PCHS_MASTER_KEY;
typedef struct { SM2_Z256_POINT P_pub; } PCHS_PUBLIC_PARAMS;
typedef struct { sm2_z256_t x_p; sm2_z256_t x_p_inv; SM2_Z256_POINT PK_p; } PCHS_PKI_KEY;
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
```

If exact GmSSL public type spelling differs, adapt to the actual installed public header while preserving these semantics.

- [ ] **Step 4: Run the test and confirm link failure only**

Expected: header compiles; linker reports undefined `pchs_*` functions.

- [ ] **Step 5: Commit**

```bash
git add native/include/pchs_liu2018.h native/tests/test_pchs_liu2018.c native/CMakeLists.txt
git commit -m "test: define Liu 2018 PCHS benchmark API"
```

---

### Task 2: Implement faithful PCHS setup/keygen/signcrypt/unsigncrypt

**Files:**
- Create: `native/src/pchs_liu2018.c`
- Modify: `native/CMakeLists.txt`
- Modify: `native/tests/test_pchs_liu2018.c`

**Interfaces:** consumes Task 1 header; produces working API.

- [ ] **Step 1: Add failing algebra-specific tests**

Extend the test to verify:

```text
[d]P == T + [gamma]P_pub
R1_recovered == [k]P
R2_recovered == [h]P
R1 == [h]P - [u]PK_p
```

Production API may expose a test-only trace structure under `#ifdef PCHS_TESTING` or provide an internal helper compiled only into the test target. Do not add benchmark-only overhead to release code.

- [ ] **Step 2: Verify the new tests fail**

Run `ctest -R pchs --output-on-failure`; expected FAIL because implementation is absent.

- [ ] **Step 3: Implement scalar helpers**

Implement internal helpers for:

- nonzero random scalar;
- modular add/sub/mul/inverse;
- SM3-to-nonzero-scalar reduction;
- canonical point encoding;
- SM3-KDF mask generation.

Domain labels must be exact constants, e.g.:

```c
static const uint8_t H1_DOMAIN[] = "LIU2018-PCHS-H1";
static const uint8_t H2_DOMAIN[] = "LIU2018-PCHS-H2";
static const uint8_t H3_DOMAIN[] = "LIU2018-PCHS-H3";
```

- [ ] **Step 4: Implement Setup, PKI-KG and CLC-KG**

Faithful equations:

```text
P_pub = [s]P
PK_p  = [x_p^{-1}]P
T     = [t]P
gamma = H1(ID,T)
d     = t + s*gamma mod q
PK_c1 = [x_c]P
```

Reject zero scalar results and retry random generation where required.

- [ ] **Step 5: Implement Signcrypt**

Faithful equations:

```text
R1 = [k]P
h  = H2(m,R1)
R2 = [h]P
c  = m XOR H3(R2)
u  = (h-k)*x_p mod q
V  = [k]PK_c1 + T + [gamma]P_pub
```

`PCHS_CIPHERTEXT.c` owns allocated memory and cleanup securely clears it.

- [ ] **Step 6: Implement Unsigncrypt**

Faithful equations:

```text
R1 = [x_c^{-1}](V - [d]P)
R2 = R1 + [u]PK_p
m  = c XOR H3(R2)
h  = H2(m,R1)
accept iff R1 == [h]P - [u]PK_p
```

Do not skip the final verification equation even though roundtrip would often recover the message.

- [ ] **Step 7: Run correctness tests**

Run:

```bash
ctest -R pchs --output-on-failure
```

Expected: PASS for all six message sizes and all algebraic checks.

- [ ] **Step 8: Add and run tamper tests**

For each valid ciphertext, independently mutate `c`, `u`, `V`, sender `PK_p`, receiver `x_c`, receiver `d`; `pchs_unsigncrypt` must not return `PCHS_OK` with the original message accepted.

- [ ] **Step 9: Run full native regression suite**

```bash
ctest --output-on-failure
```

Expected: all existing V2 tests plus PCHS tests pass.

- [ ] **Step 10: Commit**

```bash
git add native/src/pchs_liu2018.c native/tests/test_pchs_liu2018.c native/CMakeLists.txt
git commit -m "feat: implement Liu 2018 PKI-to-CLC PCHS"
```

---

### Task 3: Add raw-timing benchmark with the same Windows clock protocol

**Files:**
- Create: `native/bench/bench_pchs_liu2018.c`
- Modify: `native/CMakeLists.txt`

**Interfaces:** consumes PCHS API; produces append-only raw CSV rows.

- [ ] **Step 1: Write benchmark smoke test target first**

Add CTest invocation with `--warmup 0 --iterations 1 --message-bytes 20` writing to build-local CSV. Run before benchmark source exists and confirm target failure.

- [ ] **Step 2: Implement argument parser and CSV schema**

Required CLI:

```text
--run-id
--gmssl-commit
--message-bytes
--warmup
--iterations
--raw
```

CSV header:

```text
run_id,implementation,source_id,gmssl_commit,message_bytes,phase,iteration,ns
```

Constant fields:

```text
implementation=liu2018_pchs
source_id=doi:10.1109/ACCESS.2018.2797102
```

- [ ] **Step 3: Use the same timer family as V2**

On Windows use `QueryPerformanceCounter/QueryPerformanceFrequency`; POSIX fallback uses `clock_gettime(CLOCK_MONOTONIC)`.

- [ ] **Step 4: Implement warm-up**

Each warm-up iteration must execute full `Signcrypt -> Unsigncrypt -> compare message` and abort on correctness failure.

- [ ] **Step 5: Implement measured phases**

Per iteration, time independently:

```text
pchs_sender_signcrypt
pchs_unsigncrypt
```

Each measured ciphertext must still be correctness-checked before moving to the next iteration. Do not time file I/O inside the measured region.

- [ ] **Step 6: Run benchmark smoke test**

Expected: two data rows for one iteration at one message size, plus header; recovered message is correct.

- [ ] **Step 7: Run full regression**

`ctest --output-on-failure` must pass.

- [ ] **Step 8: Commit**

```bash
git add native/bench/bench_pchs_liu2018.c native/CMakeLists.txt
git commit -m "bench: add Liu 2018 PCHS raw timing harness"
```

---

### Task 4: Add Windows submission runner and statistics/comparison scripts

**Files:**
- Create: `scripts/run_pchs_liu2018_windows.ps1`
- Create: `scripts/summarize_pchs_liu2018.py`
- Create: `scripts/compare_v2_pchs.py`
- Create: `docs/benchmark/LIU2018_PCHS_REPRODUCTION.md`

**Interfaces:**
- Runner writes a new timestamped artifact directory.
- Summarizer converts raw CSV to summary CSV.
- Comparison script consumes existing V2 summary/raw and new PCHS summary/raw and writes a comparison CSV/Markdown report.

- [ ] **Step 1: Write failing parser/statistics tests as script self-tests**

`python scripts/summarize_pchs_liu2018.py --self-test` must exercise nearest-rank P95 and sample standard deviation on a fixed miniature dataset; before implementation it exits nonzero.

- [ ] **Step 2: Implement summarizer**

Group by `message_bytes,phase`; output:

```text
message_bytes,phase,n,mean_ns,median_ns,stdev_ns,p95_ns
```

No outlier deletion.

- [ ] **Step 3: Implement comparison script**

For each size 20/128/1024/4096, locate:

- V2 `online_signcrypt`
- V2 `sender_total`
- V2 `unsigncrypt`
- PCHS `pchs_sender_signcrypt`
- PCHS `pchs_unsigncrypt`

Compute:

```text
online_reduction_pct = (PCHS_signcrypt - V2_online) / PCHS_signcrypt * 100
sender_total_delta_pct = (V2_sender_total - PCHS_signcrypt) / PCHS_signcrypt * 100
unsigncrypt_delta_pct = (V2_unsigncrypt - PCHS_unsigncrypt) / PCHS_unsigncrypt * 100
```

If any required raw/summary group is absent or `n != 1000`, exit nonzero and do not print a performance claim.

- [ ] **Step 4: Implement Windows runner**

The script must:

1. require explicit `-BuildDir` and `-GmsslCommit`;
2. create a fresh timestamped artifact directory;
3. run `ctest` before timing;
4. run message sizes 20,128,1024,4096 with warmup=1000, iterations=1000;
5. write raw/summary/test log/benchmark log/environment JSON;
6. never touch `artifacts/ryzen8845h-ieee-20260909-152244`.

- [ ] **Step 5: Document exact local invocation**

`docs/benchmark/LIU2018_PCHS_REPRODUCTION.md` must give the user no more than three commands per checkpoint and state that percentages are invalid until the Ryzen artifact exists.

- [ ] **Step 6: Run self-tests and full native tests**

```bash
python scripts/summarize_pchs_liu2018.py --self-test
python scripts/compare_v2_pchs.py --self-test
ctest --output-on-failure
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add scripts/run_pchs_liu2018_windows.ps1 scripts/summarize_pchs_liu2018.py scripts/compare_v2_pchs.py docs/benchmark/LIU2018_PCHS_REPRODUCTION.md
git commit -m "bench: add reproducible Windows PCHS comparison workflow"
```

---

### Task 5: Reviewer-facing verification before asking for Ryzen benchmark

**Files:**
- Modify only if verification exposes a defect in files from Tasks 1-4.

- [ ] **Step 1: Verify formula-to-code mapping**

Create a checklist mapping every Liu 2018 PCHS formula to exact source function/statement. Confirm `PK_p=[x_p^{-1}]P` is not accidentally changed to `[x_p]P`.

- [ ] **Step 2: Verify no V2 production diff**

Compare branch against base commit and confirm existing `native/src/v2_*` and V2 benchmark logic are unchanged except CMake target registration.

- [ ] **Step 3: Run clean Release build and complete test suite**

Run from a fresh build directory against the pinned GmSSL prefix; capture terminal output.

- [ ] **Step 4: Verify benchmark smoke CSV**

Check schema, row count, nonzero timing, source DOI, GmSSL commit and exact phase names.

- [ ] **Step 5: Only then hand off Windows commands**

Do not calculate or state PCHS-vs-V2 percentage until the user's Ryzen 7 8845H raw CSV has been returned and validated.
