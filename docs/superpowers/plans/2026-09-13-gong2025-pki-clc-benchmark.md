# Gong 2025 PKI→CLC Benchmark Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a faithful native-C same-platform reimplementation and benchmark of the PKI→CLC branch of Gong et al. 2025, without modifying V2/PCHS cryptographic code or frozen evidence.

**Architecture:** Add one isolated `gong2025_pki_clc` static library beside `pchs_liu2018`, one test binary, one benchmark binary, and Gong-specific statistics/Windows runner scripts. Use GmSSL low-level SM2 group operations to instantiate Gong's abstract prime-order additive group and preserve the paper's explicit PKI→CLC path (`2A+3M` signcrypt, `A+3M` unsigncrypt) rather than algebraically simplifying it.

**Tech Stack:** C11, GmSSL pinned commit `24ae482701a7b124826c382fffc55c19f76d475d`, SM2 low-level group API, SM3/SM3-KDF, CMake/Ninja, Python 3, PowerShell, GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-09-13-gong2025-pki-clc-benchmark-design.md`

## Global Constraints

- Branch: `benchmark-gong2025-pki-clc`, based on stable PCHS commit `f937d244dfc01e0f73853225f138191a2d9a86ab`.
- Do not modify `native/src/v2_*`, `native/src/pchs_liu2018.c`, PCHS tests/benchmarks, or any frozen evidence artifact.
- Gong source is DOI `10.1109/TNSE.2025.3571867`.
- PKI public key must remain `P_S=[x_S^{-1}]P`.
- CLC keys must remain `P_R=[x_R]P`, `R_R=[r_R]P`, `h_R=H1(ID_R,R_R,P_R)`, `d_R=r_R+s*h_R`, `X_R=[h_R^{-1}]R_R`.
- PKI→CLC `h4` inputs are exactly `ID_S, ID_R, P_S, P_R, R_R, X_R, P_pub, c, T1` with unambiguous length-prefix encoding.
- Signcrypt must execute the paper path `B_R=[h_R^{-1}]P_R + X_R + P_pub`, `z=a*h_R*x_S^{-1}`, `T2=[z]B_R`; do not replace it with an algebraically shortened equivalent.
- Unsigncrypt must execute `T1'=[S]P_S-[h]P`, verify `T1'=T1`, then `T2'=[x_R+d_R]T1'`.
- Official Windows benchmark: Ryzen 7 8845H, GCC 16.2.0, Release, QueryPerformanceCounter, warmup=1000, iterations=1000, message sizes 20/128/1024/4096 B.
- Official raw phases: `gong2025_sender_signcrypt`, `gong2025_unsigncrypt`; total expected Gong samples = 8000.

---

### Task 1: Define Gong API and RED algebra/round-trip tests

**Files:**
- Create: `native/include/gong2025_pki_clc.h`
- Create: `native/tests/test_gong2025_pki_clc.c`
- Modify: `native/CMakeLists.txt`

**Interfaces:**
- Produces `GONG2025_MASTER_KEY`, `GONG2025_PUBLIC_PARAMS`, `GONG2025_PKI_KEY`, `GONG2025_CLC_KEY`, `GONG2025_CIPHERTEXT` and the functions `gong2025_setup`, `gong2025_pki_keygen`, `gong2025_clc_keygen`, `gong2025_signcrypt`, `gong2025_unsigncrypt`, plus cleanup/init functions.
- The test must use only the public API for round-trip and use GmSSL group operations independently to verify the algebraic identities.

- [ ] **Step 1: Create the public header only, without implementation**

Use structs with scalar/point fields sufficient to represent the paper values:

```c
typedef struct { sm2_z256_t s; } GONG2025_MASTER_KEY;
typedef struct { SM2_Z256_POINT P_pub; } GONG2025_PUBLIC_PARAMS;
typedef struct {
    sm2_z256_t x_s;
    sm2_z256_t x_s_inv;
    SM2_Z256_POINT P_s;
} GONG2025_PKI_KEY;
typedef struct {
    sm2_z256_t x_r;
    sm2_z256_t r_r;
    sm2_z256_t d_r;
    sm2_z256_t h_r;
    SM2_Z256_POINT P_r;
    SM2_Z256_POINT R_r;
    SM2_Z256_POINT X_r;
} GONG2025_CLC_KEY;
typedef struct {
    uint8_t *c;
    size_t c_len;
    sm2_z256_t S;
    SM2_Z256_POINT T1;
} GONG2025_CIPHERTEXT;
```

- [ ] **Step 2: Write the failing test for sizes 0, 1, 20, 128, 1024, 4096**

The test must call setup/keygen/signcrypt/unsigncrypt and assert message equality. It must also independently verify:

```c
[d_r]P == R_r + [h_r]P_pub
T1_prime == T1
T2_prime == T2
```

For `T2`, reproduce the *paper path* in the test: compute `h_r_inv`, `h_r_inv * P_r`, add `X_r`, add `P_pub`, compute `z=a*h_r*x_s_inv` only through a debug/test hook returned by signcrypt, or expose a narrow test-only trace struct under `#ifdef GONG2025_TESTING`. Do not infer `T2` using the receiver shortcut.

- [ ] **Step 3: Add a CMake target and run RED**

Add `test_gong2025_pki_clc` linking a not-yet-created `gong2025_pki_clc` library target. Expected CI/local result: build fails specifically because `native/src/gong2025_pki_clc.c`/symbols are not implemented, while existing V2/PCHS sources are untouched.

- [ ] **Step 4: Commit the RED contract**

Commit message: `test: define Gong 2025 PKI-CLC benchmark contract`.

---

### Task 2: Implement faithful Gong 2025 PKI→CLC core and tamper rejection

**Files:**
- Create: `native/src/gong2025_pki_clc.c`
- Modify: `native/tests/test_gong2025_pki_clc.c`
- Modify: `native/CMakeLists.txt`

**Interfaces:**
- Consumes the Task 1 public API.
- Produces a single implementation path used by both tests and benchmark.

- [ ] **Step 1: Implement scalar/point validation and hash encodings**

Use nonzero scalar rejection sampling; validate points are on-curve and non-infinity. Encode every point as 65-byte uncompressed octets. Encode variable-length identities/ciphertext fields with explicit 64-bit big-endian lengths before bytes. Define independent domains, e.g. `GONG2025-H1`, `GONG2025-H2`, `GONG2025-H4-PKI-CLC`.

- [ ] **Step 2: Implement Setup and key generation**

Implement:

```text
P_pub=[s]P
P_s=[x_s^-1]P
P_r=[x_r]P
R_r=[r_r]P
h_r=H1(ID_R,R_r,P_r)
d_r=r_r+s*h_r mod q
X_r=[h_r^-1]R_r
```

Resample if any required nonzero scalar/denominator becomes zero.

- [ ] **Step 3: Implement Signcrypt exactly as Gong PKI→CLC**

```text
a <- Zq*
T1=[a]P_s
h_r=H1(ID_R,R_r,P_r)
B_R=[h_r^-1]P_r + X_r + P_pub
z=a*h_r*x_s^-1 mod q
T2=[z]B_R
c=m XOR KDF(T2)
h=H4(ID_S,ID_R,P_s,P_r,R_r,X_r,P_pub,c,T1)
S=a+h*x_s mod q
sigma=(c,S,T1)
```

The implementation must actually perform both point additions in `B_R` and the explicit point multiplication of `[h_r^-1]P_r`.

- [ ] **Step 4: Implement Unsigncrypt exactly as Gong**

```text
h=H4(...)
T1_prime=[S]P_s-[h]P
reject unless T1_prime==T1
T2_prime=[x_r+d_r]T1_prime
m=c XOR KDF(T2_prime)
```

- [ ] **Step 5: Make the round-trip/algebra tests GREEN**

Run all native tests. Existing V2 and PCHS tests must still pass.

- [ ] **Step 6: Add negative tests**

Create independent copies and mutate one item at a time: `c`, `S`, `T1`, sender `P_s`, receiver `x_r`, `P_r`, `R_r`, `X_r`. Every mutation must make `gong2025_unsigncrypt` return error; zero-length `c` is tested by mutating `S/T1/keys` instead of indexing `c[0]`.

- [ ] **Step 7: Commit**

Commit message: `feat: implement Gong 2025 PKI-CLC signcryption`.

---

### Task 3: Add benchmark, raw statistics, and V2 comparison

**Files:**
- Create: `native/bench/bench_gong2025_pki_clc.c`
- Create: `scripts/summarize_gong2025.py`
- Create: `scripts/compare_v2_gong2025.py`
- Modify: `native/CMakeLists.txt`

**Interfaces:**
- Benchmark CLI matches PCHS shape: `--run-id --commit --gmssl-commit --message-bytes --warmup --iterations --raw`.
- Raw header remains `run_id,commit,gmssl_commit,message_bytes,phase,iteration,ns`.

- [ ] **Step 1: Add a failing benchmark smoke test**

CMake command must request 20 B, warmup 0, iterations 1 and write a temporary CSV. Expected RED before benchmark source exists.

- [ ] **Step 2: Implement benchmark using the exact core API**

Warmup executes full round-trips. Timed loop measures `gong2025_signcrypt` and `gong2025_unsigncrypt` separately with QueryPerformanceCounter on Windows / CLOCK_MONOTONIC elsewhere. After timing, verify recovered bytes equal the input. Append phases exactly:

```text
gong2025_sender_signcrypt
gong2025_unsigncrypt
```

- [ ] **Step 3: Implement deterministic summary script**

Validate expected sizes and n per group. Emit `message_bytes,phase,n,mean_ns,median_ns,stdev_ns,p95_ns`; sample standard deviation; nearest-rank P95. Include a `--self-test` path with deterministic synthetic data.

- [ ] **Step 4: Implement V2/Gong comparison script**

Require the V2 and Gong rows to share the same `gmssl_commit`. For each message size calculate:

```text
v2_online_ms
v2_sender_total_ms
v2_unsigncrypt_ms
gong_signcrypt_ms
gong_unsigncrypt_ms
online_reduction_pct
sender_total_delta_pct
unsigncrypt_delta_pct
```

Use means from raw CSV, not precomputed report text. Include `--self-test` with exact expected percentages.

- [ ] **Step 5: Run native smoke + Python self-tests GREEN and commit**

Commit message: `bench: add Gong 2025 same-platform benchmark`.

---

### Task 4: Add formal Windows runner, reproducibility docs, and CI

**Files:**
- Create: `scripts/run_gong2025_windows.ps1`
- Create: `docs/benchmark/GONG2025_PKI_CLC_REPRODUCTION.md`
- Modify: `.gitignore`
- Modify: `.github/workflows/pchs-ci.yml` or create a Gong-specific workflow if clearer.

**Interfaces:**
- Formal runner creates `artifacts/gong2025-pki-clc-ryzen8845h-YYYYMMDD-HHMMSS/` and never overwrites.
- Inputs: mandatory `-GmsslRoot`; optional `-V2Raw`; defaults Warmup/Iterations=1000; pinned GmSSL commit.

- [ ] **Step 1: Implement runner preflight**

Require GmSSL headers, Git checkout, clean worktree, and resolve build directory `native/build-gong2025-pki-clc`. Configure `Release`, build, run `ctest`, then benchmark 20/128/1024/4096.

- [ ] **Step 2: Write environment.json**

Record `implementation=gong2025_pki_clc`, DOI, Gong source commit, GmSSL commit/root, CPU/OS, logical processors, cmake/ninja/compiler/python text, warmup/iterations, raw/summary paths, and clean-tree status.

- [ ] **Step 3: Add comparison invocation and final paths**

If `-V2Raw` is supplied, invoke `compare_v2_gong2025.py` and emit `comparison.csv`.

- [ ] **Step 4: Document the exact paper mapping**

Reproduction doc must state the source equations, Table IV `2A+3M / A+3M`, adapted SM2-group instantiation, hash/KDF instantiation, lack of equivalent PKI→CLC Type-I/II proof, and fairness limitations.

- [ ] **Step 5: Extend CI**

Pinned GmSSL build → native configure/build → all ctests → both Gong Python self-tests → PowerShell parser check. Do not treat CI timings as paper evidence.

- [ ] **Step 6: Commit**

Commit message: `ci: validate Gong 2025 benchmark workflow`.

---

### Task 5: Final audit before user-local formal run

**Files:**
- Review all changed files; no new algorithm files unless fixing findings.

- [ ] **Step 1: Compare branch against `benchmark-liu2018-pchs`**

Confirm no changes under `native/src/v2_*`, PCHS source/test/bench, or existing artifacts.

- [ ] **Step 2: Audit paper-faithfulness**

Trace every PKI→CLC line to Gong 2025 equations: `P_s=x_s^-1P`, CLC key equations, `T1`, explicit `B_R`, `T2`, exact h4 fields, `S`, `T1'`, `T2'`. Reject any algebraic optimization that changes operation counts.

- [ ] **Step 3: Audit benchmark/evidence semantics**

Confirm official group count will be 8 groups × 1000 = 8000, no outlier filtering, same GmSSL commit enforcement, and all unfavorable deltas are emitted.

- [ ] **Step 4: Require CI success on branch head**

Only after CI success may provide the user with the Windows clone/update and formal-run commands. The result is still not a paper performance claim until the user's Ryzen 7 8845H run produces complete raw data.

- [ ] **Step 5: Final commit if audit fixes were needed**

Use a narrowly descriptive message; otherwise do not create a no-op commit.
