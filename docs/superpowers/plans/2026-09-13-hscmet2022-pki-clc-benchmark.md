# HSC-MET 2022 PKI→CLC Benchmark Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a faithful n=k=2 HSC-MET 2022 PKI→CLC native C implementation and same-machine benchmark without modifying the existing V2, Liu 2018, or Gong 2025 cryptographic implementations.

**Architecture:** Extend the existing native GmSSL benchmark tree with an isolated `hscmet2022` static library, tests, benchmark executable, statistics scripts, and a Windows evidence runner. Reuse the existing raw CSV schema and V2 comparison conventions. Preserve the paper’s MET fields in both signcryption and unsigncryption.

**Tech Stack:** C11, GmSSL pinned at `24ae482701a7b124826c382fffc55c19f76d475d`, CMake/Ninja, Python 3 statistics scripts, PowerShell Windows runner.

**Spec:** `docs/superpowers/specs/2026-09-13-hscmet2022-pki-clc-benchmark-design.md`

## Global Constraints

- Branch: `benchmark-hscmet2022-pki-clc`.
- Do not modify V2, Liu 2018 PCHS, or Gong 2025 cryptographic source files.
- Fix `n=2`, `k=2`.
- Use SM2 group, canonical 65-byte point encoding, 32-byte scalar encoding.
- Benchmark phases: `hscmet2022_sender_signcrypt`, `hscmet2022_unsigncrypt`.
- Formal local run: 20/128/1024/4096 B, warmup=1000, iterations=1000, total raw=8000.
- Cross-scheme percentages come only from raw samples sharing the same GmSSL commit.

---

### Task 1: API contract and RED build

**Files:**
- Create: `native/include/hscmet2022.h`
- Create: `native/tests/test_hscmet2022.c`
- Modify: `native/CMakeLists.txt`
- Modify: `.github/workflows/pchs-ci.yml`

**Produces:** public API for setup/keygen/signcrypt/unsigncrypt and a test target linked against `hscmet2022`.

- [ ] Define master/public/sender/receiver/ciphertext structs. Ciphertext contains `C1`, dynamic `C2`, 64-byte `C3`, 32-byte `C4`, and `k`.
- [ ] Add roundtrip tests for 0,1,20,128,1024,4096 B and algebra assertions.
- [ ] Add the new target to CMake before the implementation source exists.
- [ ] Run CI and verify RED fails because `src/hscmet2022.c` is missing / symbols are undefined, not because existing V2/PCHS/Gong tests fail.

### Task 2: Core HSC-MET n=k=2 implementation

**Files:**
- Create: `native/src/hscmet2022.c`
- Modify: `native/tests/test_hscmet2022.c`

**Produces:** exact paper path adapted to variable message lengths.

- [ ] Implement scalar/random/point validation helpers.
- [ ] Implement `H1` as SM3 hash-to-nonzero-scalar with domain separation and framed inputs.
- [ ] Implement `H2` as SM3-KDF over a point with output `message_len+32`.
- [ ] Implement `H3` as SM3-KDF over a point with fixed 64-byte output.
- [ ] Implement `H4` as SM3 over canonical framed fields.
- [ ] Implement setup and PKI/CLC key generation, including `[SK_c1]P=PK_c1+[H1(ID_c)]PK`.
- [ ] Implement signcrypt: f02/f12/f2(X), Y, R, C1, C2, C3, C4.
- [ ] Implement unsigncrypt: Y', R', recover `m||r`, recover/verify `X||f2(X)`, verify C1 and C4, return message.
- [ ] Add tamper tests for C1/C2/C3/C4/k, sender PK, receiver SKc1/SKc2.
- [ ] Run CI to GREEN.

### Task 3: Raw benchmark and statistics

**Files:**
- Create: `native/bench/bench_hscmet2022.c`
- Create: `scripts/summarize_hscmet2022.py`
- Create: `scripts/compare_v2_hscmet2022.py`
- Modify: `native/CMakeLists.txt`
- Modify: `.github/workflows/pchs-ci.yml`

**Produces:** two-phase per-iteration raw nanosecond records and deterministic statistics.

- [ ] Add benchmark CLI matching existing schema: run_id, commit, gmssl_commit, message_bytes, warmup, iterations, raw.
- [ ] Warm up full signcrypt+unsigncrypt roundtrips.
- [ ] Time only full HSC-MET Signcrypt and full HSC-MET Unsigncrypt using the same `now_ns` mechanism.
- [ ] Record phases exactly as specified.
- [ ] Add benchmark smoke test to CTest.
- [ ] Add summary script computing n, mean, median, sample stdev, nearest-rank P95; reject missing/duplicate groups.
- [ ] Add comparison script requiring identical GmSSL commits and deriving online reduction, sender total delta, unsigncrypt delta from raw samples.
- [ ] Add deterministic self-tests and wire them into CI.

### Task 4: Windows formal-run evidence chain

**Files:**
- Create: `scripts/run_hscmet2022_windows.ps1`
- Create: `docs/benchmark/HSCMET2022_PKI_CLC_REPRODUCTION.md`
- Modify: `.gitignore`
- Modify: `.github/workflows/pchs-ci.yml`

**Produces:** timestamped Windows evidence directory and V2 comparison.

- [ ] Require clean git tree and record git HEAD.
- [ ] Resolve fixed GmSSL root and `C:\msys64\ucrt64\bin\gcc.exe`.
- [ ] Configure Release/Ninja with explicit C compiler.
- [ ] Build and run all native tests before measurement.
- [ ] Run four message sizes with caller-supplied warmup/iterations.
- [ ] Generate summary/comparison and environment JSON containing DOI, n=2, k=2, CPU/compiler/tool versions.
- [ ] Add PowerShell parser validation to CI.
- [ ] Document that HSC-MET has extra MET functionality and is an adapted same-platform reimplementation.

### Task 5: Final branch audit

**Files:** all changed files.

- [ ] Verify latest CI is fully green.
- [ ] Compare branch against `benchmark-gong2025-pki-clc`; confirm no V2/PCHS/Gong cryptographic source changed.
- [ ] Verify benchmark and correctness tests call the same HSC-MET implementation.
- [ ] Verify formal-run script cannot overwrite an existing raw CSV and requires a clean tree.
- [ ] Lock the final branch HEAD for the Windows smoke test and formal 8000-sample run.
