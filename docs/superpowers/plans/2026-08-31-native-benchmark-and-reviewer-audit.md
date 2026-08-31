# SM2-SM9 V2 Native Benchmark and Reviewer Audit Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement and independently test the V2 SM2/PKI -> enhanced-SM9 online/offline signcryption scheme on pinned GmSSL 3.x, obtain traceable CI benchmark evidence without fabricated numbers, and tighten the manuscript against identified cryptographic reviewer attacks.

**Architecture:** Keep `src/v2_scheme.py` as a non-authoritative Python reference. Add a native C implementation under `native/` using only public GmSSL 3.x APIs at pinned commit `24ae482701a7b124826c382fffc55c19f76d475d`. Develop on `feat/native-gmssl-v2` with a draft PR so RED/GREEN TDD evidence is observable in GitHub Actions. Native code separates public parameters/KGC state, sender key, receiver dual-factor key, one-time offline token, canonical wire encoding, online signcryption, and unsigncryption. Benchmark evidence is generated only by executables and archived as raw CSV, summary CSV, environment JSON, and logs.

**Tech Stack:** C11, CMake >= 3.16, GmSSL 3.x at commit `24ae482701a7b124826c382fffc55c19f76d475d`, GitHub Actions Ubuntu runner, Python 3 for benchmark summarization/environment helpers, LaTeX for manuscript, pytest for the reference contract.

**Spec:** `docs/superpowers/specs/2026-08-31-native-benchmark-and-reviewer-audit-design.md`

## Global Constraints

- No SM4, PoP, RA, epoch, timestamps, sequence numbers, or replay cache in V2.
- Type-I claim is only **Known-Secret Replacement (Type-I-KSR)** unless a stronger model is separately proved.
- No latency value is reported before a real executable run.
- CI results are **CI reproducibility benchmark**, not Ryzen 7 8845H submission results.
- Use only public GmSSL headers/APIs; if a required operation is unavailable, record a blocker instead of copying private internals.
- Offline token lifecycle is `READY -> CONSUMED` before message-dependent cryptographic work; retry/error never rolls back state.
- Use `gmssl_secure_memcmp` for tag acceptance and `gmssl_secure_clear` for temporary secrets.
- Protocol concatenations use domain tags and 32-bit big-endian length prefixes.
- Static source tests do not count as end-to-end cryptographic evidence.

---

## Task 1: Isolated branch and native CI smoke test

**Files:** `.github/workflows/native-ci.yml`, `native/CMakeLists.txt`, `native/tests/test_compile.c`, `native/include/v2_scheme.h`, `native/README.md`.

- [ ] Create `feat/native-gmssl-v2` from `main` and open a draft PR.
- [ ] RED: create `test_compile.c` containing `#include <v2_scheme.h>` and a `V2_PUBLIC_PARAMS` declaration before the production header exists.
- [ ] Add CI that clones GmSSL, checks out `24ae482701a7b124826c382fffc55c19f76d475d`, configures Release with `ENABLE_SM9=ON`, builds, runs upstream `sm2_sign`, `sm3`, `sm3_hmac`, and `sm9` tests, installs to a local prefix, then configures/builds native V2.
- [ ] Verify RED is specifically missing `v2_scheme.h`; if upstream GmSSL fails, stop and debug that first.
- [ ] GREEN: add minimal `v2_scheme.h` including `<gmssl/sm2.h>`, `<gmssl/sm9.h>`, `<gmssl/sm9_z256.h>` and the `V2_PUBLIC_PARAMS` type.
- [ ] Verify upstream tests and compile smoke test pass. Commit `build: establish pinned GmSSL native CI`.

CI command baseline:

```bash
git clone https://github.com/guanzhi/GmSSL.git _deps/GmSSL
git -C _deps/GmSSL checkout 24ae482701a7b124826c382fffc55c19f76d475d
cmake -S _deps/GmSSL -B _deps/GmSSL/build -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="$PWD/_deps/gmssl-install" -DENABLE_SM9=ON
cmake --build _deps/GmSSL/build --config Release -j2
ctest --test-dir _deps/GmSSL/build -R '^(sm2_sign|sm3|sm3_hmac|sm9)$' --output-on-failure
cmake --install _deps/GmSSL/build
cmake -S native -B native/build -DCMAKE_BUILD_TYPE=Release -DGMSSL_ROOT="$PWD/_deps/gmssl-install"
cmake --build native/build --config Release -j2
ctest --test-dir native/build --output-on-failure
```

---

## Task 2: Setup, receiver key generation, and canonical encoding

**Files:** `native/include/v2_scheme.h`, `native/src/v2_scheme.c`, `native/tests/test_v2.c`, `native/CMakeLists.txt`.

- [ ] RED tests: `v2_setup`, `v2_compute_qb`, `v2_receiver_keygen`; assert `X_B=[x_B]Q_B`, points are on curve/non-infinity, and `g=e(P2,Ppube)`.
- [ ] RED test context binding: changing `ID_A`, `ID_B`, SM2 public key, `X_B`, or `U` changes canonical context bytes/KDF input.
- [ ] Implement:

```c
typedef struct { SM9_ENC_MASTER_KEY master; } V2_KGC;
typedef struct { SM9_Z256_POINT Ppube; sm9_z256_fp12_t g; } V2_PUBLIC_PARAMS;
typedef struct { SM9_ENC_KEY identity_key; sm9_z256_t x_b; SM9_Z256_POINT X_b; } V2_RECEIVER_KEY;
```

- [ ] `v2_setup`: `sm9_enc_master_key_generate`, copy `Ppube`, and `sm9_z256_pairing(g, sm9_z256_twist_generator(), &Ppube)`.
- [ ] `v2_compute_qb`: `h1=sm9_z256_hash1(ID,SM9_HID_ENC)`, `Q_B=[h1]P1+Ppube` with public `sm9_z256_point_mul/add`.
- [ ] `v2_receiver_keygen`: extract `SM9_ENC_KEY`, sample non-zero `x_B`, compute `X_B=[x_B]Q_B`.
- [ ] Internal canonical encoders: 4-byte length prefix; SM9 G1 = 65-byte uncompressed octets; SM2 public point = 65-byte uncompressed octets; GT = 384-byte `sm9_z256_fp12_to_bytes`; never serialize raw C structs.
- [ ] GREEN and commit `feat(native): add SM9 dual-factor key setup and canonical encoding`.

---

## Task 3: Dual-factor offline KEM and receiver recomputation

**Files:** same native header/source/tests.

- [ ] RED agreement tests for sender/receiver `Z1`, `Z2`, `K_E`, `K_M`.
- [ ] Add sender type:

```c
typedef struct { SM2_KEY key; sm2_z256_t fast_private; } V2_SENDER_KEY;
```

- [ ] `v2_sender_keygen`: `sm2_key_generate` + `sm2_fast_sign_compute_key`.
- [ ] Offline KEM:

```c
rho <- nonzero Z_q
U  = [rho]Q_B
Z1 = g^rho                    // sm9_z256_fp12_pow
Z2 = [rho]X_B                 // sm9_z256_point_mul
```

- [ ] Receiver recomputation:

```c
Z1' = e(d_B, U)               // sm9_z256_pairing(&identity_key.de, U)
Z2' = [x_B]U
```

- [ ] Domain-separated SM3-KDF input exactly:

`SM2-SM9-V2/KEY/v1 || LP(Z1) || LP(Z2) || LP(ID_A) || LP(P_A) || LP(ID_B) || LP(X_B) || LP(U)`.

Generate 64 bytes, split into 32-byte `K_E`,`K_M`.
- [ ] Clear `rho` and temporary material on all exits.
- [ ] GREEN and commit `feat(native): implement dual-factor SM9 KEM`.

---

## Task 4: One-token SM2 offline precomputation and online signing

**Files:** native header/source/tests.

- [ ] RED test: precompute one nonce point, sign a message online, and verify using standard `sm2_do_verify`.
- [ ] RED/source contract: online signing must not call `sm2_z256_point_mul_generator`.
- [ ] Define `typedef SM2_SIGN_PRE_COMP V2_SM2_PRECOMP;`.
- [ ] Implement one-token precomputation with public APIs, not `sm2_fast_sign_pre_compute(32)`: sample nonzero `k`, call `sm2_z256_point_mul_generator`, obtain x-coordinate with `sm2_z256_point_get_xy`, reduce modulo order into `x1_modn`.
- [ ] Compute SM2 digest as `SM3(ZA || mu)` using `sm2_compute_z` and `sm3_init/update/finish`.
- [ ] Online sign with `sm2_fast_sign(sender->fast_private,&pre,dgst,&sig)` and standard verify with `sm2_do_verify`.
- [ ] Explicitly detect standard retry conditions. Retry must return `V2_ERR_RETRY_TOKEN`; enclosing token remains consumed.
- [ ] GREEN and commit `feat(native): add one-token SM2 offline signing precomputation`.

---

## Task 5: Complete OfflineSC, OnlineSC, UnSC and wire format

**Files:** native header/source/tests.

- [ ] RED roundtrip tests for message lengths `0,1,20,128,1024,4096`.
- [ ] RED test that second use of the same token fails.
- [ ] Token type:

```c
typedef enum { V2_TOKEN_EMPTY=0, V2_TOKEN_READY=1, V2_TOKEN_CONSUMED=2 } V2_TOKEN_STATE;
typedef struct {
  V2_TOKEN_STATE state;
  SM9_Z256_POINT X_b, U;
  uint8_t K_E[32], K_M[32];
  V2_SM2_PRECOMP sm2_pre;
} V2_OFFLINE_TOKEN;
```

- [ ] Ciphertext type with dynamic `C`, `C_len`, `X_B`, `U`, raw `SM2_SIGNATURE`, 32-byte `tau`; provide init/cleanup and secure-clear helpers.
- [ ] Online starts with `READY -> CONSUMED` before stream generation/signing.
- [ ] Encryption stream: domain `SM2-SM9-V2/ENC/v1`, SM3-KDF over `LP(K_E)||LP(ctx)`, XOR via `gmssl_memxor`.
- [ ] Canonical signed transcript `mu = SM2-SM9-V2/SC/v1 || LP(ID_A)||LP(ID_B)||LP(X_B)||LP(U)||LP(C)`.
- [ ] HMAC transcript `SM2-SM9-V2/MAC/v1 || LP(mu) || LP(r||s)`.
- [ ] UnSC order: validate `X_B,U` -> require ciphertext `X_B` equals receiver key -> reconstruct `mu` -> SM2 verify -> recompute `Z1,Z2,K_E,K_M` -> constant-time HMAC verify -> decrypt -> clear secrets.
- [ ] Wire format: `version(1)||X_B(65)||U(65)||C_len(4)||C||r(32)||s(32)||tau(32)`; tests for truncation, oversized length, malformed point, unsupported version.
- [ ] GREEN and commit `feat(native): complete V2 signcryption and one-time token lifecycle`.

---

## Task 6: Adversarial negative tests and attack-path demonstrations

**Files:** `native/tests/test_v2.c`, `native/tests/test_attacks.c`, CMake.

- [ ] Tamper one field at a time: `X_B`, `U`, `C`, `sigma.r`, `sigma.s`, `tau`; all must reject.
- [ ] Reject wrong `x_B`, wrong SM9 identity private key, infinity points, invalid point octets, token reuse, and mixed KDF domain labels.
- [ ] Type-I-KSR demo: choose `x'_B`, set `X'_B=[x'_B]Q_B`, and verify attacker can compute `Z2=[x'_B]U`. Label as a knowledge-path demo, not a hardness proof.
- [ ] Type-II demo: show KGC-held `d_B` computes the same `Z1` via pairing, while the legitimate V2 decapsulation API still needs `x_B` for `Z2`. Do not claim this experimentally proves CDH.
- [ ] GREEN all native tests and commit `test(native): add tamper rejection and adversary-path coverage`.

---

## Task 7: Repair Python benchmark and implement native benchmark

**Files:** `bench/benchmark.py`, `scripts/run_all.sh`, `scripts/run_all.ps1`, `native/bench/bench_v2.c`, `native/bench/summarize.py`, native run scripts.

- [ ] RED regression test for current Python bug: separate 20- and 128-byte runs must both remain in raw/summary output. Current `open(...,"w")` must fail the test.
- [ ] Fix by aggregating message sizes in one invocation or append-safe raw data plus full-summary regeneration; header written once.
- [ ] Native raw schema: `run_id,commit,gmssl_commit,message_bytes,phase,iteration,ns`.
- [ ] Native summary schema: `run_id,commit,gmssl_commit,message_bytes,phase,n,mean_ns,median_ns,stdev_ns,p95_ns`.
- [ ] Measure phases: `receiver_keygen`, `offline_signcrypt`, `online_signcrypt`, `sender_total`, `unsigncrypt`, `sm2_fixed_base_mul`, `sm9_g1_mul`, `sm9_pairing`, `sm9_gt_exp`.
- [ ] Warmup is never written. CLI accepts message size, warmup, iterations, raw output path.
- [ ] `summarize.py`: mean, median, sample stdev, nearest-rank P95; never invent missing groups.
- [ ] Short CI run is allowed only as reproducibility data, not paper submission data.
- [ ] Commit `bench: make Python and native measurements append-safe and traceable`.

---

## Task 8: GitHub Actions real CI benchmark evidence

**Files:** `.github/workflows/native-ci.yml`, `native/scripts/collect_env.py`, manifest, READMEs, reproducibility docs.

- [ ] Extend PR workflow to jobs `upstream-gmssl-tests`, `native-correctness`, `native-benchmark`.
- [ ] Record V2 SHA, GmSSL SHA, runner OS/kernel, CPU, core count, compiler/version, CMake, build type/flags, timestamp, warmup/iteration counts.
- [ ] Run 20/128/1024/4096 B; produce one combined raw CSV and summary CSV.
- [ ] Artifact `v2-ci-evidence-<sha>` contains `environment.json`, `raw.csv`, `summary.csv`, `build.log`, `upstream-tests.log`, `native-tests.log`, `benchmark.log`.
- [ ] Evidence gate: upstream tests pass, native tests pass, benchmark exits 0, all four sizes/phases present, summary recomputes from raw, artifact downloadable and tied to exact commit.
- [ ] Only then change manifest to `CI_MEASURED`; `submission_benchmark_status` stays `NOT_MEASURED`.
- [ ] Commit `ci: archive reproducible native benchmark evidence`.

---

## Task 9: Reviewer attack matrix and proof revisions

**Files:** `docs/security/REVIEWER_ATTACK_MATRIX.md`, `TYPE_I_KSR_MODEL.md`, `TYPE_II_CDH_REDUCTION.md`, manuscript source, `paper/STATUS.md`.

- [ ] Matrix columns: `ID | Concern | Severity | Attack/Failure Mode | Evidence | Resolution | Residual Risk`.
- [ ] Include at least: KSR weaker than classical Type-I; modular SM9-ID-KEM assumption; Type-II scaled CDH KDF-query consistency; identity/query guessing loss; HMAC multi-key loss; same-message alternative randomized SM2 signature vs ordinary EUF-CMA; SM3-KDF ROM wording; confidentiality vs DoS; KDF-based DEM CCA composition; offline-token leakage.
- [ ] Tighten Type-I wording to **Known-Secret Public-Key Replacement** in title/abstract/theorem if stronger arbitrary replacement is not proved.
- [ ] Type-II events: `E_id` challenge identity guess, `E_c: c!=0`, `E_K` first correct challenge KDF query, plus signature/MAC bad events. Do not freeze an advantage formula until every transition has a probability bound.
- [ ] HMAC: use a multi-key PRF/UFCMA definition consistently, or explicitly guess a forged session and pay at most `q_sc`-scale loss.
- [ ] State ordinary message-level EUF-CMA only; same-message alternative randomized SM2 signatures are handled by CCA/MAC binding, not ordinary SM2 EUF-CMA.
- [ ] ROM wording: “The domain-separated SM3-KDF instances are modeled as independent random oracles for the proof.”
- [ ] Search for a clean SM9 KEM/IBE -> BDHI-family theorem mapping. If none is clean, explicitly retain a modular `SM9-ID-KEM` assumption and list it as residual theoretical risk; never invent a reduction.
- [ ] Commit `docs(security): add reviewer attack matrix and tightened reduction accounting`.

---

## Task 10: Ryzen 7 8845H submission benchmark package

**Files:** `native/scripts/run_submission_windows.ps1`, `docs/benchmark/RYZEN_8845H_PROTOCOL.md`, `docs/benchmark/SUBMISSION_CHECKLIST.md`, manifest after real execution only.

- [ ] Submission script fails closed on build/test failure, records environment, then runs warmup >=1000 and iterations >=10000 for 20/128/1024/4096 B.
- [ ] Record Lenovo XiaoXinPro 16 AHP9 / Ryzen 7 8845H, Windows build, BIOS, power mode, compiler, CMake, optional CPU affinity, V2 SHA and GmSSL SHA only from the real machine; no pre-filled unknown values.
- [ ] Output combined raw/summary CSV, environment JSON and logs.
- [ ] Final paper data gate: all target-machine tests pass; sample counts correct; no mixed commits/configs; summary recomputes from raw; logs/environment exist.
- [ ] Only then set `submission_benchmark_status: MEASURED` and populate manuscript performance tables/figures from CSV.
- [ ] Final verification: `python -m pytest -q`, native `ctest`, recompute summary from raw and compare, inspect PR diff against approved spec, request review, merge only with green CI and documented residual risks.

## Evidence Order

1. Tasks 1–6: correctness/security behavior; **no performance claim**.
2. Task 7: benchmark tooling; **no paper number without real run**.
3. Task 8: CI evidence; may be reported only as CI reproducibility measurements.
4. Task 9: proof/model corrections; benchmark work does not override theoretical weaknesses.
5. Task 10: target Ryzen execution; only this is eligible for final submission performance tables.

A task is complete only when its stated RED/GREEN or evidence gate has been observed, not merely when files have been edited.
