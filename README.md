# SM2-SM9 V2: Reproducible Research Package

This repository is a **research implementation and reproducibility package** for the V2 construction:
SM2/PKI sender -> enhanced SM9 receiver, dual-factor KEM, SM3-KDF masking, SM2 offline point precomputation, HMAC-SM3 binding, no SM4.

## Evidence rule

**No performance value is accepted without an executable run and a traceable evidence chain.** The project now distinguishes:

- `CI_MEASURED`: a real GitHub Actions reproducibility benchmark has run successfully;
- `submission_benchmark: NOT_MEASURED`: the designated Ryzen 7 8845H final submission benchmark has not yet run.

CI values must never be relabeled as final platform results.

## Implementations

### Native submission-oriented implementation

The authoritative performance implementation is under `native/` and pins:

- `guanzhi/GmSSL`
- commit `24ae482701a7b124826c382fffc55c19f76d475d`

It uses public GmSSL 3.x SM2/SM3/HMAC-SM3/SM9 APIs. The CI pipeline first runs upstream SM2, SM3, HMAC-SM3 and SM9 tests, then V2 correctness/adversarial tests, and only then starts the benchmark.

### Python reference implementation

The earlier `src/v2_scheme.py` prototype pins `gongxian-ding/gmssl-python` commit `498ba0545a3f7667ab4575e93cd10e9b19baf4f0`. It remains useful for equation/code alignment but is **not** the authoritative standard-performance implementation.

## Native test coverage

The native suite covers:

- setup and `X_B=[x_B]Q_B`;
- sender/receiver agreement on `Z_1`, `Z_2`, `K_E`, `K_M`;
- one-token SM2 offline precomputation verified by standard GmSSL SM2 verification;
- signcrypt/unsigncrypt round trips at 0/1/20/128/1024/4096 bytes;
- one-time token reuse rejection;
- rejection after tampering `X_B`, `U`, `C`, SM2 `r/s`, or HMAC tag;
- rejection with wrong `x_B`, wrong SM9 identity private key, infinity/malformed points;
- Type-I-KSR and Type-II knowledge-path demonstrations (explicitly not hardness proofs).

## Repository layout

- `native/include/`, `native/src/`: native V2 implementation
- `native/tests/`: correctness, negative-security and adversary-path tests
- `native/bench/bench_v2.c`: per-iteration native timing collector
- `native/bench/summarize.py`: deterministic summary generation
- `native/bench/validate_evidence.py`: fail-closed evidence validation
- `native/scripts/collect_env.py`: environment capture
- `native/scripts/run_submission_windows.ps1`: Ryzen submission benchmark entry point
- `src/v2_scheme.py`: Python equation-aligned reference
- `bench/`: Python reference benchmark tooling
- `metadata/experiment_manifest.json`: evidence state and exact identities
- `docs/security/`: reviewer-attack and reduction audit
- `docs/benchmark/`: CI evidence and submission protocol
- `paper/STATUS.md`: manuscript status/integrity metadata

## Verified CI reproducibility benchmark

A real native benchmark has been archived from GitHub Actions run `33383426286`:

- V2 commit: `c0f3247fea828c37970dbf03f66c5aa18bc3e837`
- GmSSL commit: `24ae482701a7b124826c382fffc55c19f76d475d`
- artifact ID: `9754694893`
- four message sizes: 20 / 128 / 1024 / 4096 bytes
- nine phases
- 50 measured samples per size×phase group
- 1800 raw timing rows total
- raw/summary/environment/log evidence archived and independently revalidated

Full metadata and hashes are in `docs/benchmark/CI_EVIDENCE.md` and `metadata/experiment_manifest.json`.

This run is classified **CI reproducibility benchmark**, not the final submission benchmark.

## Final Ryzen benchmark

On the designated Lenovo XiaoXinPro 16 AHP9 / Ryzen 7 8845H Windows machine, run from a clean commit:

```powershell
powershell -ExecutionPolicy Bypass -File .\native\scripts\run_submission_windows.ps1
```

The script requires at least 1000 warm-up iterations and 10000 measured iterations per size×phase, validates all tests first, writes raw/summary/environment/logs, and fails closed if evidence validation fails. See `docs/benchmark/RYZEN_8845H_PROTOCOL.md`.

## Security-model status

Type-I is explicitly **Known-Secret Public-Key Replacement (Type-I-KSR)**. It is not presented as the strongest classical certificateless arbitrary-public-key-replacement model. The primary remaining theoretical risks are documented in `docs/security/REVIEWER_ATTACK_MATRIX.md`, especially:

1. Type-I-KSR model strength;
2. exact mapping from the modular SM9 identity-KEM assumption to published SM9 encryption hardness results;
3. multi-key HMAC and KDF-query loss accounting.

No implementation benchmark is treated as a substitute for a cryptographic reduction.
