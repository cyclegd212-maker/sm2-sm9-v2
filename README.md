# SM2-SM9 V2: Reproducible Research Package

This repository is a **research implementation and reproducibility package** for the V2 construction:
SM2/PKI sender -> enhanced SM9 receiver, dual-factor KEM, SM3-KDF masking, SM2 offline point precomputation, HMAC-SM3 binding, no SM4.

## Reproducibility status

The performance experiments reported in the current manuscript have been executed on the native-C/GmSSL implementation. The reported manuscript results are therefore no longer in a `NOT_MEASURED` state.

The current manuscript benchmark environment is:

- Lenovo XiaoXinPro 16 AHP9
- AMD Ryzen 7 8845H (8 cores / 16 threads)
- 32 GB RAM
- Windows 11
- GmSSL commit `24ae482701a7b124826c382fffc55c19f76d475d`
- MSYS2 UCRT64 GCC 16.2.0
- CMake 4.4.3
- Ninja 1.13.2
- GmSSL options: `ENABLE_SM9=ON`, `ENABLE_SM2_AMD64=OFF`
- message sizes: 20 B, 128 B, 1024 B, 4096 B
- per message size: 1000 warm-up runs + 1000 measured runs, without outlier deletion

The pure-Python prototype remains useful for equation/code alignment and protocol inspection, but it is not the source of the performance numbers reported in the current manuscript.

## Reference dependency

For a transparent first prototype the code pins:

- `gongxian-ding/gmssl-python`
- commit `498ba0545a3f7667ab4575e93cd10e9b19baf4f0`

This dependency is a pure-Python reference baseline. It is useful for equation/code alignment and protocol experiments, but it is **not** treated here as evidence of official GB/T SM9 parameter compliance or as the final performance implementation. The current manuscript performance evaluation instead uses the pinned native-C GmSSL environment listed above.

## Layout

- `src/v2_scheme.py`: equation-aligned V2 reference implementation
- `bench/benchmark.py`: raw nanosecond sample collector for the reference workflow
- `bench/collect_env.py`: environment/commit/dependency capture
- `tests/`: static/source-contract tests
- `data/raw/`: raw samples for the reference workflow
- `data/processed/`: derived statistics for the reference workflow
- `metadata/`: version/environment metadata
- `logs/`: preserved run logs
- `scripts/run_all.sh`, `scripts/run_all.ps1`: reproducible reference entry points
- `docs/`: research-writing, proof-audit and benchmark mapping material
- `paper/STATUS.md`: manuscript status and integrity metadata

## Run

```bash
python -m venv .venv
# Linux/macOS: source .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m pytest -q
bash scripts/run_all.sh          # Linux/macOS
# or: .\scripts\run_all.ps1   # Windows PowerShell
```

For performance claims, preserve the exact repository commit, library commit, build flags, CPU/OS information, raw measurements, derived statistics and logs used for the manuscript result.

## Repository status

Canonical repository: `https://github.com/cyclegd212-maker/sm2-sm9-v2`.

Current status:

- the manuscript performance experiment has been measured on the native-C/GmSSL implementation;
- the current manuscript reports formal timings for the proposed scheme at 20 B, 128 B, 1024 B and 4096 B;
- three PKI->CLC comparison baselines used in the manuscript have been independently reimplemented and measured on the same machine/environment;
- every reported comparison should remain traceable to the corresponding benchmark branch, frozen commit, environment record and manuscript table;
- the repository remains a pre-submission research artifact rather than a claim of a finalized standards-validation package.

## Research status

This is a pre-submission research artifact. Formal performance measurements used by the current manuscript are available, while the security model and reductions should still be treated as research results subject to reviewer-level cryptographic scrutiny.

## Same-platform reproduced baselines used in the current manuscript

The native-C comparison implementations are preserved on dedicated benchmark branches. Their current manuscript reference numbers are:

- **[30] Liu 2018** — `benchmark-liu2018-pchs`
- **[34] HSC-MET 2022** — `benchmark-hscmet2022-pki-clc`
- **[37] Gong 2025** — `benchmark-gong2025-pki-clc`

Detailed bibliography/commit mapping: [`docs/REPRODUCED_BASELINES.md`](docs/REPRODUCED_BASELINES.md).

These are independent reimplementations from the published scheme descriptions, not the original authors' source-code releases.
