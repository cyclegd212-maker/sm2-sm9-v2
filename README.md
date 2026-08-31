# SM2-SM9 V2: Reproducible Research Package

This directory is a **repo-ready research implementation** for the paper's V2 construction:
SM2/PKI sender -> enhanced SM9 receiver, dual-factor KEM, SM3-KDF masking, SM2 offline point precomputation, HMAC-SM3 binding, no SM4.

## Reproducibility rule

**No millisecond value is reported until the benchmark has actually run.** The checked-in CSV files contain headers only and `metadata/experiment_manifest.json` is marked `NOT_MEASURED`.

## Reference dependency

For a transparent first prototype the code pins:

- `gongxian-ding/gmssl-python`
- commit `498ba0545a3f7667ab4575e93cd10e9b19baf4f0`

This repository is pure Python and old; it is appropriate only as a *functional/protocol reference baseline*, not as evidence of GB/T SM9 parameter compliance and not as the final performance implementation. Its internal curve/parameter choices must not be cited as official SM9 benchmark parameters without independent test-vector verification. A submission-quality benchmark should migrate or replicate the implementation on a maintained native library (preferably GmSSL 3.x or another implementation that passes official SM9 test vectors) and record its exact commit, compiler flags, test-vector results, raw CSV, and logs.

## Layout

- `src/v2_scheme.py`: equation-aligned V2 reference implementation
- `bench/benchmark.py`: raw nanosecond sample collector
- `bench/collect_env.py`: environment/commit/dependency capture
- `tests/`: static/source-contract tests
- `data/raw/`: raw samples only
- `data/processed/`: derived statistics only
- `metadata/`: version/environment metadata
- `logs/`: preserved run logs
- `scripts/run_all.sh`, `scripts/run_all.ps1`: reproducible run entry points

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

Before using benchmark data in a paper, archive the repository commit, `pip freeze`, OS/CPU details, raw CSV, summary CSV and all logs. Never copy latency values from another machine or library version.

## Repository status

Canonical repository: `https://github.com/cyclegd212-maker/sm2-sm9-v2`.

The repository is intentionally conservative about evidence:

- the paper and LaTeX source are versioned under `paper/`;
- benchmark CSV files are headers-only until a real run is executed;
- `metadata/experiment_manifest.json` records `NOT_MEASURED`;
- every future performance claim should be traceable to a repository commit, environment record, raw CSV, summary CSV, and preserved run log.

## Research status

This is a pre-submission research artifact, not a claim of a finalized standard-conformant implementation. The current Python prototype is used to align code with the V2 equations and to prepare a reproducible benchmark workflow. Submission-quality measurements should be replicated on a maintained native implementation that passes official SM2/SM3/SM9 test vectors.
