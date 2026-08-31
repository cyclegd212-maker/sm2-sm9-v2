# SM2-SM9 V2: Reproducible Research Package

This repository is a **research implementation and reproducibility package** for the V2 construction:
SM2/PKI sender -> enhanced SM9 receiver, dual-factor KEM, SM3-KDF masking, SM2 offline point precomputation, HMAC-SM3 binding, no SM4.

## Reproducibility rule

**No millisecond value is reported until the benchmark has actually run.** The checked-in CSV files contain headers only and `metadata/experiment_manifest.json` is marked `NOT_MEASURED`.

## Reference dependency

For a transparent first prototype the code pins:

- `gongxian-ding/gmssl-python`
- commit `498ba0545a3f7667ab4575e93cd10e9b19baf4f0`

This dependency is a pure-Python reference baseline. It is useful for equation/code alignment and protocol experiments, but it is **not** treated here as evidence of official GB/T SM9 parameter compliance or as the final performance implementation. Submission-quality performance results must be replicated on an implementation that passes authoritative SM2/SM3/SM9 test vectors, with the exact library commit, build flags, environment, raw CSV and logs recorded.

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
- `docs/`: research-writing and proof-audit material
- `paper/STATUS.md`: manuscript status and integrity metadata; the PDF/TeX deliverables are generated separately and are not silently represented as repository files

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

- benchmark CSV files remain headers-only until a real run is executed;
- `metadata/experiment_manifest.json` records `NOT_MEASURED`;
- every future performance claim should be traceable to a repository commit, environment record, raw CSV, summary CSV, and preserved run log;
- manuscript PDF/TeX artifacts are tracked by filename and SHA-256 in `paper/STATUS.md` until they are separately uploaded/released.

## Research status

This is a pre-submission research artifact, not a claim of a finalized standard-conformant implementation. The current prototype is used to align code with the V2 equations and prepare a reproducible benchmark workflow. The main theoretical item still requiring reviewer-level scrutiny is the non-standard Type-I-KSR (known-secret public-key replacement) model; formal performance claims remain pending real measurements.
