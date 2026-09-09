# IEEE-style performance evaluation rerun

This branch adds two missing microbenchmarks required by the revised manuscript cost accounting:

- `sm9_g1_add`: one SM9 G1 point addition, used to measure `T1a`;
- `sm9_qb_compute`: the complete computation of `Q_B = [H_1(ID_B)]P_1 + P_pub`, including hash-to-scalar, G1 multiplication and G1 addition.

The evidence validator now expects 11 phases per message size. The publication plotting script is `native/bench/plot_performance.py`.

## Formal Windows target-machine run

Run from the repository root in PowerShell:

```powershell
git fetch origin
git checkout perf/ieee-q1-evaluation
git pull --ff-only origin perf/ieee-q1-evaluation
powershell -ExecutionPolicy Bypass -File native/scripts/run_submission_windows.ps1 -Warmup 1000 -Iterations 10000
```

The submission runner requires a clean working tree, rebuilds the pinned GmSSL configuration, runs upstream and V2 tests, then produces an evidence directory under `artifacts/submission-ryzen8845h-*`.

Expected raw row count for the new formal run:

`4 message sizes x 11 phases x 10000 iterations = 440000 rows`.

## Generate figures

After the run succeeds:

```powershell
python native/bench/plot_performance.py artifacts/submission-<RUN_ID>/summary.csv --output-dir artifacts/submission-<RUN_ID>/figures
```

The script generates separate PDF and 600-dpi PNG figures:

1. `fig_normalized_major_operations`;
2. `fig_protocol_runtime`;
3. `fig_online_latency`;
4. `fig_online_share`;
5. `fig_communication_overhead`;
6. `derived_performance_metrics.csv`.

The normalized major-operation figure is a structural normalization only: it multiplies published operation counts by V2 primitive timings on the Ryzen 7 8845H. It is not presented as a reproduction of other schemes on the same platform.

## Evidence to return for manuscript finalization

Send the entire generated `artifacts/submission-<RUN_ID>` directory as a ZIP, or at minimum:

- `raw.csv`;
- `summary.csv`;
- `environment.json`;
- `hashes.json`;
- `evidence-validation.log`;
- the `figures/` directory.
