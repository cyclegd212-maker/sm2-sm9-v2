# Reproducibility checklist

Before any number is copied into the paper:

- [ ] SM2 official/authoritative test vectors pass.
- [ ] SM3 official/authoritative test vectors pass.
- [ ] SM9 official/authoritative test vectors pass on the exact benchmark implementation.
- [ ] Library repository and exact commit are recorded.
- [ ] Compiler, CMake/build options, OS, CPU and power mode are recorded.
- [ ] Warm-up count and measured iteration count are fixed before inspecting results.
- [ ] Raw per-iteration nanosecond samples are preserved in `data/raw/timings.csv`.
- [ ] `data/processed/summary.csv` is derived from the raw file, never hand-entered.
- [ ] Full console output is archived in `logs/run.log`.
- [ ] Repository commit containing the benchmark code is recorded in metadata.
- [ ] The paper reports mean, median, standard deviation and P95, and identifies message size.

`NOT_MEASURED` means no latency claim is permitted.
