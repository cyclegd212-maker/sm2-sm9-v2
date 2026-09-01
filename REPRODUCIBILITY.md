# Reproducibility checklist

## Evidence classes

- `CI_MEASURED`: real native benchmark on a GitHub-hosted runner; may be used to demonstrate reproducibility and implementation behavior.
- `submission_benchmark: MEASURED`: final target-machine evidence; only this class may populate the manuscript's final Ryzen 7 8845H performance table.

A CI number must never be silently relabeled as a submission-platform number.

## Before any CI benchmark is accepted

- [x] GmSSL commit pinned exactly.
- [x] GmSSL SM2 signing test passes.
- [x] GmSSL SM3 test passes.
- [x] GmSSL HMAC-SM3 test passes.
- [x] GmSSL SM9 test passes.
- [x] Native V2 correctness/adversarial tests pass.
- [x] Environment JSON records V2/GmSSL identities and build context.
- [x] Raw per-iteration samples are archived.
- [x] Summary is derived automatically from raw data.
- [x] Evidence validator checks every message-size × phase group and recomputes summary.
- [x] Artifact hash and raw/summary hashes are recorded.

The first verified CI evidence is documented in `docs/benchmark/CI_EVIDENCE.md`.

## Before final submission numbers are copied into the paper

- [ ] Run on the designated Lenovo XiaoXinPro 16 AHP9 / AMD Ryzen 7 8845H Windows machine.
- [ ] V2 working tree is clean and exact commit recorded.
- [ ] GmSSL commit is `24ae482701a7b124826c382fffc55c19f76d475d`.
- [ ] Release build and compiler/CMake versions are recorded.
- [ ] Windows build, CPU and power mode are recorded.
- [ ] Warm-up >= 1000.
- [ ] Measured iterations >= 10000 per message-size × phase.
- [ ] Message sizes are 20, 128, 1024 and 4096 bytes.
- [ ] All upstream and V2 correctness/security tests pass before timing.
- [ ] Raw CSV contains all nine phases and all four message sizes.
- [ ] Summary fresh recomputation exactly matches the archived summary.
- [ ] `environment.json`, `raw.csv`, `summary.csv`, `hashes.json` and full logs are archived together.
- [ ] The manuscript reports mean, median, sample standard deviation and P95, with message size and platform identified.
- [ ] CI EPYC observations are not mixed with Ryzen results in the final platform table.

Use:

```powershell
powershell -ExecutionPolicy Bypass -File .\native\scripts\run_submission_windows.ps1
```

See `docs/benchmark/RYZEN_8845H_PROTOCOL.md` and `docs/benchmark/SUBMISSION_CHECKLIST.md`.

## Independent proof gate

Performance evidence does not validate the security proof. Before submission, independently confirm:

- [ ] Type-I is consistently described as Known-Secret Replacement, not strongest classical Type-I.
- [ ] Type-II scaled CDH embedding has complete ROM tables and query-loss accounting.
- [ ] HMAC is handled as multi-key/multi-user (or an explicit session-guess loss is paid).
- [ ] Same-message alternative randomized SM2 signatures are not misclassified as ordinary EUF-CMA new-message forgeries.
- [ ] SM3-KDF random-oracle wording is explicit.
- [ ] The modular SM9 identity-KEM assumption is mapped to an existing published SM9 theorem or remains explicitly modular.
