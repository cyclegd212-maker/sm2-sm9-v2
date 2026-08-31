# Native GmSSL CI reproducibility benchmark evidence

本文件记录第一次通过全部证据门禁的真实 CI benchmark。它证明“仓库中存在可执行的 native V2、测试和可复现测量管线”，但**不是**最终投稿平台 Ryzen 7 8845H 的性能结果。

## Evidence identity

- GitHub Actions run: `33383426286`
- Artifact ID: `9754694893`
- Artifact name: `v2-ci-evidence-c0f3247fea828c37970dbf03f66c5aa18bc3e837`
- V2 commit: `c0f3247fea828c37970dbf03f66c5aa18bc3e837`
- GmSSL commit: `24ae482701a7b124826c382fffc55c19f76d475d`
- Artifact SHA-256: `ac8890926e1a859a02323ea412ce2d6346e7e8fda46f14406e06539c1349dbb9`
- Raw CSV SHA-256: `696e020b116e47ff359fa5ed8cf9d6504c6314a3c3057433de5ba879803ba49d`
- Summary CSV SHA-256: `b875325b109ea1ed567e6ff9da5d70470b63a8aca094529c4219c7485afccca2`

## Environment

- GitHub hosted runner
- CPU reported by runner: `AMD EPYC 7763 64-Core Processor`
- Logical CPUs visible: 4
- Linux kernel: `6.17.0-1022-azure`
- GCC: `13.3.0`
- CMake: `3.31.6`
- Build type: `Release`
- CI warmup: 10
- Formal samples: 50 per message-size × phase group

## Integrity validation

The downloaded raw artifact was independently checked after the workflow finished:

- message sizes: `20, 128, 1024, 4096 B`;
- phases: 9;
- groups: `4 × 9 = 36`;
- every group contains exactly 50 raw samples;
- total raw rows: `36 × 50 = 1800`;
- exactly one `(run_id, V2 commit, GmSSL commit)` identity occurs in raw data;
- `summary.csv` exactly matches a fresh recomputation from `raw.csv`;
- artifact ZIP SHA-256 matches the digest returned by GitHub Actions.

`evidence-validation.log` result:

```text
benchmark evidence validation: ok
```

## Selected CI observations

These numbers are reported here only to describe the CI run; they must be labeled **CI reproducibility benchmark** if mentioned elsewhere.

| Message | Phase | Mean | Median | P95 |
|---:|---|---:|---:|---:|
| 20 B | offline signcryption | 5.214 ms | 5.207 ms | 5.415 ms |
| 20 B | online signcryption | 0.290 ms | 0.286 ms | 0.310 ms |
| 20 B | unsigncryption | 9.103 ms | 9.072 ms | 9.296 ms |
| 128 B | offline signcryption | 5.223 ms | 5.160 ms | 5.362 ms |
| 128 B | online signcryption | 0.291 ms | 0.289 ms | 0.300 ms |
| 128 B | unsigncryption | 9.061 ms | 9.015 ms | 9.080 ms |
| 1024 B | online signcryption | 0.317 ms | 0.315 ms | 0.324 ms |
| 4096 B | online signcryption | 0.390 ms | 0.386 ms | 0.398 ms |

The same artifact measured GmSSL primitives on the same runner: a pairing is about 8 ms, GT exponentiation about 3.3–3.5 ms, and SM9 G1 scalar multiplication about 0.5 ms. These observations explain why moving SM9 heavy operations out of the online sender phase materially changes online latency. They are **not** transferable to another CPU or library build.

## What may be claimed

It is now supported to say:

> A pinned native GmSSL implementation of V2 has been compiled and tested in GitHub Actions, and a reproducible CI benchmark artifact containing environment metadata, raw samples, derived statistics, and logs has been archived.

It is **not** yet supported to say:

> The manuscript's final platform latency is X ms.

The latter requires the designated Lenovo XiaoXinPro 16 AHP9 / Ryzen 7 8845H submission run with the same code/evidence protocol.
