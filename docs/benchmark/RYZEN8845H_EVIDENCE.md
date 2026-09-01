# Ryzen 7 8845H target-machine benchmark evidence

## Evidence identity

- Run ID: `ryzen8845h-20260901-131213`
- V2 implementation commit measured: `b63cf0480a9e659e8717e9aa2fefce35c1702d82`
- GmSSL commit: `24ae482701a7b124826c382fffc55c19f76d475d`
- Platform: Lenovo XiaoXinPro 16 AHP9 / AMD Ryzen 7 8845H / Windows 11 10.0.26200
- Logical CPUs: 16
- Compiler: MSYS2 UCRT64 GCC 16.2.0
- CMake: 4.4.3
- Build: Release
- GmSSL options: `-DENABLE_SM9=ON;-DENABLE_SM2_AMD64=OFF`
- Warm-up: 1000 complete protocol iterations per message size
- Measured samples: 1000 iterations for every size × phase group
- Message sizes: 20, 128, 1024, 4096 bytes
- Phases: 9
- Raw timing rows: 36000
- Evidence validation: PASS

The `ENABLE_SM2_AMD64=OFF` setting is intentional: on the pinned GmSSL revision, the Windows/MinGW AMD64 SM2 assembly path reproduced an upstream `sm2_sign` crash. The non-assembly path passed upstream SM2/SM3/HMAC-SM3/SM9 tests and all native V2 tests. Absolute timing results therefore apply to this exact build configuration.

## Integrity hashes

- `raw.csv`: `810db51e31bb54a3ebee7bcd7cf1157462c18c43f6d4f4f4e914968c5ba66559`
- `summary.csv`: `62daba90689ba72ce2e3e45a3ac85de73a0a2e170fb5e4752209db51932cec58`
- `environment.json`: `60fe4e5d89a308298ae22d2c3ee144b8d7dda4b5b93c875a8afa3ae7dd1fc762`
- uploaded evidence ZIP: `c9e73332441a5f73871413f212ab36afa4fe7a58ef84f0bcfe75ec555a193ca4`

Independent re-computation confirmed that every one of the 36 size × phase groups contains exactly 1000 samples with iteration indices 0–999 and that mean, median, sample standard deviation and nearest-rank P95 in `summary.csv` reproduce from `raw.csv`.

## Main target-machine results (ms)

| Message | Phase | Mean | Median | SD | P95 |
|---:|---|---:|---:|---:|---:|
| 20 B | offline signcrypt | 7.561 | 7.367 | 0.673 | 8.681 |
| 20 B | online signcrypt | 0.554 | 0.526 | 0.106 | 0.683 |
| 20 B | sender total | 8.144 | 7.918 | 1.233 | 9.134 |
| 20 B | unsigncrypt | 13.237 | 12.937 | 0.908 | 14.699 |
| 128 B | offline signcrypt | 7.722 | 7.541 | 0.652 | 8.975 |
| 128 B | online signcrypt | 0.563 | 0.530 | 0.124 | 0.689 |
| 128 B | sender total | 8.262 | 8.071 | 0.769 | 9.352 |
| 128 B | unsigncrypt | 13.887 | 13.665 | 0.794 | 15.429 |
| 1024 B | offline signcrypt | 7.698 | 7.504 | 0.692 | 8.908 |
| 1024 B | online signcrypt | 0.602 | 0.560 | 0.205 | 0.744 |
| 1024 B | sender total | 8.253 | 8.087 | 0.606 | 9.218 |
| 1024 B | unsigncrypt | 13.401 | 13.144 | 0.833 | 14.946 |
| 4096 B | offline signcrypt | 7.638 | 7.485 | 0.598 | 8.605 |
| 4096 B | online signcrypt | 0.680 | 0.643 | 0.123 | 0.847 |
| 4096 B | sender total | 8.296 | 8.119 | 0.648 | 9.333 |
| 4096 B | unsigncrypt | 13.520 | 13.307 | 0.716 | 14.797 |

Online signcryption accounts for roughly 6.8%–8.2% of sender-total mean time across the four payload sizes. The target result therefore supports the narrow claim that V2 substantially reduces **post-message-arrival online latency**; it does not establish lowest total cost against unrelated or pairing-free schemes.

## Communication overhead used in the manuscript

The native header defines `V2_CIPHERTEXT_FIXED_BYTES = 1 + 65 + 65 + 4 + 64 + 32 = 231` bytes. Therefore the current self-contained wire format has

`|CT| = |M| + 231 bytes`.

For payloads 20, 128, 1024 and 4096 bytes, serialized ciphertext sizes are 251, 359, 1255 and 4327 bytes respectively.

## Source-archive note

The target machine could reach GitHub codeload but `git clone` repeatedly timed out. The V2 source was therefore downloaded from the `feat/native-gmssl-v2` branch ZIP while that branch head was `b63cf0480a9e659e8717e9aa2fefce35c1702d82`; the benchmark command records that commit in every raw row. Because a GitHub ZIP archive has no `.git` directory, `environment.json` reports `git_head` and `git_status_porcelain` as unavailable. This limitation is disclosed rather than hidden.
