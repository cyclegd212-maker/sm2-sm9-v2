# Manuscript status

Current manuscript deliverables are generated separately from the code repository and tracked here by integrity metadata.

## Latest PDF

- Filename: `SM2_SM9_V2_投稿标准化研究稿_8845H实测与图表版.pdf`
- SHA-256: `cb3bcd29bfe44618a4a9855b1e9c0ecdd713d5b123cabb7ed8f522c546aa125a`
- Pages: 27
- Status: compiled successfully with XeLaTeX and rendered page-by-page for layout inspection. The performance section now contains the physical Ryzen 7 8845H benchmark, the corrected 231-byte self-contained wire overhead, and four submission figures for computation, online scaling, primitive operation cost, and communication overhead.

## Latest LaTeX source

- Source filename: `SM2_SM9_V2_投稿标准化研究稿_8845H实测与图表版.tex`
- SHA-256: `bf3809ad7699c6ae60bbfa693ed89c79557d7adcbe9392ab6caee3b20dd940f9`
- Status: source used to generate the PDF above. Generated manuscript files are delivered separately; this status file records their integrity identity.

## Implementation evidence

- Native library: GmSSL 3.x pinned at `24ae482701a7b124826c382fffc55c19f76d475d`.
- Measured V2 implementation commit: `b63cf0480a9e659e8717e9aa2fefce35c1702d82`.
- Native V2 implements dual-factor KEM, single-token SM2 offline precomputation, one-time token lifecycle, canonical ciphertext encoding, online signcryption and unsigncryption.
- Correctness/adversarial coverage includes round trips, field tampering, wrong keys, invalid/infinity points, token reuse, and Type-I-KSR/Type-II knowledge-path demonstrations.

## Windows toolchain status

- Reproduced failure configuration: Windows + Ninja + MinGW + pinned GmSSL with `ENABLE_SM2_AMD64=ON`.
- Failure: GmSSL's own upstream `sm2_sign` test segfaults while SM3/HMAC-SM3/SM9 pass.
- Single-variable resolution: setting `-DENABLE_SM2_AMD64=OFF` makes upstream SM2/SM3/HMAC-SM3/SM9, all native V2 tests, and benchmark execution pass.
- Target measurements therefore use `-DENABLE_SM9=ON;-DENABLE_SM2_AMD64=OFF`; this option is part of the evidence identity and must be disclosed with the latency numbers.

## Benchmark status

- CI reproducibility benchmark: `MEASURED`.
- Physical submission benchmark (Lenovo XiaoXinPro 16 AHP9 / Ryzen 7 8845H): `MEASURED`.
- Target run ID: `ryzen8845h-20260901-131213`.
- OS: Windows 11 10.0.26200.
- CPU: AMD Ryzen 7 8845H, 16 logical processors.
- Compiler: MSYS2 UCRT64 GCC 16.2.0; CMake 4.4.3; Release build.
- Warm-up: 1000 complete protocol iterations per message size.
- Measured samples: 1000 per size × phase.
- Sizes: 20, 128, 1024, 4096 B.
- Raw rows: 36000 = 4 sizes × 9 phases × 1000 samples.
- Evidence validation: PASS.
- `raw.csv` SHA-256: `810db51e31bb54a3ebee7bcd7cf1157462c18c43f6d4f4f4e914968c5ba66559`.
- `summary.csv` SHA-256: `62daba90689ba72ce2e3e45a3ac85de73a0a2e170fb5e4752209db51932cec58`.
- `environment.json` SHA-256: `60fe4e5d89a308298ae22d2c3ee144b8d7dda4b5b93c875a8afa3ae7dd1fc762`.
- Uploaded evidence ZIP SHA-256: `c9e73332441a5f73871413f212ab36afa4fe7a58ef84f0bcfe75ec555a193ca4`.
- Full target evidence summary: `docs/benchmark/RYZEN8845H_EVIDENCE.md`.

The branch source was downloaded to the target machine as a GitHub ZIP because `git clone` timed out. The branch head was recorded as `b63cf0480a9e659e8717e9aa2fefce35c1702d82` in the benchmark commands and raw rows; `.git` metadata is absent in the ZIP, so `environment.json` correctly reports `git_head` as unavailable. This limitation is disclosed.

## Communication overhead correction

The native header defines `V2_CIPHERTEXT_FIXED_BYTES = 1 + 65 + 65 + 4 + 64 + 32 = 231` bytes. Therefore the actual current self-contained wire format is `|CT| = |M| + 231 B`; earlier 226-byte estimates omitted the 1-byte version and 4-byte ciphertext-length fields and are superseded.

## Proof status

### Type-I-KSR confidentiality

- Model: Known-Secret Public-Key Replacement (Type-I-KSR), explicitly weaker than the strongest classical CL-PKC arbitrary public-key replacement model.
- `Z1=e(U,d_B)=g^rho` is mapped to the hidden pairing value of Cheng's SM9-KEM proof.
- Concrete base assumption for the Cheng path: `Gap-q-BCAA1_{1,2}` in the random-oracle model, not ordinary `q-BDHI`.
- The full confidentiality bound cites the generic ID-KEM/one-time-DEM hybrid theorem of Bentahar et al., Journal of Cryptology 21(2):178–199, DOI `10.1007/s00145-007-9000-z`.
- Reviewer-grade proof skeleton: `docs/security/TYPE_I_KSR_REDUCTION.md`.

### Type-II confidentiality

- Type-II proof retains the distribution-preserving scaled CDH embedding with honest challenge `H_1` output: `c=h*+s`, `Q*=cP`, `U*=c[a]P`, `X*=c[b]P`, `Z2*=c[ab]P`.
- Plain-CDH simulator has no gap/DDH oracle for testing arbitrary candidate `Z2`; therefore the current proof path retains explicit critical KDF-query extraction/guessing loss.
- Reviewer-level oracle/bad-event skeleton: `docs/security/TYPE_II_CDH_REDUCTION.md`.

### Authentication

- Confidentiality and authenticity are separated to avoid double-counting assumptions.
- Multi-session authenticity still requires an explicit multi-key HMAC PRF/UFCMA treatment or a target-session guessing reduction.

## Remaining pre-submission gates

1. Freeze the exact Type-II game/query counts and derive its final numerical advantage coefficients from the complete oracle simulation rather than a structural template.
2. Finish the standalone multi-session signcryption authenticity theorem (SM2 EUF-CMA + multi-key HMAC) and ensure its events are not double-counted in confidentiality.
3. If time permits, repeat the same target benchmark 2–3 times to quantify run-to-run variation and CPU dynamic-frequency effects.
4. Keep all novelty claims at the construction/composition level and retain the explicit Type-I-KSR limitation.
