# Manuscript status

Current manuscript deliverables are generated separately from the code repository and tracked here by integrity metadata.

## Latest PDF

- Filename: `SM2_SM9_V2_投稿标准化研究稿_原生实现与CI实测版.pdf`
- SHA-256: `3a0a169dadc898ae9bb5895288b12f9879b063873e4b8b1e0570253f00d431d5`
- Pages: 22
- Status: compiled successfully with XeLaTeX and rendered page-by-page for layout inspection. It includes the verified native GmSSL CI reproducibility benchmark, but it does **not** present CI timings as the final Ryzen submission benchmark.

## Latest LaTeX source

- Source filename: `SM2_SM9_V2_投稿标准化研究稿_原生实现与CI实测版.tex`
- SHA-256: `192a2d7c8239fb593c1a8bf1b5ff848251447b2a7667546ca40da1a188c25437`
- Status: source used to generate the PDF above. The generated manuscript files are delivered separately from the code repository; this status file records their integrity identity.

## Implementation evidence

- Native library: GmSSL 3.x pinned at `24ae482701a7b124826c382fffc55c19f76d475d`.
- Native V2 implements dual-factor KEM, single-token SM2 offline precomputation, one-time token lifecycle, canonical ciphertext encoding, online signcryption and unsigncryption.
- Correctness/adversarial coverage includes round trips, field tampering, wrong keys, invalid/infinity points, token reuse, and Type-I-KSR/Type-II knowledge-path demonstrations.

## Benchmark status

- CI reproducibility benchmark: `MEASURED`.
- Verified evidence run: GitHub Actions `33383426286`.
- Evidence V2 commit: `c0f3247fea828c37970dbf03f66c5aa18bc3e837`.
- Evidence artifact ID: `9754694893`.
- Evidence artifact SHA-256: `ac8890926e1a859a02323ea412ce2d6346e7e8fda46f14406e06539c1349dbb9`.
- Raw rows independently verified: 1800 = 4 message sizes × 9 phases × 50 measured iterations.
- Submission benchmark (Lenovo XiaoXinPro 16 AHP9 / Ryzen 7 8845H): `NOT_MEASURED`.

## Proof status

- Type-I model: Known-Secret Replacement (Type-I-KSR), explicitly weaker than the strongest classical CL-PKC arbitrary public-key replacement model.
- Type-II proof: scaled CDH embedding with honestly distributed challenge `H_1` output; no detectable programming such as `H_1(ID*)=1-s`.
- HMAC accounting: manuscript now uses multi-key HMAC security notation rather than silently applying a single-key advantage to independent session keys.
- SM9 identity factor: Cheng 2018 provides a formal ROM security analysis for SM9 encryption/key agreement, but the exact theorem-to-V2-KEM hardness mapping is not claimed until the source proof is checked in detail; the manuscript keeps this as a modular SM9-ID-KEM assumption meanwhile.

## Remaining pre-submission gates

1. Run the fail-closed Windows submission script on the designated Ryzen 7 8845H machine with warmup >= 1000 and iterations >= 10000 per size×phase.
2. Independently review the generated target-machine raw/summary/environment/log evidence before setting `submission_benchmark` to `MEASURED`.
3. Finish reviewer-level proof tightening for Type-I-KSR and the exact SM9-ID-KEM hardness bridge.
4. Keep novelty claims at the combination/construction level, not at the individual user-secret or SM2-precomputation component level.
