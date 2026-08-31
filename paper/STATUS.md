# Manuscript status

Current manuscript deliverables are generated separately from the code repository and tracked here by integrity metadata.

## Latest PDF

- Filename: `SM2_SM9_V2_投稿标准化研究稿_GapBCAA证明与Windows稳定版.pdf`
- SHA-256: `63a772920b5c1948fa036e2497f776d2afbb4cca7245a1bb27c989fd856e98ba`
- Pages: 24
- Status: compiled successfully with XeLaTeX and rendered page-by-page for layout inspection. The security section now contains the concrete Type-I-KSR → SM9-KEM → Gap-q-BCAA1_{1,2} bridge and the corrected Type-II plain-CDH/query-extraction distinction. CI timings remain reproducibility evidence rather than the final Ryzen submission benchmark.

## Latest LaTeX source

- Source filename: `SM2_SM9_V2_投稿标准化研究稿_GapBCAA证明与Windows稳定版.tex`
- SHA-256: `4bc0a9335732485cef6ca7a698d8d06f011a5329c2b33cd30310a1413d5117cc`
- Status: source used to generate the PDF above. Generated manuscript files are delivered separately; this status file records their integrity identity.

## Implementation evidence

- Native library: GmSSL 3.x pinned at `24ae482701a7b124826c382fffc55c19f76d475d`.
- Native V2 implements dual-factor KEM, single-token SM2 offline precomputation, one-time token lifecycle, canonical ciphertext encoding, online signcryption and unsigncryption.
- Correctness/adversarial coverage includes round trips, field tampering, wrong keys, invalid/infinity points, token reuse, and Type-I-KSR/Type-II knowledge-path demonstrations.
- Current verified branch head: `88ba1854b3dd2701daa3437d546c653bb1a85abc`.
- On that head the Linux native CI, Windows native smoke, benchmark metadata contract, and Windows submission-script check all complete successfully.

## Windows toolchain status

- Reproduced failure configuration: Windows 2025 + Ninja + MinGW GCC 15.2 + pinned GmSSL with `ENABLE_SM2_AMD64=ON`.
- Failure: GmSSL's own upstream `sm2_sign` test segfaults while SM3/HMAC-SM3/SM9 pass.
- Single-variable resolution: setting `-DENABLE_SM2_AMD64=OFF` on the same Windows/MinGW toolchain makes upstream SM2/SM3/HMAC-SM3/SM9, all native V2 tests, and a real Windows benchmark smoke run pass.
- Formal Windows submission runner therefore pins `-DENABLE_SM9=ON;-DENABLE_SM2_AMD64=OFF`, records those options in `environment.json`/`hashes.json`, adds the installed GmSSL `bin` directory to `PATH`, and records the Windows CPU marketing name through `Win32_Processor.Name` when available.
- This is an evidence-preserving compatibility choice. Because disabling the AMD64 SM2 assembly path changes absolute timing, the option must be reported with final performance results.

## Benchmark status

- CI reproducibility benchmark: `MEASURED`.
- Verified CI evidence contains four message sizes and all measured phases with raw samples, derived summary, environment metadata, and logs.
- Submission benchmark (Lenovo XiaoXinPro 16 AHP9 / Ryzen 7 8845H): `NOT_MEASURED`.
- Formal target-machine protocol remains: warmup >= 1000 and iterations >= 10000 for each size×phase, followed by independent raw/summary/environment/log review.

## Proof status

### Type-I-KSR confidentiality

- Model: Known-Secret Public-Key Replacement (Type-I-KSR), explicitly weaker than the strongest classical CL-PKC arbitrary public-key replacement model.
- Exact identity-factor mapping is now checked:
  `Q_B=[h_B+s]P1`, `d_B=[s/(h_B+s)]P2`, `U=[rho]Q_B`, hence
  `Z1=e(U,d_B)=e(P1,P2)^(rho s)=g^rho`.
- This is exactly the hidden pairing value of Cheng's SM9-KEM security analysis (Theorem 4, INSCRYPT 2018, DOI `10.1007/978-3-030-14234-6_1`).
- Under Type-I-KSR the active user-factor secret `x_B` is known to the adversary/simulator, so `Z2=[x_B]U` is computable and enters the session KDF as auxiliary known input.
- Concrete base assumption for the Cheng path: `Gap-q-BCAA1_{1,2}` in the random-oracle model, not ordinary `q-BDHI`.
- The Gap reduction can test candidate hidden pairing values with the DBIDH oracle; therefore challenge-identity KDF-query count enters reduction running time rather than adding an unsupported `1/q_K` advantage loss.
- Reviewer-grade proof skeleton: `docs/security/TYPE_I_KSR_REDUCTION.md`.

### Type-II confidentiality

- Type-II proof retains the distribution-preserving scaled CDH embedding with honest challenge `H_1` output: `c=h*+s`, `Q*=cP`, `U*=c[a]P`, `X*=c[b]P`, `Z2*=c[ab]P`.
- Plain-CDH simulator has no gap/DDH oracle for testing arbitrary candidate `Z2`; therefore the current proof path retains explicit critical KDF-query extraction/guessing loss and cannot copy the Type-I Gap-BCAA accounting.
- Reviewer-level oracle/bad-event skeleton: `docs/security/TYPE_II_CDH_REDUCTION.md`.

### Authentication

- Confidentiality and authenticity are now separated to avoid double-counting assumptions.
- Type-I confidentiality is expressed through the SM9-derived KEM plus authenticated one-time DEM; SM2 EUF-CMA is reserved for the separate authentication/unforgeability theorem.
- Multi-session authenticity still requires an explicit multi-key HMAC PRF/UFCMA treatment or a target-session guessing reduction.

## Remaining pre-submission gates

1. **Physical target measurement only:** run `native/scripts/run_submission_windows.ps1` on the designated Ryzen 7 8845H machine. This cannot be substituted by GitHub-hosted CI.
2. Independently audit the resulting target-machine `raw.csv`, `summary.csv`, `environment.json`, logs, and hashes before changing `submission_benchmark` to `MEASURED`.
3. Freeze the exact Type-II game/query counts and derive its final numerical advantage coefficients from the complete oracle simulation rather than using a structural template.
4. Finish the standalone multi-session signcryption authenticity theorem (SM2 EUF-CMA + multi-key HMAC) and ensure its events are not double-counted in confidentiality.
5. Keep all novelty claims at the construction/composition level and retain the explicit Type-I-KSR limitation.
