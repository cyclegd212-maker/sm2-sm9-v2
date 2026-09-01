# Manuscript status

Current manuscript deliverables are generated separately from the code repository and tracked here by integrity metadata.

## Latest PDF

- Filename: `SM2_SM9_V2_投稿标准化研究稿_TypeII与Authenticity终审版.pdf`
- SHA-256: `50aa22b70d6aec3a92861b64c435f56296c5d2a4370e93b71b3ea829b242ab46`
- Pages: 29
- Status: compiled successfully with XeLaTeX and rendered page-by-page for layout inspection. The security section now contains the finalized Type-II plain-CDH coefficient/oracle simulation and an independent two-layer authenticity treatment separating message-level SM2 EUF-CMA from transcript-level multi-key HMAC binding. The Ryzen 7 8845H physical benchmark and 231-byte wire-overhead correction remain included.

## Latest LaTeX source

- Source filename: `SM2_SM9_V2_投稿标准化研究稿_TypeII与Authenticity终审版.tex`
- SHA-256: `f0fd402bcabf1ace2a5d534a9ba2775367188dc75c88de82afc8bb675347bb05`
- Status: source used to generate the PDF above. Generated manuscript files are delivered separately; this status file records their integrity identity.

## Implementation evidence

- Native library: GmSSL 3.x pinned at `24ae482701a7b124826c382fffc55c19f76d475d`.
- Measured V2 implementation commit: `b63cf0480a9e659e8717e9aa2fefce35c1702d82`.
- Native V2 implements dual-factor KEM, single-token SM2 offline precomputation, one-time token lifecycle, canonical ciphertext encoding, online signcryption and unsigncryption.
- Correctness/adversarial coverage includes round trips, field tampering, wrong keys, invalid/infinity points, token reuse, and Type-I-KSR/Type-II knowledge-path demonstrations.

## Benchmark status

- CI reproducibility benchmark: `MEASURED`.
- Physical submission benchmark (Lenovo XiaoXinPro 16 AHP9 / Ryzen 7 8845H): `MEASURED`.
- Target run ID: `ryzen8845h-20260901-131213`.
- OS: Windows 11 10.0.26200.
- CPU: AMD Ryzen 7 8845H, 16 logical processors.
- Compiler: MSYS2 UCRT64 GCC 16.2.0; CMake 4.4.3; Release build.
- GmSSL build: `-DENABLE_SM9=ON;-DENABLE_SM2_AMD64=OFF`.
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

The branch source was downloaded to the target machine as a GitHub ZIP because `git clone` timed out. The benchmark rows explicitly record implementation commit `b63cf0480a9e659e8717e9aa2fefce35c1702d82`; `.git` metadata is absent in the ZIP and this limitation is disclosed.

## Communication overhead correction

The native header defines `V2_CIPHERTEXT_FIXED_BYTES = 1 + 65 + 65 + 4 + 64 + 32 = 231` bytes. Therefore the current self-contained wire format is `|CT| = |M| + 231 B`.

## Proof status

### Type-I-KSR confidentiality

- Model: Known-Secret Public-Key Replacement (Type-I-KSR), explicitly weaker than the strongest classical CL-PKC arbitrary public-key replacement model.
- `Z1=e(U,d_B)=g^rho` is mapped to the hidden pairing value of Cheng's SM9-KEM proof.
- Base assumption for the Cheng path: `Gap-q-BCAA1_{1,2}` in the random-oracle model, not ordinary `q-BDHI`.
- The full confidentiality bound cites the generic ID-KEM/one-time-DEM hybrid theorem of Bentahar et al., Journal of Cryptology 21(2):178–199, DOI `10.1007/s00145-007-9000-z`.
- Reviewer-grade proof: `docs/security/TYPE_I_KSR_REDUCTION.md`.

### Type-II confidentiality — FINALIZED FOR CURRENT MODEL

- Uses a distribution-preserving user-public-key CDH embedding: honest `h*`, `c=h*+s`, `Q*=cP`, `X*=c[b]P`, challenge `U*=c[a]P`, and `Z2*=c[ab]P`.
- Challenge-user guessing is tightened to `N_U`, the number of receiver user-public-key instantiations, rather than all `H1` identities; current interface permits the conservative bound `N_U <= q_x+q_sc+q_usc+1`.
- Explicitly pays challenge-state Signcrypt collision `Pr[Coll_U] <= q_sc*/(q-1)`.
- Challenge-user Unsigncrypt simulation is split into three exhaustive cases: new `mu` -> SM2 EUF-CMA; ordinary `L_SC` records -> exact simulation with stored `K_M`; challenge `mu*` alternate signatures -> single-target HMAC PRF hybrid plus `q_usc*/2^256` random-tag guessing.
- Plain CDH still requires critical `H_K` query-index extraction; no Gap/DDH oracle is silently assumed.
- Under the manuscript half-advantage convention `epsilon_II=|Pr[b'=b]-1/2|`, define
  `delta_II = Adv_SM2^EUF-CMA + Adv_HMAC^PRF + q_usc*/2^256 + q_E*/2^256 + q_sc*/(q-1)`.
  Then the finalized bound is
  `epsilon_II <= delta_II + (N_U q_K)/(2(1-1/q)) Adv_CDH_G1`.
- The runtime account no longer charges a group multiplication for every candidate `H_K` query; candidate processing is parse/compare/table work and the `c^{-1}` scalar multiplication occurs once on successful extraction.
- Reviewer-grade proof: `docs/security/TYPE_II_CDH_REDUCTION.md`.

### Authentication — TWO LAYERS FINALIZED

- Message-level EUF-CMA: any accepted ciphertext whose canonical `mu` was never signed yields a direct SM2 EUF-CMA forgery. No HMAC term and no strong-unforgeability assumption are needed.
- Stronger transcript authenticity is separately defined for accepted ciphertexts that are not byte-identical to any historical Signcrypt output.
- For an old `mu_i`, canonical injectivity forces the same `(X,U,C)` and session key. A new accepted ciphertext must therefore use `sigma* != sigma_i`, making `Enc(MAC,mu_i,sigma*)` a new HMAC message.
- The transcript theorem explicitly exposes `KeyAsk`: if the adversary has already queried the exact session-KDF input and recovered `K_M`, HMAC secrecy is gone and that event must be bounded by the receiver-side KEM proof rather than mislabeled as a MAC forgery.
- With multi-key HMAC notation:
  `Pr[Forge_T] <= Adv_SM2^EUF-CMA + Adv_HMAC^{mu-UF-CMA} + Pr[KeyAsk] + negl_enc`.
  A conservative single-key corollary is
  `Pr[Forge_T] <= Adv_SM2^EUF-CMA + q_sc Adv_HMAC^{UF-CMA} + Pr[KeyAsk] + negl_enc`.
- HMAC constructional support cites Bellare, Journal of Cryptology 28(4):844–878, DOI `10.1007/s00145-014-9185-x`; multi-user linear guessing-loss context cites Morgan–Pass–Shi, ASIACRYPT 2020, DOI `10.1007/978-3-030-64837-4_24`; SM2 EUF-CMA positioning cites Zhang–Yang–Zhang–Chen, SSR 2015, DOI `10.1007/978-3-319-27152-1_7`.
- Reviewer-grade proof: `docs/security/AUTHENTICITY_THEOREM.md`.

## Remaining pre-submission gates

1. The main theoretical limitation remains the Type-I-KSR model itself: it is not the strongest arbitrary ReplacePublicKey model.
2. If the manuscript claims transcript-level authenticity rather than only message-level EUF-CMA, `Pr[KeyAsk]` must remain explicit or be instantiated with the corresponding Type-I/Type-II KEM key-hiding theorem; it cannot simply be deleted.
3. If time permits, repeat the target benchmark 2–3 times to quantify run-to-run variation and CPU dynamic-frequency effects; the current 1000-sample run is already archived and validated.
4. Keep novelty claims at the construction/composition level and retain the explicit Type-I-KSR limitation.
