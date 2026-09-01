# Manuscript status

Current manuscript deliverables are generated separately from the code repository and tracked here by integrity metadata.

## Latest manuscript

- PDF: `SM2_SM9_V2_投稿标准化研究稿_SM3抽象与文献对比版.pdf`
- PDF SHA-256: `780c4141971810c2d5a6f985f269d4710775c3ce2baa32c0e6e027a7556266d3`
- Pages: 31
- LaTeX: `SM2_SM9_V2_投稿标准化研究稿_SM3抽象与文献对比版.tex`
- LaTeX SHA-256: `c514099c98a38d2a1e31f75f3c7a20e0164023f7d3e9f14e80bdf30236404bb0`
- Status: XeLaTeX compilation successful and all 31 pages rendered for layout inspection. The paper retains the finalized Type-I-KSR / Type-II / authenticity proofs, the validated Ryzen 7 8845H benchmark, and the corrected 231-byte native wire overhead.

## Hash/KDF/MAC abstraction

The theoretical construction no longer exposes SM3 as a scheme-level component. It uses abstract interfaces:

- `H : {0,1}* -> {0,1}^256`
- `KDF : {0,1}* -> {0,1}^ell`
- `MAC_K : {0,1}* -> {0,1}^256`

SM3, the SM3-based KDF and HMAC-SM3 are retained only as concrete GmSSL implementation instantiations. They are not claimed as innovations and the manuscript does not discuss SM3 compression/message-expansion internals. The implementation itself is unchanged so the archived Ryzen benchmark remains valid.

## Literature comparison policy

The manuscript does **not** reimplement other papers. Cross-paper evidence follows two rules:

1. directly cite security features, operation counts, communication expressions, and author-reported runtimes from the original paper (or an explicitly identified published comparison table);
2. where useful, map published major-operation counts onto the V2 Ryzen primitive-operation means to produce a **normalized major-operation cost** figure. This is structural normalization, not experimental reproduction.

No speedup factor is claimed by dividing another paper's CPU/library timing by the V2 Ryzen timing. Source accounting is documented in `docs/benchmark/LITERATURE_COMPARISON.md`.

Representative comparison set:

- Zhang et al. 2019, CLPKC→IDPKC online/offline heterogeneous signcryption, DOI `10.3969/j.issn.1007-130X.2019.05.007`;
- Iqbal et al. 2019, CLC→PKI online/offline heterogeneous signcryption, DOI `10.1177/1550147719875654`;
- Lai et al. 2017, identity-based online/offline signcryption, DOI `10.1007/s10207-016-0320-6`;
- Liu et al. 2018, PKI↔CLC mutual heterogeneous signcryption, DOI `10.1109/ACCESS.2018.2797102`;
- Xiong et al. 2022, IBC→PKI equality-test heterogeneous signcryption, DOI `10.1109/JSYST.2020.3048972`;
- Hou et al. 2023, CLC→PKI online/offline equality-test heterogeneous signcryption, DOI `10.1109/TVT.2023.3264672`.

The performance chapter now contains:

- functionality/security positioning table;
- directly sourced theoretical operation-count table;
- directly sourced communication-overhead table (with unverified byte fields left qualitative rather than fabricated);
- normalized major-operation cost bar chart;
- the physical Ryzen 7 8845H V2 measured tables/figures.

## Physical benchmark evidence

- Target: Lenovo XiaoXinPro 16 AHP9 / AMD Ryzen 7 8845H / Windows 11 10.0.26200
- V2 measured implementation commit: `b63cf0480a9e659e8717e9aa2fefce35c1702d82`
- GmSSL: `24ae482701a7b124826c382fffc55c19f76d475d`
- Build: MSYS2 UCRT64 GCC 16.2.0, CMake 4.4.3, Release, `-DENABLE_SM9=ON;-DENABLE_SM2_AMD64=OFF`
- Warm-up: 1000 complete iterations per payload
- Samples: 1000 per size × phase
- Payloads: 20/128/1024/4096 B
- Raw rows: 36000
- Evidence validation: PASS
- `raw.csv` SHA-256: `810db51e31bb54a3ebee7bcd7cf1157462c18c43f6d4f4f4e914968c5ba66559`
- `summary.csv` SHA-256: `62daba90689ba72ce2e3e45a3ac85de73a0a2e170fb5e4752209db51932cec58`
- `environment.json` SHA-256: `60fe4e5d89a308298ae22d2c3ee144b8d7dda4b5b93c875a8afa3ae7dd1fc762`
- Full evidence: `docs/benchmark/RYZEN8845H_EVIDENCE.md`

Mean V2 online signcryption latency is 0.554/0.563/0.602/0.680 ms for 20/128/1024/4096 B, respectively. The performance claim remains narrow: V2 reduces post-message-arrival online latency; it does not claim minimum total cost among all heterogeneous or pairing-free schemes.

## Security proof status

### Type-I-KSR

- Explicitly limited to known-secret replacement, not strongest arbitrary ReplacePublicKey.
- Missing identity factor is mapped to Cheng's SM9-KEM hidden pairing value and reduced to `Gap-q-BCAA1_{1,2}` in ROM.
- Proof: `docs/security/TYPE_I_KSR_REDUCTION.md`.

### Type-II

- Final scaled-CDH embedding uses honest `h*`, `c=h*+s`, `Q*=cP`, `X*=c[b]P`, `U*=c[a]P`, `Z2*=c[ab]P`.
- Half-advantage bound:
  `epsilon_II <= delta_II + (N_U q_K)/(2(1-1/q)) Adv_CDH_G1`,
  with `delta_II = Adv_SM2^EUF-CMA + Adv_MAC^PRF + q_usc*/2^256 + q_E*/2^256 + q_sc*/(q-1)`.
- Proof: `docs/security/TYPE_II_CDH_REDUCTION.md`.

### Authenticity

- Message-level new-`mu` forgery is reduced directly to SM2 EUF-CMA.
- Stronger transcript authenticity separates old-`mu`/new-signature binding and uses abstract multi-key MAC security while keeping `Pr[KeyAsk]` explicit.
- Proof: `docs/security/AUTHENTICITY_THEOREM.md`.

## Remaining main limitation

The largest theoretical limitation is still the Type-I-KSR model: it is weaker than unrestricted classical certificateless public-key replacement. Novelty claims must remain at the construction/composition level.
