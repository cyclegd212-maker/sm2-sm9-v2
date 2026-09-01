# Literature performance comparison evidence

This file records the evidence used by the manuscript's cross-paper performance comparison. Policy: **do not reimplement other papers, do not compare millisecond values across different platforms as if they were controlled benchmarks, and do not fabricate missing fields.**

## Zhang et al. 2019 — CLPKC→IDPKC online/offline heterogeneous signcryption

- Y. Zhang et al., “A provable secure from CLPKC to IDPKC online/offline heterogeneous signcryption scheme,” Computer Engineering & Science, 41(5):813–820, 2019.
- DOI: `10.3969/j.issn.1007-130X.2019.05.007`.
- The paper reports no pairing in the signcryption path and two pairings in unsigncryption.
- The manuscript preserves the original operation notation reported by the source/performance table: precomputation `2P`, offline `2e`, online `0e+0P`, unsigncryption `2P+1e`.
- `P/e` are only mapped as operation categories; parameter sets and implementations are not assumed identical to V2.

## Iqbal et al. 2019 — CLC→PKI online/offline heterogeneous signcryption

- J. Iqbal et al., “Efficient and secure attribute-based heterogeneous online/offline signcryption for body sensor networks based on blockchain,” International Journal of Distributed Sensor Networks, 15(9), 2019.
- DOI: `10.1177/1550147719875654`.
- Original Table 2 reports for the proposed scheme:
  - offline: `1E + 4M`
  - online: `0`
  - unsigncryption: `1E + 2Pr + 1M`
- The paper reports MICA2 primitive timings `M=0.81 s`, `Pr=1.90 s`, `E=0.9 s`.
- Its Table 3 reports encoded text of 640 bit; the accompanying transmission accounting gives a 120 B figure after including an additional 160-bit field under that paper's message/field assumptions.
- These source-reported seconds/bytes are cited as source data and are **not** divided by the Ryzen 8845H V2 timings to claim a speedup factor.

## Lai et al. 2017 — identity-based online/offline signcryption

- J. Lai, Y. Mu, F. Guo, “Efficient identity-based online/offline encryption and signcryption with short ciphertext,” International Journal of Information Security, 16(3):299–311, 2017.
- DOI: `10.1007/s10207-016-0320-6`.
- The manuscript uses Iqbal et al. 2019 Table 2's public re-tabulation of Lai's scheme:
  - offline `1E + 3M`
  - online `0`
  - unsigncryption `1E + 2Pr + 3M`
- Communication uses Iqbal Table 3's re-tabulation: encoded text 800 bit.
- The manuscript explicitly identifies this as a secondary-table source chain rather than our reproduction.

## Liu et al. 2018 — PKI↔CLC mutual heterogeneous signcryption

- J. Liu et al., “Mutual Heterogeneous Signcryption Schemes for 5G Network Slicings,” IEEE Access, 6:7854–7863, 2018.
- DOI: `10.1109/ACCESS.2018.2797102`.
- Original Table I reports PCHS:
  - key generation `4S+H`
  - signcryption `4S+2H`
  - unsigncryption `3S+2H`
  - communication `|G1|+|Zq*|+|m|`
  - direction PKI→CLC.
- Original Figure 6(b) reports PCHS signcryption+unsigncryption time: Ubuntu 12.684 ms and Raspberry Pi 70.050 ms.
- These values are preserved as author-reported cross-platform evidence, not treated as a controlled benchmark against the Ryzen V2 result.

## Xiong et al. 2022 — IBC→PKI with equality test

- H. Xiong et al., “Heterogeneous Signcryption Scheme From IBC to PKI With Equality Test for WBANs,” IEEE Systems Journal, 16(2):2391–2400, 2022.
- DOI: `10.1109/JSYST.2020.3048972`.
- Used for functional positioning: IBC→PKI and equality-test support with security/performance analysis.
- A complete byte-level ciphertext decomposition was not verified from the public source used in this audit, so the manuscript does not invent a byte count. It instead notes that equality-test fields represent an additional function and make direct communication-size ranking inappropriate without a common format.

## Hou et al. 2023 — CLC→PKI online/offline with equality test

- Y. Hou et al., “An Efficient Online/Offline Heterogeneous Signcryption Scheme With Equality Test for IoVs,” IEEE Transactions on Vehicular Technology, 72(9):12047–12062, 2023.
- DOI: `10.1109/TVT.2023.3264672`.
- Used for functional positioning: CLC→PKI, online/offline, equality test. The paper states that heavy/preparative computation is placed offline and lightweight work remains online.
- No numeric operation-count or ciphertext-size entry is inserted unless the original table is directly verified.

## Normalized major-operation figure

The manuscript's normalized bar chart is **not** an experimental reproduction of the cited schemes. It performs only the following transformation:

1. take source-reported major-operation counts;
2. multiply compatible categories by V2's Ryzen 7 8845H primitive means:
   - `T_p = 10.751 ms`
   - `T_1m = 0.689 ms`
   - `T_Te = 4.582 ms`
   - `T_Sm = 0.103 ms`;
3. omit light hash/XOR/ordinary modular arithmetic whose source definitions are inconsistent;
4. use the result only to illustrate whether major operations occur before or after message arrival.

The figure must be described as a **normalized major-operation cost comparison**, not as experimental runtime of the other schemes.

## V2 wire overhead

The native header defines:

`V2_CIPHERTEXT_FIXED_BYTES = 1 + 65 + 65 + 4 + 64 + 32 = 231 B`.

Thus the current self-contained native wire format is:

`|CT| = |M| + 231 B`.

For payloads 20/128/1024/4096 B the serialized sizes are 251/359/1255/4327 B. These values come from the implemented C wire format, not a theoretical estimate.
