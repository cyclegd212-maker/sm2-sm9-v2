# Gong 2025 PKI→CLC Same-Platform Reproduction

## Scope

This branch reimplements only the PKI→CLC branch of Bei Gong et al., *Multi-Heterogeneous Signcryption Scheme for Next Generation Slicing Networking*, IEEE Transactions on Network Science and Engineering, DOI `10.1109/TNSE.2025.3571867`.

This is a faithful algebraic reimplementation adapted to the same GmSSL/SM2 group environment used by the V2 implementation. It is **not** the authors' original code or original Python/Pypbc execution environment.

## Paper mapping

### PKI sender

The paper defines:

- `SK_S = x_S`
- `P_S = [x_S^{-1}]P`

The inverse-public-key relation is preserved exactly.

### CLC receiver

The implementation follows:

- `P_R = [x_R]P`
- `R_R = [r_R]P`
- `h_R = H1(ID_R, R_R, P_R)`
- `d_R = r_R + s*h_R mod q`
- `X_R = [h_R^{-1}]R_R`
- `SK_R = (x_R, d_R)`
- `PK_R = (P_R, R_R, X_R)`

The test suite verifies `[d_R]P = R_R + [h_R]P_pub`.

### PKI→CLC signcryption

The paper path is implemented directly:

1. `T1 = [a]P_S`
2. `B_R = [h_R^{-1}]P_R + X_R + P_pub`
3. `z = a*h_R*x_S^{-1} mod q`
4. `T2 = [z]B_R`
5. `c = m XOR H2(T2)`
6. `h = h4(ID_S, ID_R, P_S, P_R, R_R, X_R, P_pub, c, T1)`
7. `S = a + h*x_S mod q`
8. `sigma = (c,S,T1)`

No cross-step algebraic simplification is used in the timed signcryption path. This preserves the paper's PKI→CLC theoretical count of `2A + 3M`.

### Unsigncryption

The receiver computes:

1. `h = h4(...)`
2. `T1' = [S]P_S - [h]P`
3. reject unless `T1' == T1`
4. `T2' = [x_R + d_R]T1'`
5. `m = c XOR H2(T2')`

This corresponds to the paper's `A + 3M` count.

## Concrete same-platform instantiation

Gong et al. define an abstract prime-order additive group. For same-platform comparison, this implementation instantiates that group with the same GmSSL SM2 256-bit prime-order elliptic-curve group used by the local benchmark framework.

- GmSSL commit: `24ae482701a7b124826c382fffc55c19f76d475d`
- Group encoding: 65-byte uncompressed SM2 points
- `H1`: SM3 with domain separation and length-delimited canonical inputs, reduced/rejected to nonzero SM2 scalar
- `H2`: SM3-KDF over domain-separated canonical `T2` encoding
- PKI→CLC `h4`: SM3 with independent domain separation over exactly `ID_S, ID_R, P_S, P_R, R_R, X_R, P_pub, c, T1`, reduced/rejected to nonzero scalar

This concrete hash/KDF choice is an engineering instantiation needed because the paper models the hash functions abstractly.

## Correctness tests

The test suite covers message sizes `0,1,20,128,1024,4096` bytes and verifies:

- CLC partial-key relation
- recovered `T1' == T1`
- sender paper-path `T2 == receiver T2'`
- full message round trip
- rejection after tampering with `c`, `S`, `T1`, sender `P_S`, and receiver public components `P_R`, `R_R`, `X_R`

A corrupted local receiver secret `x_R` is required to fail to recover the original plaintext; the original Gong unsigncryption algorithm does not contain an independent secret-key consistency check, so forcing an explicit rejection would add an operation not present in the paper.

## Formal benchmark protocol

The Windows formal runner uses:

- AMD Ryzen 7 8845H target machine
- MSYS2 UCRT64 GCC 16.2.0
- Release build
- the pinned GmSSL commit above
- `QueryPerformanceCounter`
- message sizes `20,128,1024,4096` bytes
- 1000 warm-up round trips per size
- 1000 measured iterations per phase per size

Raw phases:

- `gong2025_sender_signcrypt`
- `gong2025_unsigncrypt`

Expected formal sample count: `4 * 2 * 1000 = 8000`.

## Comparison semantics

The preregistered primary metric is:

`(Gong complete signcrypt - V2 online signcrypt) / Gong complete signcrypt * 100%`.

The comparison script must also report, even when unfavorable to V2:

- V2 sender total vs Gong complete signcrypt
- V2 unsigncrypt vs Gong unsigncrypt

Only raw same-machine measurements with the same GmSSL commit are accepted by the comparison script.

## Security-model limitation

Gong et al. provide a generalized construction supporting six heterogeneous directions, including PKI→CLC. However, their formal reduction section explicitly chooses the PKI→IBC branch as the worked security-proof case. The PKI→CLC branch is therefore used here as a **same-direction performance baseline**, not as evidence of an equivalent CLC Type-I/Type-II security model.

CI timings are correctness evidence only and must never be reported as the user's Windows performance results.
