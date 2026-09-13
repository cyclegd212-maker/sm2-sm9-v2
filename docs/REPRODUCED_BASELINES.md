# Reproduced Baselines and Manuscript Reference Mapping

This file maps the same-platform native-C baseline reproductions used in the current PKI→CLC heterogeneous signcryption manuscript to their bibliography numbers.

> Important: these are independent reimplementations based on the algorithms/formulas described in the cited papers. They are not claimed to be the original authors' source code.

| Manuscript ref. | Baseline | Paper | Reproduction branch | Frozen reproduction commit |
|---|---|---|---|---|
| **[30]** | Liu 2018 | J. Liu, L. Zhang, R. Sun, X. Du, M. Guizani, “Mutual Heterogeneous Signcryption Schemes for 5G Network Slicings,” *IEEE Access*, vol. 6, pp. 7854–7863, 2018. DOI: 10.1109/ACCESS.2018.2797102 | `benchmark-liu2018-pchs` | `f937d244dfc01e0f73853225f138191a2d9a86ab` |
| **[34]** | HSC-MET 2022 | X. Yang, N. Ren, A. Chen, Z. Wang, C. Wang, “HSC-MET: Heterogeneous signcryption scheme supporting multi-ciphertext equality test for Internet of Drones,” *PLOS ONE*, 17(9): e0274695, 2022. DOI: 10.1371/journal.pone.0274695 | `benchmark-hscmet2022-pki-clc` | `81f44dfbe805ae76f3adb57e8dbe71088b2d3d18` |
| **[37]** | Gong 2025 | B. Gong, Y. Wu, J. Zhang, S. Tu, H. Alasmary, M. Waqas, “Multi-Heterogeneous Signcryption Scheme for Next Generation Slicing Networking,” *IEEE Transactions on Network Science and Engineering*, 2025. DOI: 10.1109/TNSE.2025.3571867 | `benchmark-gong2025-pki-clc` | `48ff94ef023dda1b942a329db36913c59238810b` |

## Experimental role

The three baselines above are the implementations used for the same-machine comparison against the proposed scheme. The manuscript compares the proposed **online signcryption critical path** with the complete `Signcrypt` path of these baselines under the fixed GmSSL/native-C environment.

- Liu 2018: reproduced PKI→CLC branch.
- HSC-MET 2022: reproduced with the minimum meaningful MET configuration `n = k = 2`, retaining the MET-related computation.
- Gong 2025: reproduced PKI→CLC branch and kept the paper's stated `2A+3M / A+3M` path without algebraic-shortcut optimization.

## Current same-platform mean Signcrypt timings

| Baseline | 20 B | 128 B | 1024 B | 4096 B |
|---|---:|---:|---:|---:|
| Liu 2018 [30] | 2.099 ms | 2.107 ms | 2.193 ms | 2.396 ms |
| HSC-MET 2022 [34] | 3.381 ms | 3.402 ms | 3.510 ms | 3.637 ms |
| Gong 2025 [37] | 3.573 ms | 3.556 ms | 3.559 ms | 3.506 ms |

The bibliography numbering in this file follows the current manuscript version in which these papers are references **[30]**, **[34]**, and **[37]**. If the bibliography is renumbered before submission, this mapping file must be updated synchronously.
