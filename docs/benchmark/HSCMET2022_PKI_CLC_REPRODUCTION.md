# HSC-MET 2022 PKI→CLC Same-Platform Reproduction

## Scope

This benchmark implements the PKI→CLC signcryption/unsigncryption path of Yang et al., *HSC-MET: Heterogeneous signcryption scheme supporting multi-ciphertext equality test for Internet of Drones*, PLOS ONE (2022), DOI `10.1371/journal.pone.0274695`.

It is a **faithful algebraic, adapted same-platform reimplementation**, not the authors' original code or original experimental platform.

## Why this is a supplemental benchmark

HSC-MET provides multi-ciphertext equality test (MET), while the V2 SM2/PKI→SM9-structured-CLC proposal does not. Therefore HSC-MET is reported as a functionality-enhanced supplemental same-direction PKI→CLC benchmark. Any latency difference must not be described as an equal-function absolute efficiency advantage.

## Fixed MET configuration

The source scheme supports a maximum MET parameter `n` and per-ciphertext `k`. This implementation fixes:

- `n = 2`
- `k = 2`

This is the minimum meaningful multi-ciphertext configuration and avoids artificially inflating the competitor's MET overhead.

For `k=2`, the polynomial is represented exactly by two coefficients:

- `f0 = H1(m || 2)`
- `f1 = H1(m || 2 || f0)`
- `f2(X) = f0 + f1*X mod q`

The signcryption path still generates `C3` and `C4`, and unsigncryption still recovers and verifies them. The MET-related signcryption/unsigncryption work is therefore not removed from the measured protocol path. The separate cloud equality-test operation itself is outside the signcryption/unsigncryption timing boundary.

## Group and hash adaptation

The paper specifies an abstract prime-order additive group. For same-platform measurement, the group is instantiated with the GmSSL SM2 256-bit prime-order elliptic-curve group.

Pinned GmSSL commit:

`24ae482701a7b124826c382fffc55c19f76d475d`

Canonical encodings:

- curve points: 65-byte uncompressed SM2 point encoding;
- scalars: fixed 32-byte big-endian encoding.

Hash instantiation:

- H1: SM3 with domain separation and length framing, rejection sampled to a nonzero scalar modulo the SM2 order;
- H2: SM3-KDF over the canonical point encoding;
- H3: SM3-KDF over the canonical point encoding, fixed 64-byte output for `X || f2(X)` at `n=2`;
- H4: SM3 over framed canonical ciphertext/MET fields.

The paper writes H2 output as `{0,1}^{2l}`. To benchmark the same 20/128/1024/4096-byte application messages already used by V2, Liu 2018 and Gong 2025, this implementation derives exactly `message_bytes + 32` bytes for the `(m || r)` mask. This variable-message-length KDF adaptation is recorded in `environment.json` and must be disclosed in the paper.

## Correctness gates

Before timing, the native tests verify:

- `PK_p = [SK_p]P`;
- `[SK_c1]P = PK_c1 + [H1(ID_c)]PK`;
- sender and receiver derive the same `Y`;
- signcryption/unsigncryption roundtrip for 0, 1, 20, 128, 1024 and 4096 bytes;
- rejection after tampering with C1, C2, C3, C4, k, sender public key, or receiver secret values.

The benchmark executable uses the same implementation functions as the correctness tests.

## Formal timing protocol

Target machine and build settings must match the earlier formal V2/Liu/Gong runs:

- AMD Ryzen 7 8845H;
- Windows 11;
- MSYS2 UCRT64 GCC 16.2.0;
- Ninja;
- Release build;
- pinned GmSSL above;
- `QueryPerformanceCounter` timing;
- message sizes 20, 128, 1024, 4096 bytes;
- 1000 warm-up roundtrips per size;
- 1000 measured iterations per phase per size;
- no outlier deletion.

Raw phases:

- `hscmet2022_sender_signcrypt`
- `hscmet2022_unsigncrypt`

A formal run therefore contains `4 × 2 × 1000 = 8000` raw timing samples.

## Pre-registered comparisons

Primary real-time comparison:

`(HSCMET Signcrypt - V2 Online Signcrypt) / HSCMET Signcrypt × 100%`.

Mandatory adverse comparisons are also retained:

- V2 sender total vs HSC-MET complete Signcrypt;
- V2 Unsigncrypt vs HSC-MET Unsigncrypt.

A formal percentage is permitted only after all eight `(message_bytes, phase)` groups contain exactly 1000 samples and the V2/HSC-MET raw files record the same GmSSL commit.
