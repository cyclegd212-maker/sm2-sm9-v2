# Native V2 implementation

This directory is the submission-oriented C implementation of the SM2 -> enhanced-SM9 V2 construction.

## Cryptographic dependency

GmSSL is pinned to commit:

`24ae482701a7b124826c382fffc55c19f76d475d`

The native implementation may use only public headers/APIs from that revision. In particular, the design relies on public SM2 fast-sign/precomputation primitives, SM3/HMAC/KDF APIs, SM9 encryption-key extraction, and public `sm9_z256` point/GT/pairing interfaces.

## Evidence policy

The native implementation is developed test-first. GitHub Actions evidence is classified as a **CI reproducibility benchmark**. It does not replace the final submission benchmark on the designated Ryzen 7 8845H machine. No manuscript latency value may be copied from this repository unless it is traceable to a V2 commit, the pinned GmSSL commit, environment metadata, raw CSV, summary CSV, and run logs.

## Current phase

The initial PR deliberately begins in a RED compile-smoke state before `v2_scheme.h` exists. The first green gate is a pinned GmSSL build plus upstream SM2/SM3/HMAC/SM9 tests and a successful native compile smoke test.
