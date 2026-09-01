"""Benchmark driver. It writes raw samples; it never fabricates missing timings."""
from __future__ import annotations

import argparse
import time
from pathlib import Path

from bench.results import append_raw_rows, rebuild_summary
from src.v2_scheme import (
    offline_signcrypt,
    online_signcrypt,
    receiver_keygen,
    sender_keygen,
    setup_sm9,
    unsigncrypt,
    validate_receiver_key,
)

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "data" / "raw" / "timings.csv"
SUMMARY = ROOT / "data" / "processed" / "summary.csv"


def ns_call(fn, *args):
    t0 = time.perf_counter_ns()
    result = fn(*args)
    return result, time.perf_counter_ns() - t0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--iterations", type=int, default=1000)
    ap.add_argument("--warmup", type=int, default=100)
    ap.add_argument("--message-bytes", type=int, default=128)
    args = ap.parse_args()

    if args.iterations < 1 or args.warmup < 0 or args.message_bytes < 0:
        raise SystemExit("iterations must be >=1; warmup and message-bytes must be >=0")

    master_public, master_secret = setup_sm9()
    sender = sender_keygen()
    receiver = receiver_keygen(master_public, master_secret)
    validate_receiver_key(master_public, receiver)
    msg = bytes((i % 251 for i in range(args.message_bytes)))

    for _ in range(args.warmup):
        tok = offline_signcrypt(master_public, sender, receiver.id_b, receiver.X_b)
        ct = online_signcrypt(sender, tok, msg)
        assert unsigncrypt(master_public, sender, receiver, ct) == msg

    rows = []
    for i in range(args.iterations):
        tok, t_off = ns_call(offline_signcrypt, master_public, sender, receiver.id_b, receiver.X_b)
        ct, t_on = ns_call(online_signcrypt, sender, tok, msg)
        pt, t_un = ns_call(unsigncrypt, master_public, sender, receiver, ct)
        if pt != msg:
            raise RuntimeError("correctness failure")
        rows.extend([
            (i, args.message_bytes, "offline_signcrypt", t_off),
            (i, args.message_bytes, "online_signcrypt", t_on),
            (i, args.message_bytes, "unsigncrypt", t_un),
        ])

    append_raw_rows(RAW, rows)
    rebuild_summary(RAW, SUMMARY)
    print(f"raw: {RAW}")
    print(f"summary: {SUMMARY}")


if __name__ == "__main__":
    main()
