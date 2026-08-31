"""Benchmark driver. It writes raw samples; it never fabricates missing timings."""
from __future__ import annotations
import argparse, csv, statistics, time
from pathlib import Path

from src.v2_scheme import setup_sm9, sender_keygen, receiver_keygen, validate_receiver_key, offline_signcrypt, online_signcrypt, unsigncrypt

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "data" / "raw" / "timings.csv"
SUMMARY = ROOT / "data" / "processed" / "summary.csv"


def ns_call(fn, *args):
    t0 = time.perf_counter_ns()
    result = fn(*args)
    return result, time.perf_counter_ns() - t0


def percentile(xs, p):
    ys = sorted(xs)
    if not ys:
        return None
    idx = min(len(ys)-1, max(0, int(round((len(ys)-1)*p))))
    return ys[idx]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--iterations", type=int, default=1000)
    ap.add_argument("--warmup", type=int, default=100)
    ap.add_argument("--message-bytes", type=int, default=128)
    args = ap.parse_args()

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

    RAW.parent.mkdir(parents=True, exist_ok=True)
    with RAW.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["iteration", "message_bytes", "stage", "elapsed_ns"])
        w.writerows(rows)

    by_stage = {}
    for _, _, stage, elapsed in rows:
        by_stage.setdefault(stage, []).append(elapsed)
    SUMMARY.parent.mkdir(parents=True, exist_ok=True)
    with SUMMARY.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["message_bytes", "stage", "n", "mean_ns", "median_ns", "stdev_ns", "p95_ns"])
        for stage, xs in sorted(by_stage.items()):
            w.writerow([
                args.message_bytes, stage, len(xs), statistics.mean(xs), statistics.median(xs),
                statistics.stdev(xs) if len(xs) > 1 else 0, percentile(xs, .95)
            ])
    print(f"raw: {RAW}")
    print(f"summary: {SUMMARY}")

if __name__ == "__main__":
    main()
