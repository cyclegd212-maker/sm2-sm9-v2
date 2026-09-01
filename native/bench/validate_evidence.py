"""Fail-closed validation for archived native benchmark evidence."""
from __future__ import annotations

import argparse
import csv
import tempfile
from collections import defaultdict
from pathlib import Path

from native.bench.summarize import RAW_HEADER, summarize_file

EXPECTED_PHASES = {
    "receiver_keygen",
    "offline_signcrypt",
    "online_signcrypt",
    "sender_total",
    "unsigncrypt",
    "sm2_fixed_base_mul",
    "sm9_g1_mul",
    "sm9_pairing",
    "sm9_gt_exp",
}


def validate(raw: Path, summary: Path, expected_sizes: set[int], iterations: int) -> None:
    counts: dict[tuple[int, str], list[int]] = defaultdict(list)
    identities: set[tuple[str, str, str]] = set()

    with raw.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        if reader.fieldnames != RAW_HEADER:
            raise ValueError(f"unexpected raw header: {reader.fieldnames!r}")
        for row in reader:
            size = int(row["message_bytes"])
            phase = row["phase"]
            iteration = int(row["iteration"])
            ns = int(row["ns"])
            if ns <= 0:
                raise ValueError(f"non-positive timing: {row}")
            if size not in expected_sizes:
                raise ValueError(f"unexpected message size: {size}")
            if phase not in EXPECTED_PHASES:
                raise ValueError(f"unexpected phase: {phase}")
            counts[(size, phase)].append(iteration)
            identities.add((row["run_id"], row["commit"], row["gmssl_commit"]))

    if len(identities) != 1:
        raise ValueError(f"mixed evidence identities: {sorted(identities)!r}")
    expected_groups = {(size, phase) for size in expected_sizes for phase in EXPECTED_PHASES}
    if set(counts) != expected_groups:
        missing = sorted(expected_groups - set(counts))
        extra = sorted(set(counts) - expected_groups)
        raise ValueError(f"phase coverage mismatch; missing={missing}, extra={extra}")
    expected_iterations = list(range(iterations))
    for key, observed in counts.items():
        if sorted(observed) != expected_iterations:
            raise ValueError(f"iteration coverage mismatch for {key}: {sorted(observed)!r}")

    with tempfile.TemporaryDirectory() as td:
        recomputed = Path(td) / "summary.csv"
        summarize_file(raw, recomputed)
        if recomputed.read_bytes() != summary.read_bytes():
            raise ValueError("summary.csv does not exactly match a fresh recomputation from raw.csv")


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("raw", type=Path)
    p.add_argument("summary", type=Path)
    p.add_argument("--sizes", default="20,128,1024,4096")
    p.add_argument("--iterations", type=int, required=True)
    args = p.parse_args()
    sizes = {int(x) for x in args.sizes.split(",") if x}
    if not sizes or args.iterations < 1:
        raise SystemExit("sizes must be non-empty and iterations >= 1")
    validate(args.raw, args.summary, sizes, args.iterations)
    print("benchmark evidence validation: ok")


if __name__ == "__main__":
    main()
