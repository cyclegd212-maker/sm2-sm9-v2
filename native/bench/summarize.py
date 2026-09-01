"""Summarize native benchmark raw CSV without inventing missing samples."""
from __future__ import annotations

import argparse
import csv
import math
import statistics
from pathlib import Path

RAW_HEADER = [
    "run_id", "commit", "gmssl_commit", "message_bytes", "phase", "iteration", "ns"
]
SUMMARY_HEADER = [
    "run_id", "commit", "gmssl_commit", "message_bytes", "phase",
    "n", "mean_ns", "median_ns", "stdev_ns", "p95_ns"
]


def nearest_rank(values: list[int], percentile: float) -> int:
    if not values:
        raise ValueError("cannot compute percentile of empty data")
    if not (0 < percentile <= 1):
        raise ValueError("percentile must be in (0,1]")
    ordered = sorted(values)
    rank = max(1, math.ceil(percentile * len(ordered)))
    return ordered[rank - 1]


def summarize_file(raw_path: Path, summary_path: Path) -> None:
    groups: dict[tuple[str, str, str, int, str], list[int]] = {}
    with raw_path.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        if reader.fieldnames != RAW_HEADER:
            raise ValueError(f"unexpected raw header: {reader.fieldnames!r}")
        for row in reader:
            key = (
                row["run_id"], row["commit"], row["gmssl_commit"],
                int(row["message_bytes"]), row["phase"],
            )
            groups.setdefault(key, []).append(int(row["ns"]))

    summary_path.parent.mkdir(parents=True, exist_ok=True)
    with summary_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(SUMMARY_HEADER)
        for (run_id, commit, gmssl_commit, message_bytes, phase), values in sorted(groups.items()):
            writer.writerow([
                run_id,
                commit,
                gmssl_commit,
                message_bytes,
                phase,
                len(values),
                statistics.mean(values),
                statistics.median(values),
                statistics.stdev(values) if len(values) > 1 else 0,
                nearest_rank(values, 0.95),
            ])


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("raw", type=Path)
    parser.add_argument("summary", type=Path)
    args = parser.parse_args()
    summarize_file(args.raw, args.summary)


if __name__ == "__main__":
    main()
