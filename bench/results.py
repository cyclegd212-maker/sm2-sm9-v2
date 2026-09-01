"""Append-safe benchmark result persistence and deterministic summaries."""
from __future__ import annotations

import csv
import math
import statistics
from pathlib import Path
from typing import Iterable, Sequence

RAW_HEADER = ["iteration", "message_bytes", "stage", "elapsed_ns"]
SUMMARY_HEADER = [
    "message_bytes", "stage", "n", "mean_ns", "median_ns", "stdev_ns", "p95_ns"
]

RawRow = tuple[int, int, str, int]


def append_raw_rows(path: Path, rows: Iterable[RawRow]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    write_header = not path.exists() or path.stat().st_size == 0
    with path.open("a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        if write_header:
            writer.writerow(RAW_HEADER)
        writer.writerows(rows)


def nearest_rank(values: Sequence[int], percentile: float) -> int | None:
    if not values:
        return None
    if not (0 < percentile <= 1):
        raise ValueError("percentile must be in (0, 1]")
    ordered = sorted(values)
    rank = max(1, math.ceil(percentile * len(ordered)))
    return ordered[rank - 1]


def rebuild_summary(raw_path: Path, summary_path: Path) -> None:
    groups: dict[tuple[int, str], list[int]] = {}
    if raw_path.exists() and raw_path.stat().st_size:
        with raw_path.open(newline="", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                key = (int(row["message_bytes"]), row["stage"])
                groups.setdefault(key, []).append(int(row["elapsed_ns"]))

    summary_path.parent.mkdir(parents=True, exist_ok=True)
    with summary_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(SUMMARY_HEADER)
        for (message_bytes, stage), values in sorted(groups.items()):
            writer.writerow([
                message_bytes,
                stage,
                len(values),
                statistics.mean(values),
                statistics.median(values),
                statistics.stdev(values) if len(values) > 1 else 0,
                nearest_rank(values, 0.95),
            ])
