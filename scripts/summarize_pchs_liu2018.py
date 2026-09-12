#!/usr/bin/env python3
"""Summarize raw Liu et al. 2018 PCHS benchmark samples.

This script intentionally consumes raw per-iteration nanosecond records and
never accepts hand-entered latency values. P95 uses the nearest-rank rule used
by the existing V2 submission benchmark.
"""

from __future__ import annotations

import argparse
import csv
import math
import statistics
import tempfile
from collections import defaultdict
from pathlib import Path
from typing import Iterable

REQUIRED_COLUMNS = {
    "run_id",
    "commit",
    "gmssl_commit",
    "message_bytes",
    "phase",
    "iteration",
    "ns",
}
PCHS_PHASES = ("pchs_sender_signcrypt", "pchs_unsigncrypt")
DEFAULT_SIZES = (20, 128, 1024, 4096)


def nearest_rank(values: Iterable[int], quantile: float) -> int:
    ordered = sorted(values)
    if not ordered:
        raise ValueError("cannot compute a quantile of an empty sample")
    if not 0 < quantile <= 1:
        raise ValueError("quantile must be in (0, 1]")
    rank = math.ceil(quantile * len(ordered))
    return ordered[rank - 1]


def read_raw(path: Path) -> list[dict[str, str]]:
    with path.open("r", newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        if reader.fieldnames is None:
            raise ValueError(f"{path}: missing CSV header")
        missing = REQUIRED_COLUMNS.difference(reader.fieldnames)
        if missing:
            raise ValueError(f"{path}: missing columns: {sorted(missing)}")
        rows = list(reader)
    if not rows:
        raise ValueError(f"{path}: contains no benchmark samples")
    return rows


def validate_identity(rows: list[dict[str, str]]) -> tuple[str, str, str]:
    run_ids = {r["run_id"] for r in rows}
    commits = {r["commit"] for r in rows}
    gmssl_commits = {r["gmssl_commit"] for r in rows}
    if len(run_ids) != 1 or len(commits) != 1 or len(gmssl_commits) != 1:
        raise ValueError(
            "raw CSV must contain exactly one run_id, implementation commit, "
            "and GmSSL commit"
        )
    return next(iter(run_ids)), next(iter(commits)), next(iter(gmssl_commits))


def summarize(
    rows: list[dict[str, str]],
    *,
    expected_sizes: tuple[int, ...] | None = None,
    expected_n: int | None = None,
) -> list[dict[str, object]]:
    validate_identity(rows)
    groups: dict[tuple[int, str], list[tuple[int, int]]] = defaultdict(list)

    for row in rows:
        try:
            size = int(row["message_bytes"])
            iteration = int(row["iteration"])
            ns = int(row["ns"])
        except ValueError as exc:
            raise ValueError(f"non-integer benchmark field in row: {row}") from exc
        if size < 0 or iteration < 0 or ns < 0:
            raise ValueError(f"negative benchmark field in row: {row}")
        phase = row["phase"]
        if phase not in PCHS_PHASES:
            raise ValueError(f"unexpected PCHS phase: {phase!r}")
        groups[(size, phase)].append((iteration, ns))

    if expected_sizes is not None:
        expected_keys = {(s, p) for s in expected_sizes for p in PCHS_PHASES}
        if set(groups) != expected_keys:
            missing = sorted(expected_keys.difference(groups))
            extra = sorted(set(groups).difference(expected_keys))
            raise ValueError(f"PCHS groups mismatch; missing={missing}, extra={extra}")

    out: list[dict[str, object]] = []
    for (size, phase), samples in sorted(groups.items()):
        iterations = [i for i, _ in samples]
        if len(iterations) != len(set(iterations)):
            raise ValueError(f"duplicate iteration in group {(size, phase)}")
        if set(iterations) != set(range(len(iterations))):
            raise ValueError(
                f"iteration sequence for {(size, phase)} is not contiguous from zero"
            )
        values = [ns for _, ns in samples]
        if expected_n is not None and len(values) != expected_n:
            raise ValueError(
                f"group {(size, phase)} has n={len(values)}, expected {expected_n}"
            )
        out.append(
            {
                "message_bytes": size,
                "phase": phase,
                "n": len(values),
                "mean_ns": statistics.fmean(values),
                "median_ns": statistics.median(values),
                "stdev_ns": statistics.stdev(values) if len(values) > 1 else 0.0,
                "p95_ns": nearest_rank(values, 0.95),
            }
        )
    return out


def write_summary(path: Path, rows: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = (
        "message_bytes",
        "phase",
        "n",
        "mean_ns",
        "median_ns",
        "stdev_ns",
        "p95_ns",
    )
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def self_test() -> None:
    rows: list[dict[str, str]] = []
    values = {
        (20, "pchs_sender_signcrypt"): [10, 20, 30, 40, 100],
        (20, "pchs_unsigncrypt"): [50, 60, 70, 80, 90],
    }
    for (size, phase), samples in values.items():
        for iteration, ns in enumerate(samples):
            rows.append(
                {
                    "run_id": "self-test",
                    "commit": "pchs-self-test",
                    "gmssl_commit": "gmssl-self-test",
                    "message_bytes": str(size),
                    "phase": phase,
                    "iteration": str(iteration),
                    "ns": str(ns),
                }
            )
    result = summarize(rows, expected_sizes=(20,), expected_n=5)
    by_phase = {str(r["phase"]): r for r in result}
    a = by_phase["pchs_sender_signcrypt"]
    assert a["n"] == 5
    assert a["mean_ns"] == 40.0
    assert a["median_ns"] == 30
    assert a["p95_ns"] == 100
    assert math.isclose(float(a["stdev_ns"]), statistics.stdev([10, 20, 30, 40, 100]))

    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "summary.csv"
        write_summary(path, result)
        assert path.read_text(encoding="utf-8").startswith("message_bytes,phase,n,")
    print("summarize_pchs_liu2018 self-test: ok")


def parse_sizes(text: str) -> tuple[int, ...]:
    values = tuple(int(x.strip()) for x in text.split(",") if x.strip())
    if not values or any(x < 0 for x in values) or len(set(values)) != len(values):
        raise argparse.ArgumentTypeError("sizes must be unique non-negative integers")
    return values


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--raw", type=Path)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--expected-sizes", type=parse_sizes, default=DEFAULT_SIZES)
    parser.add_argument("--expected-n", type=int, default=1000)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        self_test()
        return 0
    if args.raw is None or args.out is None:
        parser.error("--raw and --out are required unless --self-test is used")
    if args.expected_n <= 0:
        parser.error("--expected-n must be positive")

    rows = read_raw(args.raw)
    result = summarize(
        rows,
        expected_sizes=args.expected_sizes,
        expected_n=args.expected_n,
    )
    write_summary(args.out, result)
    print(f"wrote {len(result)} summary groups to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
