#!/usr/bin/env python3
"""Compare archived V2 raw samples with Liu et al. 2018 PCHS raw samples.

The script pre-registers three comparisons per message size:
1. V2 online_signcrypt vs PCHS complete signcrypt (primary metric).
2. V2 sender_total vs PCHS complete signcrypt.
3. V2 unsigncrypt vs PCHS unsigncrypt.

All percentages are derived from raw samples; no latency may be entered by hand.
"""

from __future__ import annotations

import argparse
import csv
import math
import tempfile
from collections import defaultdict
from pathlib import Path

REQUIRED_COLUMNS = {
    "run_id",
    "commit",
    "gmssl_commit",
    "message_bytes",
    "phase",
    "iteration",
    "ns",
}
DEFAULT_SIZES = (20, 128, 1024, 4096)
V2_PHASES = ("online_signcrypt", "sender_total", "unsigncrypt")
PCHS_PHASES = ("pchs_sender_signcrypt", "pchs_unsigncrypt")


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


def identity(rows: list[dict[str, str]], label: str) -> tuple[str, str, str]:
    run_ids = {r["run_id"] for r in rows}
    commits = {r["commit"] for r in rows}
    gmssl_commits = {r["gmssl_commit"] for r in rows}
    if len(run_ids) != 1 or len(commits) != 1 or len(gmssl_commits) != 1:
        raise ValueError(
            f"{label}: expected one run_id, implementation commit, and GmSSL commit"
        )
    return next(iter(run_ids)), next(iter(commits)), next(iter(gmssl_commits))


def phase_means(
    rows: list[dict[str, str]],
    *,
    label: str,
    allowed_phases: tuple[str, ...],
    expected_sizes: tuple[int, ...],
    expected_n: int,
) -> dict[tuple[int, str], float]:
    groups: dict[tuple[int, str], list[tuple[int, int]]] = defaultdict(list)
    for row in rows:
        phase = row["phase"]
        if phase not in allowed_phases:
            continue
        try:
            size = int(row["message_bytes"])
            iteration = int(row["iteration"])
            ns = int(row["ns"])
        except ValueError as exc:
            raise ValueError(f"{label}: malformed row {row}") from exc
        if size not in expected_sizes:
            continue
        if iteration < 0 or ns < 0:
            raise ValueError(f"{label}: negative field in row {row}")
        groups[(size, phase)].append((iteration, ns))

    expected = {(s, p) for s in expected_sizes for p in allowed_phases}
    if set(groups) != expected:
        raise ValueError(
            f"{label}: benchmark groups mismatch; "
            f"missing={sorted(expected.difference(groups))}, "
            f"extra={sorted(set(groups).difference(expected))}"
        )

    means: dict[tuple[int, str], float] = {}
    for key, samples in groups.items():
        if len(samples) != expected_n:
            raise ValueError(f"{label}: group {key} has n={len(samples)}, expected {expected_n}")
        iterations = [i for i, _ in samples]
        if set(iterations) != set(range(expected_n)):
            raise ValueError(f"{label}: group {key} has missing/duplicate iteration indices")
        means[key] = sum(ns for _, ns in samples) / expected_n
    return means


def compare(
    v2_rows: list[dict[str, str]],
    pchs_rows: list[dict[str, str]],
    *,
    expected_sizes: tuple[int, ...] = DEFAULT_SIZES,
    expected_n: int = 1000,
) -> tuple[dict[str, str], list[dict[str, object]]]:
    v2_run, v2_commit, v2_gmssl = identity(v2_rows, "V2")
    pchs_run, pchs_commit, pchs_gmssl = identity(pchs_rows, "PCHS")
    if v2_gmssl != pchs_gmssl:
        raise ValueError(
            "GmSSL commit mismatch: "
            f"V2={v2_gmssl}, PCHS={pchs_gmssl}; same-library comparison required"
        )

    v2 = phase_means(
        v2_rows,
        label="V2",
        allowed_phases=V2_PHASES,
        expected_sizes=expected_sizes,
        expected_n=expected_n,
    )
    pchs = phase_means(
        pchs_rows,
        label="PCHS",
        allowed_phases=PCHS_PHASES,
        expected_sizes=expected_sizes,
        expected_n=expected_n,
    )

    rows: list[dict[str, object]] = []
    for size in expected_sizes:
        v2_online = v2[(size, "online_signcrypt")] / 1_000_000.0
        v2_total = v2[(size, "sender_total")] / 1_000_000.0
        v2_uns = v2[(size, "unsigncrypt")] / 1_000_000.0
        pchs_sc = pchs[(size, "pchs_sender_signcrypt")] / 1_000_000.0
        pchs_uns = pchs[(size, "pchs_unsigncrypt")] / 1_000_000.0
        if pchs_sc <= 0 or pchs_uns <= 0:
            raise ValueError("PCHS mean latency must be positive")
        rows.append(
            {
                "message_bytes": size,
                "v2_online_ms": v2_online,
                "v2_sender_total_ms": v2_total,
                "v2_unsigncrypt_ms": v2_uns,
                "pchs_signcrypt_ms": pchs_sc,
                "pchs_unsigncrypt_ms": pchs_uns,
                "online_reduction_pct": (pchs_sc - v2_online) / pchs_sc * 100.0,
                "sender_total_delta_pct": (v2_total - pchs_sc) / pchs_sc * 100.0,
                "unsigncrypt_delta_pct": (v2_uns - pchs_uns) / pchs_uns * 100.0,
            }
        )

    metadata = {
        "v2_run_id": v2_run,
        "v2_commit": v2_commit,
        "pchs_run_id": pchs_run,
        "pchs_commit": pchs_commit,
        "gmssl_commit": v2_gmssl,
    }
    return metadata, rows


def write_comparison(
    path: Path,
    metadata: dict[str, str],
    rows: list[dict[str, object]],
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = (
        "v2_run_id",
        "v2_commit",
        "pchs_run_id",
        "pchs_commit",
        "gmssl_commit",
        "message_bytes",
        "v2_online_ms",
        "v2_sender_total_ms",
        "v2_unsigncrypt_ms",
        "pchs_signcrypt_ms",
        "pchs_unsigncrypt_ms",
        "online_reduction_pct",
        "sender_total_delta_pct",
        "unsigncrypt_delta_pct",
    )
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            merged = dict(metadata)
            merged.update(row)
            writer.writerow(merged)


def synthetic_rows(
    *,
    run_id: str,
    commit: str,
    gmssl_commit: str,
    phase_values: dict[str, list[int]],
    message_bytes: int = 20,
) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for phase, values in phase_values.items():
        for iteration, ns in enumerate(values):
            rows.append(
                {
                    "run_id": run_id,
                    "commit": commit,
                    "gmssl_commit": gmssl_commit,
                    "message_bytes": str(message_bytes),
                    "phase": phase,
                    "iteration": str(iteration),
                    "ns": str(ns),
                }
            )
    return rows


def self_test() -> None:
    v2_rows = synthetic_rows(
        run_id="v2-self",
        commit="v2-commit",
        gmssl_commit="same-gmssl",
        phase_values={
            "online_signcrypt": [500_000, 500_000],
            "sender_total": [2_000_000, 2_000_000],
            "unsigncrypt": [3_000_000, 3_000_000],
        },
    )
    pchs_rows = synthetic_rows(
        run_id="pchs-self",
        commit="pchs-commit",
        gmssl_commit="same-gmssl",
        phase_values={
            "pchs_sender_signcrypt": [1_000_000, 1_000_000],
            "pchs_unsigncrypt": [1_500_000, 1_500_000],
        },
    )
    metadata, rows = compare(v2_rows, pchs_rows, expected_sizes=(20,), expected_n=2)
    assert metadata["gmssl_commit"] == "same-gmssl"
    assert len(rows) == 1
    row = rows[0]
    assert math.isclose(float(row["online_reduction_pct"]), 50.0)
    assert math.isclose(float(row["sender_total_delta_pct"]), 100.0)
    assert math.isclose(float(row["unsigncrypt_delta_pct"]), 100.0)

    with tempfile.TemporaryDirectory() as td:
        out = Path(td) / "comparison.csv"
        write_comparison(out, metadata, rows)
        text = out.read_text(encoding="utf-8")
        assert "online_reduction_pct" in text
        assert "v2-self" in text

    bad = synthetic_rows(
        run_id="pchs-bad",
        commit="pchs-commit",
        gmssl_commit="different-gmssl",
        phase_values={
            "pchs_sender_signcrypt": [1_000_000, 1_000_000],
            "pchs_unsigncrypt": [1_500_000, 1_500_000],
        },
    )
    try:
        compare(v2_rows, bad, expected_sizes=(20,), expected_n=2)
    except ValueError as exc:
        assert "GmSSL commit mismatch" in str(exc)
    else:
        raise AssertionError("GmSSL mismatch was not rejected")

    print("compare_v2_pchs self-test: ok")


def parse_sizes(text: str) -> tuple[int, ...]:
    values = tuple(int(x.strip()) for x in text.split(",") if x.strip())
    if not values or any(x < 0 for x in values) or len(set(values)) != len(values):
        raise argparse.ArgumentTypeError("sizes must be unique non-negative integers")
    return values


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--v2-raw", type=Path)
    parser.add_argument("--pchs-raw", type=Path)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--expected-sizes", type=parse_sizes, default=DEFAULT_SIZES)
    parser.add_argument("--expected-n", type=int, default=1000)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        self_test()
        return 0
    if args.v2_raw is None or args.pchs_raw is None or args.out is None:
        parser.error("--v2-raw, --pchs-raw, and --out are required unless --self-test")
    if args.expected_n <= 0:
        parser.error("--expected-n must be positive")

    metadata, rows = compare(
        read_raw(args.v2_raw),
        read_raw(args.pchs_raw),
        expected_sizes=args.expected_sizes,
        expected_n=args.expected_n,
    )
    write_comparison(args.out, metadata, rows)
    print(f"wrote {len(rows)} comparison rows to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
