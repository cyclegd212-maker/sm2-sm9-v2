import csv
from pathlib import Path

from native.bench.summarize import summarize_file


def read_csv(path: Path):
    with path.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def test_native_summary_groups_by_evidence_identity_and_uses_nearest_rank_p95(tmp_path):
    raw = tmp_path / "raw.csv"
    summary = tmp_path / "summary.csv"
    with raw.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["run_id", "commit", "gmssl_commit", "message_bytes", "phase", "iteration", "ns"])
        for i, ns in enumerate(range(1, 21)):
            w.writerow(["ci-1", "v2sha", "gmsslsha", 20, "online_signcrypt", i, ns])
        w.writerow(["ci-1", "v2sha", "gmsslsha", 128, "online_signcrypt", 0, 100])

    summarize_file(raw, summary)
    rows = read_csv(summary)
    assert len(rows) == 2
    row20 = next(r for r in rows if r["message_bytes"] == "20")
    assert row20["n"] == "20"
    assert row20["p95_ns"] == "19"
    assert row20["run_id"] == "ci-1"
    assert row20["commit"] == "v2sha"
    assert row20["gmssl_commit"] == "gmsslsha"
