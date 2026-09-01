import csv
from pathlib import Path

from bench.results import append_raw_rows, rebuild_summary


def read_csv(path: Path):
    with path.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def test_multiple_message_sizes_survive_sequential_writes(tmp_path):
    raw = tmp_path / "raw.csv"
    summary = tmp_path / "summary.csv"

    append_raw_rows(raw, [
        (0, 20, "offline_signcrypt", 100),
        (1, 20, "offline_signcrypt", 200),
    ])
    rebuild_summary(raw, summary)

    append_raw_rows(raw, [
        (0, 128, "offline_signcrypt", 300),
        (1, 128, "offline_signcrypt", 500),
    ])
    rebuild_summary(raw, summary)

    raw_rows = read_csv(raw)
    assert {(r["message_bytes"], r["elapsed_ns"]) for r in raw_rows} == {
        ("20", "100"), ("20", "200"), ("128", "300"), ("128", "500")
    }

    summary_rows = read_csv(summary)
    assert {(r["message_bytes"], r["stage"]) for r in summary_rows} == {
        ("20", "offline_signcrypt"), ("128", "offline_signcrypt")
    }


def test_nearest_rank_p95_is_recomputed_from_all_raw_samples(tmp_path):
    raw = tmp_path / "raw.csv"
    summary = tmp_path / "summary.csv"
    append_raw_rows(raw, [
        (i, 20, "online_signcrypt", value)
        for i, value in enumerate(range(1, 21))
    ])
    rebuild_summary(raw, summary)
    rows = read_csv(summary)
    assert len(rows) == 1
    assert rows[0]["n"] == "20"
    assert rows[0]["p95_ns"] == "19"
