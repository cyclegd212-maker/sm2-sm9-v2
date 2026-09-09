"""Publication-oriented performance figures for the SM2-SM9 V2 paper.

Reads native/bench summary.csv produced by summarize.py and creates separate
figures (no subplots) suitable for insertion into the manuscript.  The script
auto-detects a CJK font on Windows/Linux/macOS and never fabricates a missing
primitive timing: the normalized comparison requires sm9_g1_add to be present.
"""
from __future__ import annotations

import argparse
import csv
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
from matplotlib import font_manager


REQUIRED_SIZES = [20, 128, 1024, 4096]


def configure_font() -> str:
    candidates = [
        "Microsoft YaHei",
        "Microsoft YaHei UI",
        "SimHei",
        "Noto Sans CJK SC",
        "Source Han Sans SC",
        "PingFang SC",
        "Arial Unicode MS",
    ]
    available = {f.name for f in font_manager.fontManager.ttflist}
    for name in candidates:
        if name in available:
            plt.rcParams["font.sans-serif"] = [name]
            plt.rcParams["axes.unicode_minus"] = False
            return name
    plt.rcParams["axes.unicode_minus"] = False
    return "default"


def load_summary(path: Path) -> dict[tuple[int, str], dict[str, float]]:
    data: dict[tuple[int, str], dict[str, float]] = {}
    with path.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        required = {
            "message_bytes", "phase", "n", "mean_ns", "median_ns",
            "stdev_ns", "p95_ns",
        }
        if not required.issubset(reader.fieldnames or []):
            raise ValueError(f"summary.csv header missing fields: {sorted(required)}")
        for row in reader:
            key = (int(row["message_bytes"]), row["phase"])
            data[key] = {
                "n": float(row["n"]),
                "mean_ms": float(row["mean_ns"]) / 1e6,
                "median_ms": float(row["median_ns"]) / 1e6,
                "stdev_ms": float(row["stdev_ns"]) / 1e6,
                "p95_ms": float(row["p95_ns"]) / 1e6,
            }
    return data


def phase_values(data, phase: str, field: str = "mean_ms") -> np.ndarray:
    values = []
    for size in REQUIRED_SIZES:
        key = (size, phase)
        if key not in data:
            raise ValueError(f"missing summary row: size={size}, phase={phase}")
        values.append(data[key][field])
    return np.asarray(values, dtype=float)


def primitive_mean(data, phase: str) -> float:
    # Every message size is sampled with the same n in the submission runner;
    # averaging the per-size means therefore gives the same equal-weight estimate.
    return float(np.mean(phase_values(data, phase, "mean_ms")))


def save_figure(fig, output_dir: Path, stem: str) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    fig.savefig(output_dir / f"{stem}.pdf", bbox_inches="tight")
    fig.savefig(output_dir / f"{stem}.png", dpi=600, bbox_inches="tight")
    plt.close(fig)


def plot_normalized_major_operations(data, output_dir: Path) -> dict[str, float]:
    tp = primitive_mean(data, "sm9_pairing")
    t1m = primitive_mean(data, "sm9_g1_mul")
    t1a = primitive_mean(data, "sm9_g1_add")
    tte = primitive_mean(data, "sm9_gt_exp")
    tsm = primitive_mean(data, "sm2_fixed_base_mul")

    schemes = [
        "Zhang et al. 2019",
        "Lai et al. 2017",
        "Iqbal et al. 2019",
        "Liu et al. 2018 PCHS",
        "本文",
    ]
    before = np.asarray([
        2 * tp + 2 * tte,
        tte + 3 * t1m,
        tte + 4 * t1m,
        0.0,
        3 * t1m + t1a + tte + tsm,
    ])
    after = np.asarray([
        0.0,
        0.0,
        0.0,
        4 * t1m,
        0.0,
    ])

    y = np.arange(len(schemes))
    h = 0.34
    fig, ax = plt.subplots(figsize=(8.6, 4.8))
    b1 = ax.barh(y - h / 2, before, height=h, label="消息到达前/离线主要操作")
    b2 = ax.barh(y + h / 2, after, height=h, label="消息到达后/在线主要操作")
    ax.set_yticks(y)
    ax.set_yticklabels(schemes)
    ax.invert_yaxis()
    ax.set_xlabel("归一化主要操作成本 / ms")
    ax.grid(axis="x", alpha=0.20)
    ax.legend(frameon=False, loc="lower right")
    xmax = max(float(before.max()), float(after.max()))
    ax.set_xlim(0, xmax * 1.16 if xmax else 1)

    for bars in (b1, b2):
        for bar in bars:
            value = bar.get_width()
            if value <= 0:
                continue
            ax.text(
                value + xmax * 0.012,
                bar.get_y() + bar.get_height() / 2,
                f"{value:.2f}",
                va="center",
                fontsize=9,
            )

    fig.tight_layout()
    save_figure(fig, output_dir, "fig_normalized_major_operations")
    return {"Tp": tp, "T1m": t1m, "T1a": t1a, "TTe": tte, "TSm": tsm}


def plot_protocol_runtime(data, output_dir: Path) -> None:
    x = np.asarray(REQUIRED_SIZES, dtype=float)
    fig, ax = plt.subplots(figsize=(7.6, 4.6))
    for phase, label, marker in [
        ("offline_signcrypt", "离线签密", "o"),
        ("sender_total", "发送端总计", "s"),
        ("unsigncrypt", "解签密", "^"),
    ]:
        ax.plot(x, phase_values(data, phase), marker=marker, linewidth=1.8, label=label)
    ax.set_xscale("log")
    ax.set_xticks(REQUIRED_SIZES)
    ax.set_xticklabels([str(x) for x in REQUIRED_SIZES])
    ax.set_xlabel("消息长度 / B")
    ax.set_ylabel("平均时延 / ms")
    ax.grid(alpha=0.20)
    ax.legend(frameon=False)
    fig.tight_layout()
    save_figure(fig, output_dir, "fig_protocol_runtime")


def plot_online_latency(data, output_dir: Path) -> None:
    x = np.asarray(REQUIRED_SIZES, dtype=float)
    fig, ax = plt.subplots(figsize=(7.6, 4.6))
    for field, label, marker in [
        ("mean_ms", "均值", "o"),
        ("median_ms", "中位数", "s"),
        ("p95_ms", "P95", "^"),
    ]:
        ax.plot(x, phase_values(data, "online_signcrypt", field), marker=marker,
                linewidth=1.8, label=label)
    ax.set_xscale("log")
    ax.set_xticks(REQUIRED_SIZES)
    ax.set_xticklabels([str(x) for x in REQUIRED_SIZES])
    ax.set_xlabel("消息长度 / B")
    ax.set_ylabel("在线签密时延 / ms")
    ax.grid(alpha=0.20)
    ax.legend(frameon=False)
    fig.tight_layout()
    save_figure(fig, output_dir, "fig_online_latency")


def plot_online_share(data, output_dir: Path) -> None:
    online = phase_values(data, "online_signcrypt")
    total = phase_values(data, "sender_total")
    share = 100.0 * online / total
    labels = [f"{x} B" for x in REQUIRED_SIZES]
    fig, ax = plt.subplots(figsize=(7.2, 4.2))
    bars = ax.bar(labels, share)
    ax.set_ylabel("在线阶段占发送端总时延 / %")
    ax.set_ylim(0, max(10.0, float(share.max()) * 1.25))
    ax.grid(axis="y", alpha=0.20)
    for bar, value in zip(bars, share):
        ax.text(bar.get_x() + bar.get_width() / 2, value + 0.15,
                f"{value:.1f}%", ha="center", va="bottom", fontsize=9)
    fig.tight_layout()
    save_figure(fig, output_dir, "fig_online_share")


def plot_communication_overhead(output_dir: Path) -> None:
    payload = np.asarray(REQUIRED_SIZES, dtype=float)
    fixed = np.full_like(payload, 231.0)
    labels = [f"{x} B" for x in REQUIRED_SIZES]
    fig, ax = plt.subplots(figsize=(7.2, 4.2))
    ax.bar(labels, payload, label="消息载荷")
    ax.bar(labels, fixed, bottom=payload, label="固定协议字段 231 B")
    ax.set_ylabel("序列化密文长度 / B")
    ax.grid(axis="y", alpha=0.20)
    ax.legend(frameon=False)
    for i, (m, f) in enumerate(zip(payload, fixed)):
        total = m + f
        share = 100.0 * f / total
        ax.text(i, total + max(total * 0.015, 8), f"{int(total)} B\n固定占比 {share:.1f}%",
                ha="center", va="bottom", fontsize=8.5)
    ax.set_ylim(0, float((payload + fixed).max()) * 1.16)
    fig.tight_layout()
    save_figure(fig, output_dir, "fig_communication_overhead")


def write_derived_csv(data, primitive, output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    out = output_dir / "derived_performance_metrics.csv"
    online = phase_values(data, "online_signcrypt")
    total = phase_values(data, "sender_total")
    qb = phase_values(data, "sm9_qb_compute")
    with out.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.writer(f)
        writer.writerow(["metric", "20B", "128B", "1024B", "4096B", "unit"])
        writer.writerow(["online_mean", *[f"{x:.6f}" for x in online], "ms"])
        writer.writerow(["online_share", *[f"{x:.4f}" for x in (100 * online / total)], "%"])
        writer.writerow(["qb_compute_mean", *[f"{x:.6f}" for x in qb], "ms"])
        for key in ["Tp", "T1m", "T1a", "TTe", "TSm"]:
            writer.writerow([key, f"{primitive[key]:.6f}", "", "", "", "ms"])


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("summary", type=Path)
    parser.add_argument("--output-dir", type=Path, default=Path("performance_figures"))
    args = parser.parse_args()

    font = configure_font()
    data = load_summary(args.summary)
    primitive = plot_normalized_major_operations(data, args.output_dir)
    plot_protocol_runtime(data, args.output_dir)
    plot_online_latency(data, args.output_dir)
    plot_online_share(data, args.output_dir)
    plot_communication_overhead(args.output_dir)
    write_derived_csv(data, primitive, args.output_dir)

    print(f"font: {font}")
    print(f"figures written to: {args.output_dir.resolve()}")
    print("primitive means (ms):")
    for key, value in primitive.items():
        print(f"  {key} = {value:.6f}")


if __name__ == "__main__":
    main()
