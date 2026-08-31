"""Collect non-secret environment metadata for a real native benchmark run."""
from __future__ import annotations

import argparse
import json
import os
import platform
import subprocess
from datetime import datetime, timezone
from pathlib import Path


def cmd(args: list[str]) -> str:
    try:
        return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT).strip()
    except Exception as exc:  # evidence should record unavailability, not hide it
        return f"UNAVAILABLE: {exc}"


def cpu_model() -> str:
    if os.name == "nt":
        value = os.environ.get("PROCESSOR_IDENTIFIER")
        if value:
            return value
    cpuinfo = Path("/proc/cpuinfo")
    if cpuinfo.exists():
        for line in cpuinfo.read_text(errors="replace").splitlines():
            if line.lower().startswith("model name") and ":" in line:
                return line.split(":", 1)[1].strip()
    return platform.processor() or "UNKNOWN"


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--run-id", required=True)
    p.add_argument("--v2-commit", required=True)
    p.add_argument("--gmssl-commit", required=True)
    p.add_argument("--build-type", default="Release")
    p.add_argument("--warmup", type=int, required=True)
    p.add_argument("--iterations", type=int, required=True)
    args = p.parse_args()

    meta = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "run_id": args.run_id,
        "v2_commit": args.v2_commit,
        "gmssl_commit": args.gmssl_commit,
        "build_type": args.build_type,
        "warmup": args.warmup,
        "iterations": args.iterations,
        "platform": platform.platform(),
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "cpu_model": cpu_model(),
        "logical_cpu_count": os.cpu_count(),
        "python": platform.python_version(),
        "compiler_cc": cmd(["cc", "--version"]),
        "cmake": cmd(["cmake", "--version"]),
        "git_head": cmd(["git", "rev-parse", "HEAD"]),
        "git_status_porcelain": cmd(["git", "status", "--porcelain=v1"]),
        "runner": {
            "RUNNER_OS": os.environ.get("RUNNER_OS"),
            "RUNNER_ARCH": os.environ.get("RUNNER_ARCH"),
            "GITHUB_RUN_ID": os.environ.get("GITHUB_RUN_ID"),
            "GITHUB_RUN_ATTEMPT": os.environ.get("GITHUB_RUN_ATTEMPT"),
        },
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(meta, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps(meta, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
