from __future__ import annotations
import json, platform, subprocess, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def cmd(args):
    try:
        return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT).strip()
    except Exception as e:
        return f"UNAVAILABLE: {e}"

meta = {
    "timestamp_policy": "recorded when benchmark is actually run",
    "platform": platform.platform(),
    "python": sys.version,
    "processor": platform.processor(),
    "machine": platform.machine(),
    "git_head": cmd(["git", "rev-parse", "HEAD"]),
    "git_status": cmd(["git", "status", "--porcelain=v1"]),
    "pip_freeze": cmd([sys.executable, "-m", "pip", "freeze"]),
    "reference_gmssl_commit": "498ba0545a3f7667ab4575e93cd10e9b19baf4f0",
}
(ROOT / "metadata" / "environment.json").write_text(json.dumps(meta, indent=2, ensure_ascii=False), encoding="utf-8")
print(json.dumps(meta, indent=2, ensure_ascii=False))
