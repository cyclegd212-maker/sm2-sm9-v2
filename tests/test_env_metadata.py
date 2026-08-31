from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def test_collect_env_records_gmssl_build_options(tmp_path: Path) -> None:
    output = tmp_path / "environment.json"
    cmd = [
        sys.executable,
        "native/scripts/collect_env.py",
        "--output", str(output),
        "--run-id", "test-run",
        "--v2-commit", "v2-test",
        "--gmssl-commit", "gmssl-test",
        "--gmssl-build-options", "-DENABLE_SM9=ON;-DENABLE_SM2_AMD64=OFF",
        "--build-type", "Release",
        "--warmup", "1000",
        "--iterations", "10000",
    ]
    subprocess.run(cmd, check=True)
    meta = json.loads(output.read_text(encoding="utf-8"))
    assert meta["gmssl_build_options"] == [
        "-DENABLE_SM9=ON",
        "-DENABLE_SM2_AMD64=OFF",
    ]
