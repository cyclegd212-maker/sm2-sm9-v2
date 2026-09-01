from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COLLECT_ENV = ROOT / "native" / "scripts" / "collect_env.py"


def load_collect_env_module():
    spec = importlib.util.spec_from_file_location("v2_collect_env", COLLECT_ENV)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_collect_env_records_gmssl_build_options(tmp_path: Path) -> None:
    output = tmp_path / "environment.json"
    cmd = [
        sys.executable,
        str(COLLECT_ENV),
        "--output", str(output),
        "--run-id", "test-run",
        "--v2-commit", "v2-test",
        "--gmssl-commit", "gmssl-test",
        "--gmssl-build-options=-DENABLE_SM9=ON;-DENABLE_SM2_AMD64=OFF",
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


def test_windows_cpu_model_prefers_cim_marketing_name(monkeypatch) -> None:
    module = load_collect_env_module()
    monkeypatch.setattr(module.os, "name", "nt")
    monkeypatch.setenv("PROCESSOR_IDENTIFIER", "AMD64 Family 25 Model 120")

    calls = []

    def fake_check_output(args, **kwargs):
        calls.append(args)
        if args[0].lower().startswith("powershell"):
            return "AMD Ryzen 7 8845H w/ Radeon 780M Graphics\n"
        raise FileNotFoundError(args[0])

    monkeypatch.setattr(module.subprocess, "check_output", fake_check_output)
    assert module.cpu_model() == "AMD Ryzen 7 8845H w/ Radeon 780M Graphics"
    assert any("Win32_Processor" in " ".join(call) for call in calls)
