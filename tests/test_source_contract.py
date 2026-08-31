"""Static tests that can run even when the pinned external SM9 dependency is unavailable."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TEXT = (ROOT / "src" / "v2_scheme.py").read_text(encoding="utf-8")

def test_no_sm4():
    assert "SM4" not in TEXT.upper()

def test_domains_present():
    for tag in ["/KEY/v1", "/ENC/v1", "/SC/v1", "/MAC/v1", "/CTX/v1"]:
        assert tag in TEXT

def test_pinned_dependency():
    req = (ROOT / "requirements.txt").read_text(encoding="utf-8")
    assert "498ba0545a3f7667ab4575e93cd10e9b19baf4f0" in req

def test_token_is_consumed_before_online_use():
    assert "token.consumed = True" in TEXT

def test_benchmark_runners_use_module_mode():
    sh = (ROOT / "scripts" / "run_all.sh").read_text(encoding="utf-8")
    ps = (ROOT / "scripts" / "run_all.ps1").read_text(encoding="utf-8")
    assert "python -m bench.benchmark" in sh
    assert "python -m bench.benchmark" in ps


def test_windows_submission_records_stable_gmssl_sm2_configuration():
    script = (ROOT / "native" / "scripts" / "run_submission_windows.ps1").read_text(encoding="utf-8")
    assert '"-DENABLE_SM2_AMD64=OFF"' in script
    assert '--gmssl-build-options=' in script
    assert '-DENABLE_SM9=ON;-DENABLE_SM2_AMD64=OFF' in script
