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
