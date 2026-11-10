import os
import random
from pathlib import Path

import pytest

from aegis.calibration import Calibration, FormatCalibration, aci_run
from aegis.engine import Engine
from aegis.provenance import read_provenance
from aegis.rules import RulePack

ROOT = Path(__file__).resolve().parent.parent


def _triples():
    triples = []
    for i in range(10):
        triples.append((i, False, "text"))
        triples.append((50 + i, True, "text"))
    for i in range(3):  # pe group too small: must fall back
        triples.append((i, False, "pe"))
        triples.append((60 + i, True, "pe"))
    for i in range(8):
        triples.append((20 + i, False, "pdf"))
        triples.append((35 + i, True, "pdf"))
    return triples


def test_format_conditioning_and_fallback():
    fc = FormatCalibration(_triples())
    text_result = fc.classify(55, "text")
    assert text_result["conditioning"] == "format:text"
    pdf_result = fc.classify(37, "pdf")
    assert pdf_result["conditioning"] == "format:pdf"
    pe_result = fc.classify(61, "pe")
    assert pe_result["conditioning"].startswith("global")
    assert "pe" in fc.fallback_formats


def test_aci_long_run_coverage_under_drift():
    rng = random.Random(7)
    fit = [(rng.randrange(0, 20), False) for _ in range(60)] \
        + [(rng.randrange(40, 80), True) for _ in range(60)]
    stream = []
    for i in range(240):
        drift = 15 if i >= 120 else 0  # distribution shifts midway
        if i % 2:
            stream.append((rng.randrange(40 + drift, 80 + drift), True))
        else:
            stream.append((rng.randrange(0 + drift, 20 + drift), False))
    result = aci_run(fit, stream, alpha=0.1, gamma=0.02)
    assert result["long_run_coverage"] >= 0.85
    assert result["worst_window_coverage"] <= result["long_run_coverage"]
    assert "long-run" in result["guarantee"]


def test_provenance_zone_identifier_and_score_invariance(tmp_path):
    target = tmp_path / "download.bin"
    payload = b"AEGIS-SYNTHETIC-RANSOMWARE-PATTERN"
    target.write_bytes(payload)
    Path(str(target) + ":Zone.Identifier").write_text(
        "[ZoneTransfer]\nZoneId=3\n"
        "HostUrl=https://example.invalid/file\n")
    prov = read_provenance(target)
    assert prov["zone_identifier"]["zone_id"] == 3
    assert prov["zone_identifier"]["zone_meaning"] == "internet"
    assert prov["scores_affected"] is False
    engine = Engine(RulePack(ROOT / "rules" / "core_rules_v2.json"))
    with_prov = engine.scan_file(target)
    plain = tmp_path / "plain.bin"
    plain.write_bytes(payload)
    without = engine.scan_file(plain)
    assert with_prov["score"] == without["score"]
    assert with_prov["provenance"]["present"] is True
    assert "provenance" not in without


def _xattr_works(path) -> bool:
    """Capability probe, not a platform guess: CPython documents
    the xattr family as Linux-only, and even on Linux a
    filesystem may refuse them. Probe with a real set/get
    round-trip on the actual file."""
    if not (hasattr(os, "setxattr") and hasattr(os, "getxattr")):
        return False
    try:
        os.setxattr(path, "user.aegis.probe", b"1")
        return os.getxattr(path, "user.aegis.probe") == b"1"
    except OSError:
        return False


def test_provenance_xattrs(tmp_path):
    target = tmp_path / "f.bin"
    target.write_bytes(b"data")
    if not _xattr_works(target):
        pytest.skip("no working user xattrs on this platform "
                    "or filesystem (probed with a real set/get "
                    "round-trip, not guessed from the OS name)")
    os.setxattr(target, "user.aegis.test", b"hello")
    prov = read_provenance(target)
    assert prov["xattrs"].get("user.aegis.test") == "hello"
