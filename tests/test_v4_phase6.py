import json
from pathlib import Path

from aegis.corpora import make_clean_corpus
from aegis.daemon import handle_request
from aegis.engine import Engine
from aegis.fp_budget import count_clean_matches
from aegis.html_report import render_report
from aegis.packmutate import mutation_report
from aegis.rulelint import lint_pack
from aegis.rules import RulePack

ROOT = Path(__file__).resolve().parent.parent
DELIVERY = ROOT / "rules" / "delivery_rules.json"
DELIVERY_TESTS = ROOT / "rules" / "delivery_rule_tests.json"


def test_delivery_pack_full_discipline():
    assert lint_pack(DELIVERY, DELIVERY_TESTS) == []
    report = mutation_report(DELIVERY, DELIVERY_TESTS)
    assert report["mutation_score"] == 1.0
    assert report["survived"] == []
    assert len(report["equivalent"]) == 2


def test_delivery_pack_fp_budget(tmp_path):
    clean = tmp_path / "clean"
    make_clean_corpus(clean)
    result = count_clean_matches(RulePack(DELIVERY), clean)
    assert all(v == 0 for v in result["counts"].values()), result


def test_daemon_hardening(tmp_path):
    engine = Engine(RulePack(ROOT / "rules" / "core_rules_v2.json"))
    # constant-time token check: wrong token refused, right one ok
    status, _ = handle_request(engine, "GET", "/ping", token="s3cret",
                               auth_header="wrong")
    assert status == 401
    status, _ = handle_request(engine, "GET", "/ping", token="s3cret",
                               auth_header="s3cret")
    assert status == 200
    # body cap
    status, doc = handle_request(engine, "POST", "/scan_name",
                                 body=b"x" * (17 * 1024 * 1024))
    assert status == 413
    # audit log records route and status, never the body
    audit = tmp_path / "audit.jsonl"
    handle_request(engine, "GET", "/ping", audit_path=audit)
    entry = json.loads(audit.read_text().strip())
    assert entry["route"] == "/ping" and entry["status"] == 200


def test_html_report_escapes_filenames():
    hostile = "<script>alert(1)</script>.exe"
    report = {"root": "/tmp/x", "files": 1,
              "summary": {"clean": 0, "malicious_pattern": 1},
              "results": [{"file": hostile,
                           "verdict": "malicious_pattern", "score": 90,
                           "hashes": {"sha256": "ab" * 32},
                           "evidence": [{"type": "rule_match",
                                         "rule_id": "X"}]}]}
    page = render_report(report)
    assert "<script>alert(1)</script>" not in page
    assert "&lt;script&gt;alert(1)&lt;/script&gt;.exe" in page
    assert "malicious_pattern" in page
