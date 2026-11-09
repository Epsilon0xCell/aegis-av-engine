import json
import random
from pathlib import Path

import pytest

from aegis import transparency as tr
from aegis.behaviour import analyse, correlate
from aegis.corpora import make_clean_corpus, make_fixture_corpus
from aegis.parscan import report_json, scan_directory
from aegis.sigma_import import SigmaImportError, import_sigma, import_sigma_file

ROOT = Path(__file__).resolve().parent.parent
PACK = ROOT / "rules" / "core_rules_v2.json"


def _ev(t, **details):
    return {"event_type": t, "details": details}


# --- behaviour partial credit ---

def test_chain_partial_credit_and_fired():
    events = [_ev("process_create",
                  command_line="vssadmin delete shadows /all"),
              _ev("beacon")]
    results = {r["chain_id"]: r for r in analyse(events)}
    precursor = results["CHAIN-RANSOMWARE-PRECURSOR"]
    assert precursor["status"] == "partial"
    assert precursor["credit"] == 0.6  # 3 of 5 weight, in order
    assert precursor["missing_steps"] == ["file_encrypt"]
    events.append(_ev("file_encrypt"))
    fired = {r["chain_id"]: r for r in analyse(events)}
    assert fired["CHAIN-RANSOMWARE-PRECURSOR"]["status"] == "fired"
    assert correlate(events)  # binary API still reports it


def test_chain_order_matters():
    events = [_ev("file_encrypt"),
              _ev("process_create",
                  command_line="vssadmin delete shadows /all")]
    results = {r["chain_id"]: r for r in analyse(events)}
    # file_encrypt occurs BEFORE the shadow deletion, so the
    # ordered subsequence for the precursor chain cannot complete
    assert results["CHAIN-RANSOMWARE-PRECURSOR"]["status"] != "fired"


# --- sigma-subset ---

def test_sigma_shipped_rule_matches_and_filters():
    rule = import_sigma_file(ROOT / "sigma_json" / "vssadmin_shadow_deletion.json")
    assert rule["matches"]({"Image": "C:\\Windows\\vssadmin.exe",
                            "CommandLine": "vssadmin delete shadows /all"})
    assert not rule["matches"]({"Image": "C:\\Windows\\vssadmin.exe",
                                "CommandLine": "vssadmin list shadows"})
    assert not rule["matches"]({"Image": "C:\\Windows\\notepad.exe",
                                "CommandLine": "delete shadows"})


def test_sigma_rejects_unsupported_constructs_loudly():
    with pytest.raises(SigmaImportError, match="unsupported modifier"):
        import_sigma(json.dumps({
            "title": "x", "detection": {
                "selection": {"CommandLine|base64": "AAAA"},
                "condition": "selection"}}))
    with pytest.raises(SigmaImportError, match="correlation"):
        import_sigma(json.dumps({
            "title": "x", "correlation": {"type": "event_count"},
            "detection": {"selection": {"a": "b"},
                          "condition": "selection"}}))


# --- transparency log ---

def test_merkle_sweeps():
    rng = random.Random(9)
    for n in (1, 2, 3, 5, 8, 13, 21, 40):
        leaves = [bytes(rng.randrange(256) for _ in range(20))
                  for _ in range(n)]
        root = tr._mth(leaves).hex()
        for idx in range(n):
            proof = [h.hex() for h in tr._inclusion_path(idx, leaves)]
            assert tr.verify_inclusion(leaves[idx], idx, n, proof, root)
        for m in range(1, n):
            proof = [h.hex() for h in tr._subproof(m, leaves, True)]
            assert tr.verify_consistency(
                m, n, tr._mth(leaves[:m]).hex(), root, proof)
            assert not tr.verify_consistency(
                m, n, root, root, proof)


def test_log_append_heads_and_proofs(tmp_path):
    seed = bytes(range(32))
    log = tr.TransparencyLog(tmp_path / "log.json", signing_seed=seed)
    head0 = log.append({"pack": "aegis-core-fixtures", "version": "2.0.0",
                        "sequence": 7})
    log.append({"pack": "aegis-core-fixtures", "version": "2.0.1",
                "sequence": 8})
    head = log.tree_head()
    assert head["tree_size"] == 2
    assert log.verify_head_signature(head)
    proof = log.inclusion_proof(0)
    leaf = log.leaves[0]
    assert tr.verify_inclusion(leaf, 0, 2, proof, head["root"])
    cons = log.consistency_proof(1)
    assert tr.verify_consistency(1, 2, head0["root"], head["root"], cons)
    reopened = tr.TransparencyLog(tmp_path / "log.json", signing_seed=seed)
    assert reopened.root() == head["root"]


# --- parscan determinism ---

def test_parscan_deterministic_across_worker_counts(tmp_path):
    make_clean_corpus(tmp_path / "clean")
    make_fixture_corpus(tmp_path / "fixtures")
    one = scan_directory(tmp_path, PACK, workers=1)
    many = scan_directory(tmp_path, PACK, workers=4)
    assert report_json(one) == report_json(many)
    assert one["files"] >= 30
    assert one["summary"].get("malicious_pattern", 0) >= 1
