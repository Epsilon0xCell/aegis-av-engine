import json
from pathlib import Path

import pytest

from aegis.behaviour import analyse
from aegis.mining import CandidatePattern, mine
from aegis.promoted import PromotionError, load_promoted
from aegis.sigma_correlation import (CorrelationError, evaluate,
                                     load_correlation)
from aegis.sigma_import import import_sigma_file

ROOT = Path(__file__).resolve().parent.parent
BASE_ID = "98432000-0000-4000-8000-000000000101"


def _base_rules():
    rule = import_sigma_file(ROOT / "sigma_json"
                             / "vssadmin_shadow_deletion.json")
    return {rule["id"]: rule}


def _event(ts, host="ws1", **kw):
    doc = {"timestamp": ts, "host": host,
           "Image": r"C:\Windows\System32\vssadmin.exe",
           "CommandLine": "vssadmin delete shadows /all"}
    doc.update(kw)
    return doc


def test_event_count_correlation():
    corr = load_correlation(
        (ROOT / "sigma_json" / "correlations"
         / "repeated_shadow_deletion.json").read_text())
    events = [_event(0), _event(120), _event(240)]
    hits = evaluate(corr, _base_rules(), events)
    assert len(hits) == 1 and hits[0]["value"] == 3
    assert hits[0]["group"] == {"host": "ws1"}
    # two events inside the span on another host do not fire
    sparse = [_event(0), _event(120), _event(0, host="ws2"),
              _event(4000, host="ws2")]
    assert evaluate(corr, _base_rules(), sparse) == []


def test_temporal_and_ordered():
    rules = _base_rules()
    beacon = {"title": "beacon", "id": "beacon-rule",
              "detection": {"selection": {"action": "beacon"},
                            "condition": "selection"}}
    from aegis.sigma_import import import_sigma
    rules["beacon-rule"] = import_sigma(json.dumps(beacon))
    corr = load_correlation(json.dumps({
        "title": "t", "id": "c2", "correlation": {
            "type": "temporal_ordered",
            "rules": [BASE_ID, "beacon-rule"], "timespan": "10m",
            "condition": {"gte": 1}}}))
    in_order = [_event(10),
                {"timestamp": 100, "action": "beacon"}]
    assert evaluate(corr, rules, in_order)
    out_of_order = [{"timestamp": 5, "action": "beacon"}, _event(10)]
    assert evaluate(corr, rules, out_of_order) == []


def test_aggregation_rejected_loudly():
    with pytest.raises(CorrelationError, match="aggregation"):
        load_correlation(json.dumps({
            "title": "t", "correlation": {"type": "value_sum",
                                          "rules": "x"}}))


def test_promoted_chain_fires_and_unsigned_refused(tmp_path):
    chains = load_promoted(ROOT / "chains" / "promoted_chains.json")
    events = [{"event_type": "process_create", "technique": "T1490",
               "details": {"cmdline": "vssadmin delete shadows"}},
              {"event_type": "beacon", "technique": "T1071.001",
               "details": {}}]
    results = analyse(events, extra_chains=chains)
    promoted = next(r for r in results
                    if r["chain_id"] == "CHAIN-PROMOTED-ERASURE-THEN-BEACON")
    assert promoted["status"] == "fired"
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"chains": [{
        "id": "X", "promoted_from": {"pattern": ["a:T1"],
                                     "support": 2}}]}))
    with pytest.raises(PromotionError, match="no approver"):
        load_promoted(bad)


def test_miner_output_still_type_walled():
    candidates = mine([["process_create:T1490", "beacon:T1071.001"]],
                      min_support=1)
    assert candidates and isinstance(candidates[0], CandidatePattern)
    with pytest.raises(TypeError):
        analyse([], extra_chains=candidates)  # type: ignore[arg-type]
