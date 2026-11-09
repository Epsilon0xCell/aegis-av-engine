import json
from pathlib import Path

from aegis.corpora import EICAR, make_clean_corpus, make_fixture_corpus
from aegis.engine import Engine
from aegis.exports import navigator_layer, sarif_log, stix_bundle
from aegis.rules import RulePack
from aegis.scoring import extract_features, score_features, score_verdict

ROOT = Path(__file__).resolve().parent.parent


def _engine():
    return Engine(RulePack(ROOT / "rules" / "core_rules_v2.json"))


def test_scoring_exact_contributions():
    feats = {"entropy_above_6_x10": 14, "exec_high_entropy_sections": 1}
    out = score_features(feats)
    assert out["exact_sum_check"] is True
    assert out["score"] == 14 * 3 + 18
    assert out["flag"] == "suspicious"
    assert out["ceiling"] == "suspicious"


def test_scoring_clean_corpus_stays_low(tmp_path):
    engine = _engine()
    clean = make_clean_corpus(tmp_path / "clean")
    for rel in clean:
        verdict = engine.scan_file(tmp_path / "clean" / rel)
        scored = score_verdict(verdict, verdict["size"])
        assert scored["flag"] == "none", (rel, scored)


def test_exports_shapes(tmp_path):
    engine = _engine()
    fixtures = make_fixture_corpus(tmp_path / "fix")
    verdicts = [engine.scan_file(tmp_path / "fix" / rel)
                for rel in fixtures]
    verdicts.append(engine.scan_bytes(EICAR.encode(), "eicar.com"))
    layer = navigator_layer(verdicts)
    tids = {t["techniqueID"] for t in layer["techniques"]}
    assert "T1486" in tids and layer["versions"]["layer"] == "4.5"
    bundle = stix_bundle(verdicts)
    types = {o["type"] for o in bundle["objects"]}
    assert {"file", "malware-analysis"} <= types
    assert all(o.get("spec_version") == "2.1" for o in bundle["objects"])
    assert stix_bundle(verdicts) == bundle  # deterministic ids
    sarif = sarif_log(verdicts)
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"]
    json.dumps(layer), json.dumps(bundle), json.dumps(sarif)
