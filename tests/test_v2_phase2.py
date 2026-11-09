from pathlib import Path

from aegis.calibration import (Calibration, build_calibration_pairs,
                               classify_score, ece_report, risk_coverage)
from aegis.corpora import make_clean_corpus, make_fixture_corpus
from aegis.engine import Engine
from aegis.rules import RulePack

ROOT = Path(__file__).resolve().parent.parent

SEPARABLE = ([(s, False) for s in (0, 2, 4, 6, 8, 10, 12, 14, 16, 18)]
             + [(s, True) for s in (80, 84, 88, 92, 96, 100, 104, 108, 112, 116)])


def test_confident_bands_on_separable_scores():
    calib = Calibration(SEPARABLE)
    assert calib.classify(5)["band"] == "confident_clean"
    assert calib.classify(100)["band"] == "confident_suspicious"


def test_abstain_novel_between_classes():
    calib = Calibration(SEPARABLE)
    result = calib.classify(45)
    assert result["band"] == "abstain_novel"
    assert result["prediction_set"] == []


def test_abstain_ambiguous_in_overlap():
    pairs = ([(s, False) for s in range(0, 60, 4)]
             + [(s, True) for s in range(40, 100, 4)])
    calib = Calibration(pairs)
    result = calib.classify(50)
    assert result["band"] == "abstain_ambiguous"
    assert set(result["prediction_set"]) == {"clean", "malicious"}


def test_risk_coverage_curve_on_separable_data():
    pairs = SEPARABLE * 3
    curve = risk_coverage(pairs)
    row = [r for r in curve if r["alpha"] == 0.1][0]
    assert row["coverage"] >= 0.9
    assert row["risk"] == 0.0


def test_ece_report_shape():
    pairs = SEPARABLE * 3
    report = ece_report(pairs)
    assert report["ece"] is not None
    assert 0.0 <= report["ece"] <= 1.0


def test_end_to_end_generated_corpora(tmp_path):
    make_clean_corpus(tmp_path / "clean")
    make_fixture_corpus(tmp_path / "fixtures")
    engine = Engine(RulePack(ROOT / "rules" / "core_rules_v2.json"))
    pairs = build_calibration_pairs(engine, tmp_path / "clean",
                                    tmp_path / "fixtures")
    assert len(pairs) >= 20
    calib = Calibration(pairs)
    clean_scores = [s for s, m in pairs if not m]
    result = classify_score(min(clean_scores), calib)
    assert result["band"] in ("confident_clean", "abstain_ambiguous",
                              "abstain_novel")
    assert result["ceiling"] == "suspicious"
