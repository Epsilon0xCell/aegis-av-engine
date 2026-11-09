from pathlib import Path

from aegis.corpus_checks import generate_and_check
from aegis.packmutate import mutation_report
from aegis.prevalence import precision_at_prevalence, prevalence_report

ROOT = Path(__file__).resolve().parent.parent


def test_prevalence_hand_computed():
    # TPR 0.8, FPR 0.1 at prevalence 0.5:
    # precision = .8*.5 / (.8*.5 + .1*.5) = 0.8889
    assert precision_at_prevalence(8, 1, 2, 9, 0.5) == 0.888889
    # at 1 percent prevalence the same detector is mostly wrong:
    # .008 / (.008 + .099) = 0.0748
    assert precision_at_prevalence(8, 1, 2, 9, 0.01) == 0.074766
    report = prevalence_report(8, 1, 2, 9)
    assert report["rates"]["tpr"] == 0.8


def test_corpus_properties_hold(tmp_path):
    assert generate_and_check(tmp_path) == []


def test_reintroduced_generator_bug_is_caught(tmp_path):
    # the v2 bug, deliberately: a constant-byte "high entropy"
    # fixture must fail the registry by claim name
    from aegis.corpus_checks import check_corpora
    (tmp_path / "clean").mkdir()
    (tmp_path / "fixtures").mkdir()
    (tmp_path / "fixtures" / "fixture_high_entropy.bin").write_bytes(b"y" * 4096)
    failures = check_corpora(tmp_path / "clean", tmp_path / "fixtures")
    assert any("entropy above 7.0" in f["claim"] for f in failures)


def test_pack_mutation_score():
    rep = mutation_report(ROOT / "rules" / "core_rules_v2.json",
                          ROOT / "rules" / "rule_tests.json")
    assert rep["survived"] == [], rep["survived"]
    assert rep["mutation_score"] == 1.0
    # the two single-string condition flips are documented
    # equivalents, not silent survivors
    assert len(rep["equivalent"]) == 2


def test_engine_profile_shape(tmp_path):
    from aegis.corpora import EICAR
    from aegis.engine import Engine
    from aegis.rules import RulePack
    f = tmp_path / "e.txt"
    f.write_text(EICAR)
    eng = Engine(RulePack(ROOT / "rules" / "core_rules_v2.json"), profile=True)
    v = eng.scan_file(f)
    assert "digests" in v["profile_ms"] and "tlsh_and_assembly" in v["profile_ms"]
    assert all(ms >= 0 for ms in v["profile_ms"].values())
