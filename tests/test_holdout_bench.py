from pathlib import Path

import pytest

from aegis.benchmark5 import run_benchmark
from aegis.corpora import write_manifests
from aegis.engine import Engine
from aegis.holdout import HoldoutError, generate_holdout, score_holdout
from aegis.rules import RulePack

ROOT = Path(__file__).resolve().parent.parent


def _engine():
    return Engine(RulePack(ROOT / "rules" / "core_rules_v2.json"))


def test_holdout_scores_once_then_refuses(tmp_path):
    holdout = tmp_path / "holdout"
    info = generate_holdout(holdout, seed=4242)
    assert info["files"] >= 10
    result = score_holdout(_engine(), holdout)
    assert result["fp"] == 0, result
    assert result["fn"] <= 1, result  # wrapped/random mutations documented if missed
    assert result["commitment"] == info["commitment"]
    with pytest.raises(HoldoutError):
        score_holdout(_engine(), holdout)


def test_holdout_commitment_detects_tampering(tmp_path):
    holdout = tmp_path / "holdout"
    generate_holdout(holdout, seed=99)
    victim = next(holdout.glob("holdout_*"))
    victim.write_bytes(victim.read_bytes() + b"tamper")
    with pytest.raises(HoldoutError):
        score_holdout(_engine(), holdout)


def test_benchmark5_protocol(tmp_path):
    corpus = tmp_path / "corpus"
    write_manifests(corpus)
    report = run_benchmark(_engine, corpus, runs=3)
    assert report["deterministic_across_runs"] is True
    assert report["cold_files_per_sec_median"] > 0
    assert report["warm_files_per_sec_median"] >= report["cold_files_per_sec_median"] * 0.5
    assert len(report["corpus_manifest_sha256"]) == 16
