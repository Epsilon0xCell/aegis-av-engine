import json
from pathlib import Path

import pytest

from aegis.behaviour import correlate
from aegis.corpora import EICAR, write_manifests
from aegis.engine import Engine
from aegis.hashing import BloomFilter, fuzzy_digest, fuzzy_similarity
from aegis.quarantine import quarantine_file, restore_file
from aegis.rules import RulePack
from aegis.strings_engine import AhoCorasick

PACK = Path(__file__).resolve().parent.parent / "rules" / "core_rules.json"


@pytest.fixture()
def engine():
    return Engine(RulePack(PACK))


def test_aho_corasick_finds_all_patterns():
    ac = AhoCorasick()
    ac.add(b"he", "a"); ac.add(b"she", "b"); ac.add(b"hers", "c")
    ac.build()
    hits = ac.search(b"ushers")
    assert hits == {"a": 1, "b": 1, "c": 1}
    assert ac.pattern_count == 3 and ac.state_count > 3


def test_bloom_no_false_negatives():
    bf = BloomFilter()
    bf.add("abc123")
    assert "abc123" in bf


def test_fuzzy_digest_similarity():
    base = b"A" * 200 + b"pattern-data" * 20
    near = base[:-10] + b"0123456789"
    sim = fuzzy_similarity(fuzzy_digest(base), fuzzy_digest(near))
    assert sim > 0.5
    far = fuzzy_similarity(fuzzy_digest(base), fuzzy_digest(b"Z" * 400))
    assert far < 0.3


def test_clean_text_is_clean(engine):
    v = engine.scan_bytes(b"Ordinary meeting notes about benchmarks. " * 10,
                          "notes.txt")
    assert v["verdict"] == "clean" and v["evidence"] == []


def test_fixtures_flagged_and_eicar(engine):
    v = engine.scan_bytes(b"INERT\nAEGIS-SYNTHETIC-RANSOMWARE-PATTERN\n", "f.bin")
    assert v["verdict"] == "malicious_pattern"
    assert any(e["type"] == "rule_match" for e in v["evidence"])
    e = engine.scan_bytes(EICAR.encode(), "eicar.txt")
    assert e["score"] >= 100 and e["verdict"] == "malicious_pattern"


def test_determinism(engine):
    data = b"AEGIS-SYNTH-download-cradle and AEGIS-SYNTH-hidden-window in a script"
    a = engine.scan_bytes(data, "s.ps1")
    fresh = Engine(RulePack(PACK)).scan_bytes(data, "s.ps1")
    assert (a["verdict"], a["score"]) == (fresh["verdict"], fresh["score"])


def test_benchmark_corpus_accounting(engine, tmp_path):
    manifest = write_manifests(tmp_path / "corpus")
    from aegis.benchmark import run_benchmark
    report = run_benchmark(engine, tmp_path / "corpus", manifest)
    assert report["deterministic"] is True
    assert report["clean_flagged_fp"] == 0
    assert report["fixtures_flagged_tp"] >= 4


def test_behaviour_chains():
    events = [
        {"event_type": "hook_install_fixture", "details": {}},
        {"event_type": "log_append", "details": {}},
        {"event_type": "beacon", "details": {}},
        {"event_type": "file_encrypt", "details": {}},
        {"event_type": "process_create",
         "details": {"command_line": "vssadmin Delete Shadows /all"}},
    ]
    ids = {f["chain_id"] for f in correlate(events)}
    assert "CHAIN-KEYLOG-BEHAVIOUR" in ids
    assert "CHAIN-RANSOMWARE-PRECURSOR" in ids
    assert correlate([{"event_type": "beacon", "details": {}}]) == []


def test_quarantine_roundtrip(tmp_path):
    f = tmp_path / "suspect.bin"
    f.write_bytes(b"fixture")
    receipt = quarantine_file(f, tmp_path / "q", "test")
    assert not f.exists() and receipt["sha256"]
    back = restore_file("suspect.bin", tmp_path / "q")
    assert back.read_bytes() == b"fixture"
