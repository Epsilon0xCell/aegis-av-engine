import json
import stat
from pathlib import Path

from aegis.corpora import make_clean_corpus, make_fixture_corpus
from aegis.differential import (_hexpattern_to_clam,
                                build_clam_database, compare_file,
                                parse_clamscan_output, run_differential)
from aegis.engine import Engine
from aegis.rules import RulePack

ROOT = Path(__file__).resolve().parent.parent
PACK = ROOT / "rules" / "core_rules_v2.json"


def test_database_conversion():
    db = build_clam_database(RulePack(PACK))
    ndb = db["files"]["aegis_fixtures.ndb"]
    assert "Aegis.AEGIS-TEST-001" in ndb
    # the EICAR identifier text converted to hex ("EICAR-")
    assert "45494341522D" in ndb
    # the hex rule's wildcards survive conversion
    assert "4D5A????????" in ndb
    assert all(r["status"].startswith("converted")
               for r in db["report"])


def test_hexpattern_jump_conversion():
    assert _hexpattern_to_clam("4D 5A [2-6] 90") == "4D5A{2-6}90"
    assert _hexpattern_to_clam("4D 5A [4] ??") == "4D5A{4}??"


def test_parse_clamscan_output():
    text = ("/tmp/a.bin: Aegis.AEGIS-FIX-001.a FOUND\n"
            "/tmp/b.txt: OK\n"
            "----------- SCAN SUMMARY -----------\n")
    out = parse_clamscan_output(text)
    assert out["/tmp/a.bin"] == ["Aegis.AEGIS-FIX-001.a"]
    assert out["/tmp/b.txt"] == []


def _stub_clamscan(tmp_path: Path) -> Path:
    """A stub with clamscan's output contract: reports the
    Aegis.* signature for files containing the fixture marker,
    OK otherwise."""
    stub = tmp_path / "clamscan_stub.py"
    stub.write_text(
        "#!/usr/bin/env python3\n"
        "import sys, pathlib\n"
        "args = [a for a in sys.argv[1:] if not a.startswith('-')]\n"
        "for root in args:\n"
        "    for p in sorted(pathlib.Path(root).rglob('*')):\n"
        "        if p.is_file():\n"
        "            data = p.read_bytes()\n"
        "            if b'AEGIS-SYNTHETIC-RANSOMWARE-PATTERN' in data:\n"
        "                print(f'{p}: Aegis.AEGIS-FIX-001.a FOUND')\n"
        "            elif b'EICAR' in data:\n"
        "                print(f'{p}: Aegis.AEGIS-TEST-001.a FOUND')\n"
        "            else:\n"
        "                print(f'{p}: OK')\n")
    stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
    return stub


def test_differential_end_to_end_with_stub(tmp_path):
    corpus = tmp_path / "corpus"
    make_clean_corpus(corpus / "clean")
    make_fixture_corpus(corpus / "fixtures")
    engine = Engine(RulePack(PACK))
    result = run_differential(engine, RulePack(PACK), corpus,
                              tmp_path / "db",
                              clamscan=str(_stub_clamscan(tmp_path)))
    print(json.dumps(result["buckets"], indent=1))
    assert result["status"] == "completed"
    assert result["unexplained"] == 0
    assert result["buckets"].get("agree_detect", 0) >= 2
    assert result["buckets"].get("agree_clean", 0) >= 20


def test_differential_unavailable_is_honest(tmp_path):
    corpus = tmp_path / "corpus"
    make_clean_corpus(corpus)
    result = run_differential(Engine(RulePack(PACK)), RulePack(PACK),
                              corpus, tmp_path / "db", clamscan=None)
    # in CI clamscan may exist; either outcome must be explicit
    assert result["status"] in ("clamscan_unavailable", "completed")
    if result["status"] == "clamscan_unavailable":
        assert "no comparison is claimed" in result["note"]
