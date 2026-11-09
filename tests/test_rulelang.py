from pathlib import Path

import pytest

from aegis.rulelang import HexPattern, PatternError, evaluate_condition
from aegis.rulelint import lint_pack
from aegis.rules import RulePack

ROOT = Path(__file__).resolve().parent.parent


def test_hex_wildcards_and_nibbles():
    p = HexPattern("4D 5A ?? 00 4?")
    assert p.search(b"\x00MZ\x99\x00\x4f\x00")
    assert not p.search(b"\x00MZ\x99\x00\x3f\x00")
    q = HexPattern("?5")
    assert q.search(b"\xa5")


def test_hex_ranged_jump():
    p = HexPattern("41 [2-4] 42")
    assert p.search(b"AxxB")
    assert p.search(b"AxxxxB")
    assert not p.search(b"AxB")
    with pytest.raises(PatternError):
        HexPattern("41 [999]")


def test_conditions():
    matched = {"$a", "$b"}
    facts = {"format": "pe", "entropy": 7.5, "size": 10}
    assert evaluate_condition({"all_of": ["$a", "$b"]}, matched, facts)
    assert not evaluate_condition({"all_of": ["$a", "$c"]}, matched, facts)
    assert evaluate_condition({"count_at_least": {"of": ["$a", "$b", "$c"], "n": 2}},
                              matched, facts)
    assert evaluate_condition({"and": [{"format_is": "pe"}, {"entropy_above": 7.2}]},
                              matched, facts)
    assert evaluate_condition({"not": {"format_is": "elf"}}, matched, facts)


def test_v2_pack_loads_and_lints_clean():
    problems = lint_pack(ROOT / "rules" / "core_rules_v2.json",
                         ROOT / "rules" / "rule_tests.json")
    assert problems == [], problems


def test_v1_pack_still_loads():
    pack = RulePack(ROOT / "rules" / "core_rules.json")
    matched = pack.match(b"xx EICAR-STANDARD-ANTIVIRUS-TEST-FILE yy")
    assert [m["rule_id"] for m in matched] == ["AEGIS-TEST-001"]


def test_hex_rule_fires_through_engine():
    from aegis.engine import Engine
    engine = Engine(RulePack(ROOT / "rules" / "core_rules_v2.json"))
    from tests.test_containers_formats import _minimal_pe
    pe = bytearray(_minimal_pe())
    # place the AEGIS marker inside the DOS stub area after MZ + 8 wildcard bytes
    pe[10:15] = b"AEGIS"
    v = engine.scan_bytes(bytes(pe), "fixture.exe")
    assert any(e.get("rule_id") == "AEGIS-HEX-001" for e in v["evidence"])
