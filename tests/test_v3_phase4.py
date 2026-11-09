from pathlib import Path

import pytest

from aegis.corpora import make_clean_corpus
from aegis.fp_budget import check_fp_budget
from aegis.rules import RulePack
from aegis.yara_import import YaraImportError, import_yara, import_yara_file

ROOT = Path(__file__).resolve().parent.parent

SAMPLE = """
rule Demo
{
    strings:
        $a = "AegisFixture" ascii wide nocase
        $b = "PATTERN" fullword
        $c = { 4D 5A ?? 90 }
    condition:
        2 of them and #b >= 1 and filesize < 1MB
}
"""


def test_yara_import_and_evaluate():
    out = import_yara(SAMPLE)
    (rule,) = out["rules"]
    hay = b"MZ\x00\x90" + b"aegisfixture" \
        + "AegisFixture".encode("utf-16-le") + b" a PATTERN here"
    result = rule.evaluate(hay)
    assert result["matched"]
    assert result["counts"]["a"] >= 2  # ascii nocase + wide variant
    assert result["counts"]["c"] == 1
    # fullword: PATTERN inside PATTERNED is not a word match
    buried = rule.evaluate(b"MZ\x00\x90" + b"AEGISFIXTURE" + b" PATTERNED")
    assert buried["counts"]["b"] == 0
    text_report = out["report"][0]
    assert "of expressions" in text_report["constructs"]


def test_yara_example_file_imports():
    out = import_yara_file(ROOT / "yara_rules" / "example.yara")
    assert {r.name for r in out["rules"]} == {
        "Aegis_Fixture_Markers", "Aegis_PE_Header_Entropy"}
    pe_rule = out["rules"][1]
    data = b"MZ" + bytes(200)
    assert not pe_rule.evaluate(data)["matched"]  # no pe fact supplied
    with_fact = pe_rule.evaluate(data, {"pe_sections": 3})
    assert with_fact["matched"]


@pytest.mark.parametrize("source,construct", [
    ('rule R { strings: $a = /abc.*/ condition: $a }',
     "regular-expression"),
    ('rule R { strings: $a = "x" xor condition: $a }', "xor"),
    ('rule R { strings: $a = "x" condition: for any i in '
     '(1..#a) : ( $a ) }', "for loops"),
    ('rule R { strings: $a = "x" condition: @a == 0 }',
     "offset/length"),
    ('import "hash"\nrule R { strings: $a = "x" condition: $a }',
     "hash"),
    ('rule R { strings: $a = "x" condition: pe.is_pe }', "pe.is_pe"),
    ('rule R { strings: $a = "x" condition: $a and unknown_var > 3 }',
     "external variable"),
])
def test_yara_rejections_are_loud_and_specific(source, construct):
    with pytest.raises(YaraImportError) as exc:
        import_yara(source)
    assert construct in str(exc.value)


def test_fp_budget_clean_on_shipped_pack(tmp_path):
    clean = tmp_path / "clean"
    make_clean_corpus(clean)
    pack = RulePack(ROOT / "rules" / "core_rules_v2.json")
    result = check_fp_budget(pack, clean, ROOT / "rules" / "fp_budget.json")
    assert result["violations"] == [], result


def test_fp_budget_names_a_dirty_rule(tmp_path):
    clean = tmp_path / "clean"
    make_clean_corpus(clean)
    import json
    pack_data = json.loads(
        (ROOT / "rules" / "core_rules_v2.json").read_text())
    pack_data["rules"].append({
        "id": "TEST-DIRTY", "name": "matches everything",
        "description": "test", "weight": 10, "attck": [],
        "strings": [{"id": "$s", "type": "text", "value": "name"}],
        "condition": {"all_of": ["$s"]}})
    dirty = tmp_path / "dirty.json"
    dirty.write_text(json.dumps(pack_data))
    result = check_fp_budget(RulePack(dirty), clean)
    assert [v["rule"] for v in result["violations"]] == ["TEST-DIRTY"]
    assert result["violations"][0]["budget"] == 0
