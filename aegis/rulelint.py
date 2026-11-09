"""Rule pack linter: schema, sanity, and per-rule fixture tests.

A rule that cannot pass its own fixture does not ship. The linter
checks: duplicate ids, condition references to unknown strings,
suspiciously short patterns, weight range, a positive AND a
negative fixture for every rule, and that the matcher agrees with
every fixture (with the fixture's declared format fact).
"""
from __future__ import annotations

import json
from pathlib import Path

from .rulelang import evaluate_condition
from .rules import RulePack


def _condition_refs(cond: dict) -> set[str]:
    refs: set[str] = set()
    for key in ("all_of", "any_of"):
        if key in cond:
            refs.update(cond[key])
    if "count_at_least" in cond:
        refs.update(cond["count_at_least"]["of"])
    for key in ("and", "or"):
        if key in cond:
            for sub in cond[key]:
                refs.update(_condition_refs(sub))
    if "not" in cond:
        refs.update(_condition_refs(cond["not"]))
    return refs


def lint_pack(pack_path: Path, tests_path: Path) -> list[str]:
    problems: list[str] = []
    try:
        pack = RulePack(pack_path)
    except Exception as exc:
        return [f"pack does not load: {exc}"]
    seen_rules: set[str] = set()
    for rule in pack.rules:
        if rule["id"] in seen_rules:
            problems.append(f"duplicate rule id {rule['id']}")
        seen_rules.add(rule["id"])
        if not (1 <= rule["weight"] <= 100):
            problems.append(f"{rule['id']}: weight {rule['weight']} outside 1..100")
        string_ids = set()
        for s in rule["strings"]:
            if s["id"] in string_ids:
                problems.append(f"{rule['id']}: duplicate string id {s['id']}")
            string_ids.add(s["id"])
            if s["type"] == "text" and len(s["value"]) < 4:
                problems.append(f"{rule['id']}: text pattern {s['id']} shorter than 4 chars")
            if s["type"] == "hex" and len(s["value"].split()) < 3:
                problems.append(f"{rule['id']}: hex pattern {s['id']} shorter than 3 tokens")
        unknown = _condition_refs(rule["condition"]) - string_ids
        if unknown:
            problems.append(f"{rule['id']}: condition references unknown strings {sorted(unknown)}")
    tests = json.loads(tests_path.read_text())["tests"]
    by_rule: dict[str, dict] = {}
    for t in tests:
        if t["rule_id"] not in seen_rules:
            problems.append(f"fixture references unknown rule {t['rule_id']}")
        by_rule[t["rule_id"]] = t
    for rule in pack.rules:
        t = by_rule.get(rule["id"])
        if t is None:
            problems.append(f"{rule['id']}: no fixture tests")
            continue
        facts = {"format": t.get("format", "binary_unknown"), "entropy": 0.0, "size": 0}
        pos = _fixture_bytes(t, positive=True)
        neg = _fixture_bytes(t, positive=False)
        if pos is None or neg is None:
            problems.append(f"{rule['id']}: fixture missing a positive or negative case")
            continue
        hits = pack.automaton.search(pos)
        ids = pack.matched_string_ids(rule, pos, hits)
        if not (ids and evaluate_condition(rule["condition"], ids, facts)):
            problems.append(f"{rule['id']}: positive fixture does not match")
        hits = pack.automaton.search(neg)
        ids = pack.matched_string_ids(rule, neg, hits)
        if ids and evaluate_condition(rule["condition"], ids, facts):
            problems.append(f"{rule['id']}: negative fixture matches (false positive in fixture)")
    return problems


def _fixture_bytes(t: dict, positive: bool) -> bytes | None:
    if positive:
        if "should_match" in t:
            return t["should_match"].encode()
        if "should_match_hex" in t:
            return bytes(int(x, 16) for x in t["should_match_hex"].split())
    else:
        if "should_not_match" in t:
            return t["should_not_match"].encode()
        if "should_not_match_hex" in t:
            return bytes(int(x, 16) for x in t["should_not_match_hex"].split())
    return None
