"""Pack mutation testing: is the fixture suite actually strong?

Mutation testing asks whether the tests would NOTICE if the
pack changed. A mutant pack (one rule dropped, one string
dropped, one weight flattened, one condition flipped) is run
against a behaviour signature built from the rule fixtures plus
probes synthesised from the pack's own strings (each string
alone, each pair). If a mutant's signature equals the
baseline's, the mutant SURVIVED: the suite cannot tell that
pack from the real one, and either the suite grows a probe or
the mutant is documented as equivalent with the argument
written down (single-element all_of and any_of are the same
predicate; that is an equivalence, not a gap).

The score is reported, never massaged: mutation score counts
only non-equivalent mutants.
"""
from __future__ import annotations

import copy
import json
import tempfile
from pathlib import Path

from .rulelang import evaluate_condition
from .rulelint import _fixture_bytes
from .rules import RulePack

EQUIVALENT = {
    ("condition_flip", "AEGIS-FIX-002"):
        "all_of over a single string is the same predicate as any_of",
    ("condition_flip", "AEGIS-TEST-001"):
        "all_of over a single string is the same predicate as any_of",
}


def _rule_outcome(pack: RulePack, rule: dict, data: bytes,
                  fmt: str = "binary_unknown") -> tuple[bool, int]:
    hits = pack.automaton.search(data)
    ids = pack.matched_string_ids(rule, data, hits)
    facts = {"format": fmt, "entropy": 0.0, "size": len(data)}
    matched = bool(ids) and evaluate_condition(rule["condition"], ids, facts)
    return matched, (rule["weight"] if matched else 0)


def behaviour_signature(pack_path: Path, tests_path: Path) -> dict:
    pack = RulePack(pack_path)
    tests = json.loads(Path(tests_path).read_text())["tests"]
    sig: dict[str, tuple] = {}
    by_id = {r["id"]: r for r in pack.rules}
    for t in tests:
        rule = by_id.get(t["rule_id"])
        if rule is None:
            sig[f"fixture:{t['rule_id']}"] = ("missing", 0)
            continue
        fmt = t.get("format", "binary_unknown")
        pos = _fixture_bytes(t, True)
        neg = _fixture_bytes(t, False)
        if pos is not None:
            sig[f"fixture:{t['rule_id']}:pos"] = _rule_outcome(pack, rule, pos, fmt)
        if neg is not None:
            sig[f"fixture:{t['rule_id']}:neg"] = _rule_outcome(pack, rule, neg, fmt)
    for rule in pack.rules:
        text_strings = [s for s in rule["strings"] if s["type"] == "text"]
        for s in text_strings:
            sig[f"probe:{rule['id']}:{s['id']}"] = _rule_outcome(
                pack, rule, s["value"].encode())
        for i, s1 in enumerate(text_strings):
            for s2 in text_strings[i + 1:]:
                probe = s1["value"].encode() + b" " + s2["value"].encode()
                sig[f"pair:{rule['id']}:{s1['id']}+{s2['id']}"] = \
                    _rule_outcome(pack, rule, probe)
    return sig


def _mutants(pack_doc: dict):
    for ri, rule in enumerate(pack_doc["rules"]):
        rid = rule["id"]
        doc = copy.deepcopy(pack_doc)
        doc["rules"] = [r for r in doc["rules"] if r["id"] != rid]
        yield ("drop_rule", rid, doc)
        doc = copy.deepcopy(pack_doc)
        doc["rules"][ri]["weight"] = 1
        yield ("weight_to_1", rid, doc)
        for si, s in enumerate(rule["strings"]):
            doc = copy.deepcopy(pack_doc)
            doc["rules"][ri]["strings"] = [
                x for x in doc["rules"][ri]["strings"] if x["id"] != s["id"]]
            if doc["rules"][ri]["strings"]:
                yield ("drop_string", rid + s["id"], doc)
        cond = rule["condition"]
        for key in ("all_of", "any_of"):
            if key in cond:
                doc = copy.deepcopy(pack_doc)
                other = "any_of" if key == "all_of" else "all_of"
                doc["rules"][ri]["condition"] = {other: cond[key]}
                yield ("condition_flip", rid, doc)
                if len(cond[key]) > 1:
                    for elem in cond[key]:
                        doc = copy.deepcopy(pack_doc)
                        doc["rules"][ri]["condition"] = {
                            key: [e for e in cond[key] if e != elem]}
                        yield ("condition_weaken", rid + elem, doc)


def mutation_report(pack_path: Path, tests_path: Path) -> dict:
    pack_doc = json.loads(Path(pack_path).read_text())
    baseline = behaviour_signature(pack_path, tests_path)
    killed, survived, equivalent = [], [], []
    with tempfile.TemporaryDirectory() as tmp:
        for kind, target, doc in _mutants(pack_doc):
            mpath = Path(tmp) / "mutant.json"
            mpath.write_text(json.dumps(doc))
            try:
                sig = behaviour_signature(mpath, tests_path)
            except Exception:
                killed.append({"mutant": kind, "target": target,
                               "how": "mutant pack fails to load or evaluate"})
                continue
            changed = [k for k in baseline if sig.get(k) != baseline[k]]
            entry = {"mutant": kind, "target": target}
            if changed:
                entry["changed_probes"] = changed[:4]
                killed.append(entry)
            elif (kind, target) in EQUIVALENT:
                entry["argument"] = EQUIVALENT[(kind, target)]
                equivalent.append(entry)
            else:
                survived.append(entry)
    total = len(killed) + len(survived)
    return {"mutants_total_nontrivial": total + len(equivalent),
            "killed": killed, "survived": survived,
            "equivalent": equivalent,
            "mutation_score": round(len(killed) / total, 4) if total else 1.0,
            "note": "score excludes documented equivalent mutants"}
