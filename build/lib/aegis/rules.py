"""Rule loading and the transparent heuristic scorecard.

Every score the scorecard adds is a named, weighted, inspectable
contribution. There is no opaque model in the default path: an
employer, an auditor, or a user can read exactly why a file scored
what it scored, which is one of the axes this project competes on.
"""
from __future__ import annotations

import json
from pathlib import Path

from .rulelang import HexPattern, evaluate_condition
from .strings_engine import AhoCorasick

SUSPICIOUS_AT = 40
MALICIOUS_AT = 70


class RulePack:
    """Loads format-1 packs (patterns + min_patterns) and format-2
    packs (typed strings + condition ASTs) into one runtime shape."""

    def __init__(self, path: Path) -> None:
        doc = json.loads(path.read_text())
        self.name = doc["pack"]
        self.version = doc["version"]
        self.format = doc.get("format", 1)
        self.known_bad = set(doc.get("known_bad_hashes_sha256", []))
        self.rules: list[dict] = []
        self.automaton = AhoCorasick()
        self.hex_patterns: dict[str, HexPattern] = {}
        for rule in doc["rules"]:
            self._load_rule(rule)
        self.automaton.build()

    def _load_rule(self, rule: dict) -> None:
        strings = rule.get("strings")
        if strings is None:  # format 1: convert patterns + min_patterns
            strings = [{"id": f"$s{i}", "type": "text", "value": p}
                       for i, p in enumerate(rule["patterns"])]
            condition = {"count_at_least": {
                "of": [s["id"] for s in strings],
                "n": rule.get("min_patterns", 1)}}
        else:
            condition = rule["condition"]
        compiled = {"id": rule["id"], "name": rule["name"],
                    "attck": rule.get("attck", []), "weight": rule["weight"],
                    "description": rule.get("description", ""),
                    "strings": strings, "condition": condition}
        for s in strings:
            if s["type"] == "text":
                self.automaton.add(s["value"].encode(),
                                   f"{rule['id']}|{s['id']}")
            elif s["type"] == "hex":
                self.hex_patterns[f"{rule['id']}|{s['id']}"] = HexPattern(s["value"])
            else:
                raise ValueError(f"unknown string type {s['type']}")
        self.rules.append(compiled)

    def matched_string_ids(self, rule: dict, data: bytes,
                           hits: dict[str, int]) -> set[str]:
        matched: set[str] = set()
        for s in rule["strings"]:
            key = f"{rule['id']}|{s['id']}"
            if s["type"] == "text":
                if hits.get(key, 0):
                    matched.add(s["id"])
            elif self.hex_patterns[key].search(data):
                matched.add(s["id"])
        return matched

    def match(self, data: bytes, facts: dict | None = None) -> list[dict]:
        facts = facts or {}
        hits = self.automaton.search(data)
        matched = []
        for rule in self.rules:
            ids = self.matched_string_ids(rule, data, hits)
            if ids and evaluate_condition(rule["condition"], ids, facts):
                matched.append({"rule_id": rule["id"], "name": rule["name"],
                                "attck": rule["attck"], "weight": rule["weight"],
                                "patterns_matched": len(ids),
                                "strings_matched": sorted(ids),
                                "description": rule["description"]})
        return matched


def heuristic_score(fmt: str, entropy: float, size: int,
                    pe: dict) -> tuple[int, list[dict]]:
    """Named, weighted heuristic contributions. Returns (score, evidence)."""
    score = 0
    evidence: list[dict] = []

    def add(points: int, name: str, detail: str) -> None:
        nonlocal score
        score += points
        evidence.append({"heuristic": name, "points": points, "detail": detail})

    if fmt in ("pe", "elf", "macho32", "macho64", "macho_fat", "script",
              "script_shebang") and entropy > 7.2:
        add(25, "high_entropy_executable",
            f"entropy {entropy} in a {fmt} file suggests packing or encryption of code")
    if fmt == "text" and entropy > 7.6:
        add(10, "high_entropy_text", f"entropy {entropy} is unusual for text")
    if pe.get("pe_parse") == "ok" and pe.get("pe_sections", 0) >= 8:
        add(15, "many_sections", f"{pe['pe_sections']} PE sections is above the common range")
    if pe.get("pe_timestamp") == 0 and pe.get("pe_parse") == "ok":
        add(5, "zero_timestamp", "PE timestamp is zeroed, a weak tamper indicator")
    if size == 0:
        add(5, "empty_file", "zero-byte file")
    return score, evidence
