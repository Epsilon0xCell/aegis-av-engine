"""Rule loading and the transparent heuristic scorecard.

Every score the scorecard adds is a named, weighted, inspectable
contribution. There is no opaque model in the default path: an
employer, an auditor, or a user can read exactly why a file scored
what it scored, which is one of the axes this project competes on.
"""
from __future__ import annotations

import json
from pathlib import Path

from .strings_engine import AhoCorasick

SUSPICIOUS_AT = 40
MALICIOUS_AT = 70


class RulePack:
    def __init__(self, path: Path) -> None:
        doc = json.loads(path.read_text())
        self.name = doc["pack"]
        self.version = doc["version"]
        self.known_bad = set(doc.get("known_bad_hashes_sha256", []))
        self.rules = doc["rules"]
        self.automaton = AhoCorasick()
        for rule in self.rules:
            for pat in rule["patterns"]:
                self.automaton.add(pat.encode(), rule["id"])
        self.automaton.build()

    def match(self, data: bytes) -> list[dict]:
        # The automaton establishes which rules hit in one pass; the
        # per-rule distinct-pattern count below is bookkeeping for
        # the min_patterns threshold and the evidence record.
        hits = self.automaton.search(data)
        matched = []
        for rule in self.rules:
            if hits.get(rule["id"], 0) == 0:
                continue
            distinct = sum(1 for p in rule["patterns"] if p.encode() in data)
            if distinct >= rule["min_patterns"]:
                matched.append({"rule_id": rule["id"], "name": rule["name"],
                                "attck": rule["attck"], "weight": rule["weight"],
                                "patterns_matched": distinct,
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
