"""The layered pipeline, early exit first, explanation always.

Stages: ingest and identify, bloom pre-filtered exact hash lookup,
Aho-Corasick rule matching, static features and the transparent
scorecard, fuzzy-digest near matching against fixture references,
and the verdict object. Every verdict carries its evidence: file
identity, hashes, matched rules, heuristic contributions, fuzzy
matches, and the stage that decided it. Deterministic: the same
bytes and the same rule pack always produce the same verdict.
"""
from __future__ import annotations

import time
from pathlib import Path

from . import formats
from .hashing import BloomFilter, digests, fuzzy_digest, fuzzy_similarity
from .rules import MALICIOUS_AT, SUSPICIOUS_AT, RulePack, heuristic_score

VERDICT_CLEAN = "clean"
VERDICT_SUSPICIOUS = "suspicious"
VERDICT_MALICIOUS = "malicious_pattern"


class Engine:
    def __init__(self, pack: RulePack) -> None:
        self.pack = pack
        self.bloom = BloomFilter()
        for h in pack.known_bad:
            self.bloom.add(h)
        self.cache: dict[str, dict] = {}
        self.fuzzy_refs: dict[str, str] = {}  # name -> fuzzy digest of fixtures

    def register_fuzzy_reference(self, name: str, data: bytes) -> None:
        self.fuzzy_refs[name] = fuzzy_digest(data)

    def scan_bytes(self, data: bytes, name: str = "<memory>") -> dict:
        started = time.perf_counter()
        hashes = digests(data)
        sha = hashes["sha256"]
        if sha in self.cache:
            verdict = dict(self.cache[sha])
            verdict["from_cache"] = True
            return verdict
        fmt = formats.identify(data)
        entropy = formats.shannon_entropy(data)
        pe = formats.pe_features(data)
        evidence: list[dict] = []
        score = 0
        stage = "heuristic_scorecard"
        if sha in self.bloom and sha in self.pack.known_bad:
            score = 100
            stage = "exact_hash"
            evidence.append({"type": "exact_hash", "detail": "sha256 in known-bad set"})
        matched = self.pack.match(data)
        for m in matched:
            score += m["weight"]
            evidence.append({"type": "rule_match", **m})
        h_score, h_evidence = heuristic_score(fmt, entropy, len(data), pe)
        score += h_score
        evidence.extend({"type": "heuristic", **e} for e in h_evidence)
        fuzzy_matches = []
        fd = fuzzy_digest(data)
        for ref_name, ref_digest in self.fuzzy_refs.items():
            sim = fuzzy_similarity(fd, ref_digest)
            if sim >= 0.6:
                fuzzy_matches.append({"reference": ref_name, "similarity": sim})
        if fuzzy_matches:
            evidence.append({"type": "fuzzy_match", "matches": fuzzy_matches})
            score = max(score, 45)
        if score >= MALICIOUS_AT:
            label = VERDICT_MALICIOUS
        elif score >= SUSPICIOUS_AT:
            label = VERDICT_SUSPICIOUS
        else:
            label = VERDICT_CLEAN
        verdict = {
            "file": name, "verdict": label, "score": score,
            "decided_at_stage": stage, "format": fmt, "size": len(data),
            "entropy": entropy, "hashes": hashes, "fuzzy_digest": fd,
            "evidence": evidence, "rule_pack": f"{self.pack.name}@{self.pack.version}",
            "scan_seconds": round(time.perf_counter() - started, 6),
            "from_cache": False,
        }
        self.cache[sha] = verdict
        return verdict

    def scan_file(self, path: Path) -> dict:
        return self.scan_bytes(path.read_bytes(), name=str(path))

    def scan_tree(self, root: Path) -> list[dict]:
        return [self.scan_file(p) for p in sorted(root.rglob("*")) if p.is_file()]
