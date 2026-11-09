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

from . import containers, formats, formats_elf, formats_macho, formats_pe
from . import (authenticode, formats_cfb, formats_dotnet, formats_pdf,
               ovba, similarity, tlsh)
from . import segmented as segmented_mod
from . import views as views_mod
from .hashing import BloomFilter, digests, fuzzy_digest, fuzzy_similarity
from .rules import MALICIOUS_AT, SUSPICIOUS_AT, RulePack, heuristic_score

VERDICT_CLEAN = "clean"
VERDICT_SUSPICIOUS = "suspicious"
VERDICT_MALICIOUS = "malicious_pattern"


class Engine:
    def __init__(self, pack: RulePack, cache=None, profile: bool = False) -> None:
        self.pack = pack
        self.persistent_cache = cache
        self.bloom = BloomFilter()
        for h in pack.known_bad:
            self.bloom.add(h)
        self.cache: dict[str, dict] = {}
        self.fuzzy_refs: dict[str, str] = {}  # name -> fuzzy digest of fixtures
        self.profile = profile

    def register_fuzzy_reference(self, name: str, data: bytes) -> None:
        self.fuzzy_refs[name] = fuzzy_digest(data)

    def scan_bytes(self, data: bytes, name: str = "<memory>") -> dict:
        started = time.perf_counter()
        marks: list[tuple[str, float]] = [("start", started)]

        def mark(stage: str) -> None:
            if self.profile:
                marks.append((stage, time.perf_counter()))

        hashes = digests(data)
        sha = hashes["sha256"]
        if sha in self.cache:
            verdict = dict(self.cache[sha])
            verdict["from_cache"] = True
            return verdict
        if self.persistent_cache is not None:
            stored = self.persistent_cache.get(sha)
            if stored is not None:
                self.cache[sha] = stored
                return dict(stored)
        mark("digests")
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
        matched = self.pack.match(data, {"format": fmt, "entropy": entropy,
                                         "size": len(data)})
        for m in matched:
            score += m["weight"]
            evidence.append({"type": "rule_match", **m})
        h_score, h_evidence = heuristic_score(fmt, entropy, len(data), pe)
        mark("rules_and_scorecard")
        score += h_score
        evidence.extend({"type": "heuristic", **e} for e in h_evidence)
        analysis: dict = {}
        if fmt == "pe":
            analysis = formats_pe.parse_pe(data)
        elif fmt == "elf":
            analysis = formats_elf.parse_elf(data)
        elif fmt.startswith("macho"):
            analysis = formats_macho.parse_macho(data)
        for finding in analysis.get("findings", []):
            evidence.append({"type": "format_finding", **finding})
        mark("format_parse")
        if fmt == "pdf":
            pdf_analysis = formats_pdf.parse_pdf(data)
            analysis = pdf_analysis
            kw = pdf_analysis.get("keywords", {})
            kinds = [a["kind"] for a in pdf_analysis.get("actions", [])]
            if kw.get("OpenAction") and "JavaScript" in kinds:
                score += 30
                evidence.append({"type": "heuristic",
                                 "heuristic": "pdf_openaction_javascript",
                                 "points": 30,
                                 "detail": "document runs JavaScript at "
                                           "open time"})
            if "Launch" in kinds:
                score += 20
                evidence.append({"type": "heuristic",
                                 "heuristic": "pdf_launch_action",
                                 "points": 20,
                                 "detail": "document carries a Launch "
                                           "action (external program)"})
            if kw.get("EmbeddedFiles") or kw.get("EmbeddedFile"):
                score += 10
                evidence.append({"type": "heuristic",
                                 "heuristic": "pdf_embedded_files",
                                 "points": 10,
                                 "detail": "document embeds files"})
        cfb_result = None
        if fmt == "cfb":
            cfb_result = formats_cfb.parse_cfb(data)
            for finding in cfb_result.get("findings", []):
                evidence.append({"type": "format_finding", **finding})
            vba = ovba.analyze_vba(cfb_result)
            cfb_result["vba"] = {k: v for k, v in vba.items()
                                 if k != "module_sources"}
            for finding in vba.get("findings", []):
                evidence.append({"type": "format_finding", **finding})
            for mod_name, source in vba.get("module_sources", {}).items():
                for m in self.pack.match(
                        source, {"format": "vba_source",
                                 "entropy": formats.shannon_entropy(source),
                                 "size": len(source)}):
                    score += m["weight"]
                    evidence.append({"type": "vba_rule_match",
                                     "module": mod_name, **m})
        auth_result = None
        dotnet_result = None
        if fmt == "pe" and (analysis.get("directories") or {}).get("clr"):
            dotnet_result = formats_dotnet.parse_dotnet(data, analysis)
            for finding in dotnet_result.get("findings", []):
                evidence.append({"type": "format_finding", **finding})
            joined = "\n".join(
                dotnet_result.get("user_strings", [])).encode(
                    "utf-8", "replace")
            if joined:
                for m in self.pack.match(
                        joined, {"format": "dotnet_user_strings",
                                 "entropy": formats.shannon_entropy(joined),
                                 "size": len(joined)}):
                    score += m["weight"]
                    evidence.append({"type": "dotnet_user_string_match",
                                     **m})
        if fmt == "pe":
            auth_result = authenticode.verify_authenticode(data)
            if auth_result.get("status") == "mismatch":
                score += 40
                evidence.append({"type": "authenticode_mismatch",
                                 "points": 40,
                                 "detail": auth_result.get("meaning", "")})
        if analysis.get("overlay_bytes"):
            score += 10
            evidence.append({"type": "heuristic", "heuristic": "overlay_data",
                             "points": 10,
                             "detail": f"{analysis['overlay_bytes']} bytes past the last section"})
        container_result = None
        if fmt == "zip_container" or data[:2] == b"\x1f\x8b":
            container_result = containers.scan_container(data, self.scan_bytes)
            for f in container_result.findings:
                evidence.append({"type": "container_finding", **f})
            member_scores = [m.verdict["score"] for m in container_result.members
                             if m.verdict is not None]
            if member_scores:
                score = max(score, max(member_scores))
            if any(f.get("type") == "ooxml_remote_template"
                   for f in container_result.findings):
                score += 25
                evidence.append({"type": "heuristic",
                                 "heuristic": "ooxml_remote_template",
                                 "points": 25,
                                 "detail": "document fetches a remote template "
                                           "at open time (T1221)"})
        mark("containers")
        split = views_mod.split_views(data, fmt, analysis)
        seg = segmented_mod.segmented_stats(split["loaded"])
        if entropy < 6.5 and seg["max"] >= 7.2:
            score += 45
            evidence.append({"type": "heuristic", "heuristic": "entropy_dilution",
                             "points": 45,
                             "detail": f"global entropy {entropy:.2f} hides a loaded "
                                       f"window at {seg['max']:.2f}: padding dilution"})
        elif entropy < 7.2 and seg["max"] >= 7.8:
            score += 15
            evidence.append({"type": "heuristic", "heuristic": "segmented_entropy_peak",
                             "points": 15,
                             "detail": f"hottest loaded window {seg['max']:.2f} vs "
                                       f"global {entropy:.2f}"})
        mark("views_segmented")
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
            "format_analysis": analysis,
            "container": ({"kind": container_result.kind,
                           "members": [{"name": m.name,
                                        "verdict": m.verdict["verdict"] if m.verdict else None,
                                        "note": m.note} for m in container_result.members],
                           "findings": container_result.findings}
                          if container_result is not None else None),
            "segmented_entropy": seg,
            "views": {"loaded_fraction": split["loaded_fraction"],
                      "residual_bytes": len(split["residual"])},
            "scan_seconds": round(time.perf_counter() - started, 6),
            "from_cache": False,
        }
        mark("similarity")
        verdict["tlsh"] = tlsh.tlsh_digest(data)
        if self.profile:
            marks.append(("tlsh_and_assembly", time.perf_counter()))
            verdict["profile_ms"] = {
                marks[i + 1][0]: round((marks[i + 1][1] - marks[i][1]) * 1000, 4)
                for i in range(len(marks) - 1)}
        verdict["authenticode"] = auth_result
        verdict["dotnet"] = dotnet_result
        verdict["cfb"] = ({k: v for k, v in cfb_result.items()
                           if k != "streams"}
                          if cfb_result is not None else None)
        if fmt == "pe" and analysis:
            verdict["section_hashes"] = similarity.section_hashes(data, analysis)
            verdict["imphash"] = similarity.imphash(analysis)
        self.cache[sha] = verdict
        if self.persistent_cache is not None:
            self.persistent_cache.put(sha, verdict)
        return verdict

    def scan_file(self, path: Path) -> dict:
        return self.scan_bytes(path.read_bytes(), name=str(path))

    def scan_stream(self, path: Path, chunk_size: int = 65536) -> dict:
        """Streaming scan for files too large to hold comfortably:
        incremental hashes, incremental Aho-Corasick (state is one
        integer carried across chunks), and streaming windowed
        entropy. Text-pattern rules and the dilution heuristic are
        evaluated; hex-pattern rules and deep parsing are not, and
        the verdict says so plainly. Verdicts on ordinary files are
        equivalence-tested against the in-memory path."""
        import hashlib as _hl

        from . import segmented as _seg
        sha, md5 = _hl.sha256(), _hl.md5()
        tracker = _seg.WindowEntropyTracker()
        state = 0
        hits: dict[str, int] = {}
        size = 0
        head = b""
        with path.open("rb") as fh:
            while True:
                chunk = fh.read(chunk_size)
                if not chunk:
                    break
                if not head:
                    head = chunk[:512]
                size += len(chunk)
                sha.update(chunk)
                md5.update(chunk)
                tracker.feed(chunk)
                delta, state = self.pack.automaton.feed(state, chunk)
                for tag, n in delta.items():
                    hits[tag] = hits.get(tag, 0) + n
        fmt = formats.identify(head)
        seg = tracker.finish()
        evidence: list[dict] = [{"type": "stream_note",
                                 "detail": "streaming mode: hex-pattern rules "
                                           "and deep parsing not evaluated"}]
        score = 0
        for rule in self.pack.rules:
            ids = self.pack.matched_string_ids(rule, b"", hits) \
                if all(s["type"] == "text" for s in rule["strings"]) else set()
            from .rulelang import evaluate_condition
            if ids and evaluate_condition(rule["condition"], ids,
                                          {"format": fmt, "entropy": seg["max"],
                                           "size": size}):
                score += rule["weight"]
                evidence.append({"type": "rule_match", "rule_id": rule["id"],
                                 "name": rule["name"], "attck": rule["attck"],
                                 "weight": rule["weight"],
                                 "patterns_matched": len(ids),
                                 "strings_matched": sorted(ids),
                                 "description": rule["description"]})
        if seg["mean"] < 6.5 and seg["max"] >= 7.2:
            score += 45
            evidence.append({"type": "heuristic", "heuristic": "entropy_dilution",
                             "points": 45,
                             "detail": "streamed window maximum contradicts "
                                       "the diluted mean"})
        label = (VERDICT_MALICIOUS if score >= MALICIOUS_AT
                 else VERDICT_SUSPICIOUS if score >= SUSPICIOUS_AT
                 else VERDICT_CLEAN)
        return {"file": str(path), "verdict": label, "score": score,
                "mode": "streaming", "format": fmt, "size": size,
                "hashes": {"sha256": sha.hexdigest(), "md5": md5.hexdigest()},
                "segmented_entropy": seg, "evidence": evidence,
                "rule_pack": f"{self.pack.name}@{self.pack.version}"}

    def scan_tree(self, root: Path) -> list[dict]:
        return [self.scan_file(p) for p in sorted(root.rglob("*")) if p.is_file()]
