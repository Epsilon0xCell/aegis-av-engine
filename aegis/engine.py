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
from . import (authenticode, formats_cfb, formats_dotnet, formats_eml,
               formats_evtx, formats_iso, formats_jar, formats_lnk,
               formats_pdf, formats_rtf, ovba, script_lab, similarity,
               tlsh)
from . import segmented as segmented_mod
from . import views as views_mod
from .hashing import BloomFilter, digests, fuzzy_digest, fuzzy_similarity
from .rules import MALICIOUS_AT, SUSPICIOUS_AT, RulePack, heuristic_score

VERDICT_CLEAN = "clean"
VERDICT_SUSPICIOUS = "suspicious"
VERDICT_MALICIOUS = "malicious_pattern"


class Engine:
    def __init__(self, pack: RulePack, cache=None, profile: bool = False,
                 always_tlsh: bool = False) -> None:
        self.always_tlsh = always_tlsh
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

    def tlsh_of(self, data: bytes):
        """The TLSH digest on demand (see the lazy policy in
        scan_bytes)."""
        return tlsh.tlsh_digest(data)

    def scan_bytes(self, data: bytes, name: str = "<memory>",
                   _depth: int = 0) -> dict:
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
        delivery_result = None
        if fmt == "lnk":
            delivery_result = formats_lnk.parse_lnk(data)
            for finding in delivery_result["findings"]:
                evidence.append({"type": "format_finding", **finding})
            if delivery_result.get("arguments"):
                sub = script_lab.analyze_script(
                    delivery_result["arguments"].encode())
                for depth2, kind, blob in sub["layer_data"]:
                    if depth2 == 0:
                        continue
                    for m in self.pack.match(
                            blob, {"format": "script_layer",
                                   "entropy": formats.shannon_entropy(blob),
                                   "size": len(blob)}):
                        score += m["weight"]
                        evidence.append(
                            {"type": "script_layer_match",
                             "layer": f"lnk_arguments:{kind}",
                             "depth": depth2, **m})
                if sub["decoded_only_signals"] and sub["layers"]:
                    score += 20
                    evidence.append(
                        {"type": "heuristic",
                         "heuristic": "lnk_obfuscated_arguments",
                         "points": 20,
                         "detail": "shortcut arguments hide high-risk "
                                   "APIs behind encoding"})
            if any(f["type"] == "lnk_script_host"
                   for f in delivery_result["findings"]):
                score += 15
                evidence.append({"type": "heuristic",
                                 "heuristic": "lnk_script_host",
                                 "points": 15,
                                 "detail": "shortcut launches a script "
                                           "host"})
        elif fmt == "rtf":
            delivery_result = formats_rtf.parse_rtf(data)
            for finding in delivery_result["findings"]:
                evidence.append({"type": "format_finding", **finding})
            if _depth < 2:
                for blob in delivery_result["embedded"]:
                    sub = self.scan_bytes(blob, name + "!objdata",
                                          _depth + 1)
                    evidence.append(
                        {"type": "rtf_embedded_verdict",
                         "verdict": sub["verdict"],
                         "score": sub["score"]})
                    score = max(score, sub["score"])
        elif fmt == "eml":
            delivery_result = formats_eml.parse_eml(data)
            for finding in delivery_result["findings"]:
                evidence.append({"type": "format_finding", **finding})
            if _depth < 2:
                for att in delivery_result["attachments"]:
                    if att.get("data"):
                        sub = self.scan_bytes(
                            att["data"], name + "!" + att["filename"],
                            _depth + 1)
                        evidence.append(
                            {"type": "eml_attachment_verdict",
                             "filename": att["filename"],
                             "verdict": sub["verdict"],
                             "score": sub["score"]})
                        score = max(score, sub["score"])
        elif fmt == "iso":
            delivery_result = formats_iso.parse_iso(data)
            for finding in delivery_result["findings"]:
                evidence.append({"type": "format_finding", **finding})
            best = 0
            for member_name, blob in delivery_result["members"].items():
                member_facts = {"format": formats.identify(blob),
                                "entropy": formats.shannon_entropy(blob),
                                "size": len(blob)}
                for m in self.pack.match(blob, member_facts):
                    best = max(best, m["weight"])
                    evidence.append({"type": "iso_member_match",
                                     "member": member_name, **m})
                if member_name.lower().endswith(".lnk"):
                    lnk = formats_lnk.parse_lnk(blob)
                    for finding in lnk["findings"]:
                        evidence.append(
                            {"type": "format_finding",
                             "member": member_name, **finding})
                    if any(f["type"] == "lnk_script_host"
                           for f in lnk["findings"]):
                        best = max(best, 15)
            score = max(score, best)
        script_result = None
        if fmt in ("text", "script", "unknown") and len(data) <= 1024 * 1024:
            script_result = script_lab.analyze_script(data)
            for finding in script_result["findings"]:
                evidence.append({"type": "format_finding", **finding})
            for depth, kind, blob in script_result["layer_data"]:
                if depth == 0:
                    continue
                for m in self.pack.match(
                        blob, {"format": "script_layer",
                               "entropy": formats.shannon_entropy(blob),
                               "size": len(blob)}):
                    score += m["weight"]
                    evidence.append({"type": "script_layer_match",
                                     "layer": kind, "depth": depth, **m})
            if script_result["decoded_only_signals"] \
                    and script_result["layers"]:
                score += 20
                evidence.append(
                    {"type": "heuristic",
                     "heuristic": "script_obfuscated_high_risk",
                     "points": 20,
                     "detail": "high-risk APIs appear only after "
                               "decoding: "
                               + ", ".join(
                                   script_result["decoded_only_signals"])})
        evtx_result = None
        jar_result = None
        if fmt == "evtx":
            evtx_result = formats_evtx.parse_evtx(data)
            for finding in evtx_result["findings"]:
                evidence.append({"type": "format_finding", **finding})
            if any(f["type"].endswith("checksum_mismatch")
                   or f["type"].endswith("crc_mismatch")
                   for f in evtx_result["findings"]):
                score += 25
                evidence.append(
                    {"type": "heuristic",
                     "heuristic": "evtx_tamper_evidence",
                     "points": 25,
                     "detail": "event log checksums do not recompute; "
                               "the file was modified after writing"})
        if fmt in ("zip", "zip_container"):
            jar_result = formats_jar.analyze_archive(data)
            for finding in jar_result["findings"]:
                evidence.append({"type": "format_finding", **finding})
            mismatches = sum(
                1 for f in jar_result["findings"]
                if f["type"] == "jar_entry_digest_mismatch")
            if mismatches:
                score += 30
                evidence.append(
                    {"type": "heuristic",
                     "heuristic": "jar_digest_mismatch",
                     "points": 30,
                     "detail": f"{mismatches} archive entries no "
                               f"longer match their signed digests"})
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
        # Lazy TLSH (v3 performance pass): profiling showed the
        # digest costs about 2.3 ms per file, over half the scan,
        # and nothing in scoring consumes it. It is computed when
        # the verdict is at least suspicious, or on demand via
        # Engine.tlsh_of. Skipping is recorded, never silent.
        if score >= SUSPICIOUS_AT or self.always_tlsh:
            verdict["tlsh"] = tlsh.tlsh_digest(data)
        else:
            verdict["tlsh"] = None
            verdict["tlsh_skipped"] = (
                "clean verdict; digest available via Engine.tlsh_of")
        if self.profile:
            marks.append(("tlsh_and_assembly", time.perf_counter()))
            verdict["profile_ms"] = {
                marks[i + 1][0]: round((marks[i + 1][1] - marks[i][1]) * 1000, 4)
                for i in range(len(marks) - 1)}
        verdict["authenticode"] = auth_result
        verdict["dotnet"] = dotnet_result
        if evtx_result is not None:
            verdict["evtx"] = {
                k: v for k, v in evtx_result.items() if k != "findings"}
        if jar_result is not None and jar_result["findings"]:
            verdict["archive_signing"] = {
                k: v for k, v in jar_result.items() if k != "findings"}
        if delivery_result is not None:
            summary = {k: v for k, v in delivery_result.items()
                       if k not in ("embedded", "members", "attachments")}
            if "attachments" in delivery_result:
                summary["attachments"] = [
                    {kk: vv for kk, vv in a.items() if kk != "data"}
                    for a in delivery_result["attachments"]]
            if "members" in delivery_result:
                summary["members"] = sorted(delivery_result["members"])
            verdict["delivery"] = summary
        if script_result is not None:
            verdict["script"] = {
                k: script_result[k]
                for k in ("layers", "raw_signals",
                          "decoded_only_signals",
                          "unresolved_constructs")}
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
        verdict = self.scan_bytes(path.read_bytes(), name=str(path))
        from .provenance import read_provenance
        prov = read_provenance(path)
        if prov["present"]:
            # copy before attaching: scan_bytes may return the
            # shared cached verdict object, and provenance is a
            # property of this path, not of the content
            verdict = {**verdict, "provenance": prov}
        return verdict

    def scan_file_mmap(self, path: Path) -> dict:
        """scan_file over a read-only memory map, with the two
        cases the v5 research named specified rather than
        discovered later: an empty file cannot be mapped and is
        scanned as empty bytes, and a file whose size or mtime
        changes while mapped is reported as changed during scan
        and rescanned from a plain read, with the verdict
        saying which bytes it describes."""
        import mmap as _mmap
        import os as _os
        try:
            before = path.stat()
        except OSError:
            return self.scan_bytes(b"", name=str(path))
        if before.st_size == 0:
            return self.scan_file(path)
        with path.open("rb") as fh:
            with _mmap.mmap(fh.fileno(), 0,
                            access=_mmap.ACCESS_READ) as mm:
                data = mm[:]
        verdict = self.scan_bytes(data, name=str(path))
        try:
            after = path.stat()
            changed = (after.st_size != before.st_size
                       or after.st_mtime != before.st_mtime)
        except OSError:
            changed = True
        if changed:
            verdict = self.scan_file(path)
            verdict["file_changed_during_scan"] = True
            verdict["scan_method"] = "read (mmap attempt superseded)"
        else:
            verdict["scan_method"] = "mmap"
        return verdict

    def scan_stream(self, path: Path, chunk_size: int = 65536) -> dict:
        """Streaming scan for files too large to hold comfortably:
        incremental hashes, incremental Aho-Corasick (state is one
        integer carried across chunks), streaming windowed
        entropy, and hex-pattern rules evaluated exactly through
        a carry window bounded by each pattern's maximum span
        (jumps are capped, so spans are finite). Deep format
        parsing and container inspection are not performed, and
        the verdict says so plainly. Verdicts on ordinary files
        are equivalence-tested against the in-memory path."""
        import hashlib as _hl

        from . import segmented as _seg
        sha, md5 = _hl.sha256(), _hl.md5()
        tracker = _seg.WindowEntropyTracker()
        state = 0
        hits: dict[str, int] = {}
        size = 0
        head = b""
        hex_carry: dict[str, bytes] = {}
        hex_matched: set[str] = set()
        hex_skipped: list[str] = []
        for key, pattern in self.pack.hex_patterns.items():
            if pattern.max_span > 65536:
                hex_skipped.append(key)
            else:
                hex_carry[key] = b""
        with path.open("rb") as fh:
            while True:
                chunk = fh.read(chunk_size)
                if not chunk:
                    break
                if len(head) < 512:
                    head = (head + chunk)[:512]
                size += len(chunk)
                sha.update(chunk)
                md5.update(chunk)
                tracker.feed(chunk)
                delta, state = self.pack.automaton.feed(state, chunk)
                for tag, n in delta.items():
                    hits[tag] = hits.get(tag, 0) + n
                for key, pattern in self.pack.hex_patterns.items():
                    if key in hex_matched or key in hex_skipped:
                        continue
                    window = hex_carry[key] + chunk
                    if pattern.search(window):
                        hex_matched.add(key)
                    span = pattern.max_span
                    hex_carry[key] = window[-(span - 1):] if span > 1 \
                        else b""
        fmt = formats.identify(head)
        seg = tracker.finish()
        evidence: list[dict] = [{"type": "stream_note",
                                 "detail": "streaming mode: text and hex "
                                           "rules evaluated exactly (hex "
                                           "via bounded carry window); "
                                           "deep format parsing and "
                                           "container inspection are not "
                                           "performed"}]
        if hex_skipped:
            evidence.append({"type": "stream_hex_skipped",
                             "patterns": hex_skipped,
                             "detail": "pattern span above the 64KiB "
                                       "carry cap"})
        score = 0
        for rule in self.pack.rules:
            ids = set()
            for s in rule["strings"]:
                key = f"{rule['id']}|{s['id']}"
                if s["type"] == "text" and hits.get(key, 0):
                    ids.add(s["id"])
                elif s["type"] == "hex" and key in hex_matched:
                    ids.add(s["id"])
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
