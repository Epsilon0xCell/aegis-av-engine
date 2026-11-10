"""ClamAV differential harness: equal knowledge, named buckets.

The BENCHMARK.md protocol allows comparison against open
baselines under identical conditions. This harness creates the
identical conditions honestly, in two modes that never mix:

Mode A (mechanics): Aegis's own fixture signatures are
converted to a ClamAV custom database (.ndb pattern signatures
plus .hsb SHA-256 hashes), so both engines hold the SAME string
knowledge. Each engine's per-string hits are then run through
Aegis's rule conditions. A disagreement is therefore a
difference in matching mechanics or in file-type gating, never
a difference in who knows more signatures. Running ClamAV's
official database against Aegis fixtures instead would measure
signature coverage and is the protocol's category error; the
harness refuses that combination by construction (Mode A only
ever loads the converted database).

Mode B (false-positive baseline): ClamAV's official database,
when present locally, against the generated clean corpus only.

Every file lands in a named bucket. agree_detect, agree_clean,
aegis_heuristic_only (Aegis fired on scorecard heuristics, which
Mode A deliberately excludes), string_mechanics_difference
(the per-string hit sets differ), condition_difference (same
hits, different rule outcome, e.g. file-type gating), and
unexplained. The release gate is unexplained == 0.
"""
from __future__ import annotations

import hashlib
import re
import shutil
import subprocess
from pathlib import Path

from . import rulelang
from .rules import RulePack


def _text_to_hex(value: str) -> str:
    return value.encode().hex().upper()


def _hexpattern_to_clam(value: str) -> str:
    out = []
    for token in value.split():
        if token.startswith("[") and token.endswith("]"):
            body = token[1:-1]
            out.append("{" + body + "}")
        else:
            out.append(token.upper())
    return "".join(out)


def build_clam_database(pack: RulePack) -> dict:
    """Convert a pack to ClamAV custom database files.

    One .ndb signature per string, named <RULE>.<string>, so
    per-string hits survive the trip. Target 0 (any file),
    offset 0. Returns {"files": {name: text}, "report": [...]}.
    """
    lines = []
    report = []
    for rule in pack.rules:
        for s in rule["strings"]:
            sig_name = f"Aegis.{rule['id']}.{s['id'].lstrip('$')}"
            if s["type"] == "text":
                hexsig = _text_to_hex(s["value"])
                kind = "text->hex"
            elif s["type"] == "hex":
                hexsig = _hexpattern_to_clam(s["value"])
                kind = "hex->clam hex (jumps {} form)"
            else:
                report.append({"rule": rule["id"], "string": s["id"],
                               "status": f"skipped: type {s['type']} "
                                         f"has no conversion"})
                continue
            lines.append(f"{sig_name};Target:0;0:0:{hexsig}")
            report.append({"rule": rule["id"], "string": s["id"],
                           "status": f"converted ({kind})"})
    # exact-hash knowledge travels as .hsb (SHA-256) entries
    hsb = [f"{digest}:0:AegisHash.{digest[:12]}"
           for digest in sorted(pack.known_bad)]
    files = {"aegis_fixtures.ndb": "\n".join(lines) + "\n"}
    if hsb:
        files["aegis_hashes.hsb"] = "\n".join(hsb) + "\n"
    return {"files": files, "report": report}


_FOUND_RE = re.compile(r"^(.*): (.+) FOUND$")
_OK_RE = re.compile(r"^(.*): OK$")


def parse_clamscan_output(text: str) -> dict[str, list[str]]:
    hits: dict[str, list[str]] = {}
    for line in text.splitlines():
        m = _FOUND_RE.match(line)
        if m:
            hits.setdefault(m.group(1), []).append(m.group(2))
            continue
        m = _OK_RE.match(line)
        if m:
            hits.setdefault(m.group(1), [])
    return hits


def _aegis_string_hits(pack: RulePack, data: bytes,
                       facts: dict) -> dict[str, set[str]]:
    hits = pack.automaton.search(data)
    out: dict[str, set[str]] = {}
    for rule in pack.rules:
        out[rule["id"]] = pack.matched_string_ids(rule, data, hits)
    return out


def _rule_fires(pack: RulePack, rule: dict, string_ids: set[str],
                facts: dict) -> bool:
    if not string_ids:
        return False
    return rulelang.evaluate_condition(rule["condition"], string_ids,
                                       facts)


def compare_file(pack: RulePack, data: bytes, facts: dict,
                 verdict: dict, clam_sigs: list[str]) -> dict:
    """Bucket one file. clam_sigs are the Aegis.* signature
    names ClamAV reported for it."""
    aegis_hits = _aegis_string_hits(pack, data, facts)
    clam_hits: dict[str, set[str]] = {}
    for sig in clam_sigs:
        parts = sig.split(".")
        if len(parts) == 3 and parts[0] == "Aegis":
            clam_hits.setdefault(parts[1], set()).add("$" + parts[2])
    rows = []
    unexplained = False
    for rule in pack.rules:
        rid = rule["id"]
        a_ids = aegis_hits.get(rid, set())
        c_ids = clam_hits.get(rid, set())
        a_fire = _rule_fires(pack, rule, a_ids, facts)
        c_fire = _rule_fires(pack, rule, c_ids, facts)
        if a_fire == c_fire:
            continue
        if a_ids != c_ids:
            rows.append({"rule": rid, "bucket":
                         "string_mechanics_difference",
                         "aegis_strings": sorted(a_ids),
                         "clam_strings": sorted(c_ids)})
        else:
            rows.append({"rule": rid, "bucket":
                         "condition_difference",
                         "detail": "identical string hits, different "
                                   "rule outcome (fact gating)"})
    aegis_detect = verdict["verdict"] != "clean"
    sig_detect = any(_rule_fires(pack, r, aegis_hits.get(r["id"], set()),
                                 facts) for r in pack.rules)
    clam_detect = any(
        _rule_fires(pack, r, clam_hits.get(r["id"], set()), facts)
        for r in pack.rules)
    if aegis_detect and not sig_detect and not clam_detect:
        bucket = "aegis_heuristic_only"
    elif aegis_detect == clam_detect and not rows:
        bucket = "agree_detect" if aegis_detect else "agree_clean"
    elif rows:
        bucket = rows[0]["bucket"]
    else:
        bucket = "unexplained"
        unexplained = True
    return {"file": verdict["file"], "bucket": bucket,
            "rule_differences": rows, "unexplained": unexplained}


def run_differential(engine, pack: RulePack, corpus_dir: Path,
                     work_dir: Path, clamscan: str | None = None) -> dict:
    """Mode A end to end. If no clamscan binary is available the
    converted database is still produced and the run reports
    its status honestly instead of fabricating a comparison."""
    from . import formats
    db = build_clam_database(pack)
    work_dir = Path(work_dir)
    work_dir.mkdir(parents=True, exist_ok=True)
    for name, text in db["files"].items():
        (work_dir / name).write_text(text)
    binary = clamscan or shutil.which("clamscan")
    if not binary:
        return {"status": "clamscan_unavailable",
                "database": db,
                "note": "converted database generated and verified "
                        "in tests with a stub binary; no comparison "
                        "is claimed without a real clamscan"}
    proc = subprocess.run(
        [binary, "-r", "--no-summary",
         *[f"--database={work_dir / name}" for name in db["files"]],
         str(corpus_dir)],
        capture_output=True, text=True, timeout=600)
    clam = parse_clamscan_output(proc.stdout)
    buckets: dict[str, int] = {}
    details = []
    unexplained = 0
    for path in sorted(Path(corpus_dir).rglob("*")):
        if not path.is_file():
            continue
        data = path.read_bytes()
        verdict = engine.scan_bytes(data, path.name)
        facts = {"format": formats.identify(data),
                 "entropy": formats.shannon_entropy(data),
                 "size": len(data)}
        key = str(path)
        row = compare_file(pack, data, facts, verdict,
                           clam.get(key, []))
        buckets[row["bucket"]] = buckets.get(row["bucket"], 0) + 1
        if row["bucket"] not in ("agree_detect", "agree_clean"):
            details.append(row)
        unexplained += 1 if row["unexplained"] else 0
    return {"status": "completed", "buckets": buckets,
            "details": details, "unexplained": unexplained,
            "database": db}
