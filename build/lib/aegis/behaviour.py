"""Behavioural telemetry correlator (ATT&CK chains over JSONL events).

Consumes the same style of structured telemetry as the companion
labs and convicts on CHAINS, not single events: single events have
legitimate explanations; the chain is the signal. Each chain maps
to ATT&CK and carries its evidence event indexes.
"""
from __future__ import annotations

import json
from pathlib import Path

CHAINS = [
    {"id": "CHAIN-RANSOMWARE-PRECURSOR", "attck": ["T1490", "T1486"],
     "needs": ["process_create", "file_encrypt"],
     "cmdline_must_contain": "delete shadows",
     "description": "Recovery inhibition followed by encryption activity.",
     "steps": [{"event_type": "process_create", "technique": "T1490",
                "weight": 3},
               {"event_type": "file_encrypt", "technique": "T1486",
                "weight": 2}]},
    {"id": "CHAIN-KEYLOG-BEHAVIOUR", "attck": ["T1056.001", "T1071.001"],
     "needs": ["hook_install_fixture", "log_append", "beacon"],
     "cmdline_must_contain": None,
     "description": "Hook pattern plus periodic appends plus a size beacon.",
     "steps": [{"event_type": "hook_install_fixture", "technique": "T1056.001",
                "weight": 2},
               {"event_type": "log_append", "technique": "T1056.001",
                "weight": 1},
               {"event_type": "beacon", "technique": "T1071.001",
                "weight": 2}]},
    {"id": "CHAIN-C2-ENCRYPT", "attck": ["T1071.001", "T1486"],
     "needs": ["beacon", "file_encrypt"],
     "cmdline_must_contain": None,
     "description": "Beaconing combined with encryption activity from one host log.",
     "steps": [{"event_type": "beacon", "technique": "T1071.001",
                "weight": 2},
               {"event_type": "file_encrypt", "technique": "T1486",
                "weight": 3}]},
]


def analyse(events: list[dict]) -> list[dict]:
    """Partial-credit chain analysis (v2).

    correlate() answers a binary question for coverage counting:
    did the whole chain fire? This answers the analyst's
    question: how much of each chain is present, in order? Steps
    are matched as an ordered subsequence, each event consumed at
    most once per chain, and credit is the matched weight over
    the total weight. A chain at partial credit is a lead, not a
    detection, and the output says which status each chain is in:
    fired (full credit and its extra conditions hold), partial
    (at least half), or absent. Only fired chains may be counted
    as ATT&CK coverage anywhere downstream.
    """
    results = []
    for chain in CHAINS:
        steps = chain.get("steps", [])
        total = sum(s["weight"] for s in steps) or 1
        matched = []
        used: set[int] = set()
        cursor = 0
        for step in steps:
            hit = None
            for i in range(cursor, len(events)):
                if i in used:
                    continue
                if events[i].get("event_type") == step["event_type"]:
                    hit = i
                    break
            if hit is not None:
                matched.append({"event_type": step["event_type"],
                                "technique": step["technique"],
                                "weight": step["weight"],
                                "event_index": hit})
                used.add(hit)
                cursor = hit + 1
        credit = round(sum(m["weight"] for m in matched) / total, 4)
        cmdline_ok = True
        if chain.get("cmdline_must_contain"):
            cmdline_ok = any(
                chain["cmdline_must_contain"] in
                str(e.get("details", {}).get("command_line", "")).lower()
                for e in events)
        if credit >= 1.0 and cmdline_ok:
            status = "fired"
        elif credit >= 0.5:
            status = "partial"
        else:
            status = "absent"
        matched_types = {m["event_type"] for m in matched}
        results.append({
            "chain_id": chain["id"], "attck": chain["attck"],
            "description": chain["description"], "status": status,
            "credit": credit, "matched_steps": matched,
            "missing_steps": [s["event_type"] for s in steps
                              if s["event_type"] not in matched_types],
            "cmdline_condition": cmdline_ok})
    return results


def load_events(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def correlate(events: list[dict]) -> list[dict]:
    types = [e["event_type"] for e in events]
    findings = []
    for chain in CHAINS:
        if not all(t in types for t in chain["needs"]):
            continue
        if chain["cmdline_must_contain"]:
            ok = any(chain["cmdline_must_contain"] in
                     str(e.get("details", {}).get("command_line", "")).lower()
                     for e in events)
            if not ok:
                continue
        idx = sorted({types.index(t) for t in chain["needs"]})
        findings.append({"chain_id": chain["id"], "attck": chain["attck"],
                         "description": chain["description"],
                         "evidence_event_indexes": idx})
    return findings
