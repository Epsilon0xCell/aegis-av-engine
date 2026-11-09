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
     "description": "Recovery inhibition followed by encryption activity."},
    {"id": "CHAIN-KEYLOG-BEHAVIOUR", "attck": ["T1056.001", "T1071.001"],
     "needs": ["hook_install_fixture", "log_append", "beacon"],
     "cmdline_must_contain": None,
     "description": "Hook pattern plus periodic appends plus a size beacon."},
    {"id": "CHAIN-C2-ENCRYPT", "attck": ["T1071.001", "T1486"],
     "needs": ["beacon", "file_encrypt"],
     "cmdline_must_contain": None,
     "description": "Beaconing combined with encryption activity from one host log."},
]


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
