"""Human-promoted behaviour chains.

The PrefixSpan miner emits CandidatePattern objects behind a
type wall: the correlator cannot consume them, on purpose.
Promotion is the human step between mining and detection. A
reviewer who has read a candidate writes a promotion record
naming the pattern it came from, its support, and themselves
as approver; only then does the pattern become a chain the
analyser can run. A record without an approver, or without
the source pattern it claims to promote, is refused at load:
provenance is the whole mechanism.
"""
from __future__ import annotations

import json
from pathlib import Path


class PromotionError(ValueError):
    pass


def load_promoted(path: Path) -> list[dict]:
    doc = json.loads(Path(path).read_text())
    chains = []
    for entry in doc.get("chains", []):
        if not entry.get("approved_by"):
            raise PromotionError(
                f"chain {entry.get('id')!r} has no approver; "
                f"promotion is a human act and must be signed")
        source = entry.get("promoted_from") or {}
        if not source.get("pattern") or "support" not in source:
            raise PromotionError(
                f"chain {entry.get('id')!r} does not name the "
                f"mined pattern and support it was promoted from")
        steps = []
        for item in source["pattern"]:
            action, _, technique = item.partition(":")
            steps.append({"event_type": action,
                          "technique": technique or None,
                          "weight": 1})
        chains.append({
            "id": entry["id"],
            "attck": sorted({s["technique"] for s in steps
                             if s["technique"]}),
            "needs": [s["event_type"] for s in steps],
            "cmdline_must_contain": entry.get("cmdline_must_contain"),
            "description": entry.get("description", ""),
            "steps": steps,
            "promoted_from": source,
            "approved_by": entry["approved_by"]})
    return chains
