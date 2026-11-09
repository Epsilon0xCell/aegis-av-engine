"""Reporting exports: ATT&CK Navigator layer, STIX 2.1 subset, SARIF.

Exports COMMUNICATE verdicts; they add no detection capability,
and each format is a deliberate subset: the Navigator layer format
for coverage, a small STIX 2.1 bundle (file SCO, malware-analysis
SDO, relationships) with deterministic uuid5 identifiers, and
SARIF for tool interoperability. Building all 18 STIX object
types or a Navigator UI would be breadth without capability and
is explicitly out of scope (see research §8).
"""
from __future__ import annotations

from . import __version__

import json
import uuid
from pathlib import Path

_NS = uuid.UUID("98432000-0000-4000-8000-0000000000aa")


def _det_id(kind: str, key: str) -> str:
    return f"{kind}--{uuid.uuid5(_NS, kind + ':' + key)}"


def navigator_layer(verdicts: list[dict], name: str = "Aegis scan") -> dict:
    techniques: dict[str, int] = {}
    for v in verdicts:
        for e in v.get("evidence", []):
            if e.get("type") == "rule_match":
                for t in e.get("attck", []):
                    techniques[t] = techniques.get(t, 0) + 1
    return {
        "name": name, "versions": {"layer": "4.5", "navigator": "5.1.0",
                                   "attack": "17"},
        "domain": "enterprise-attack",
        "techniques": [{"techniqueID": t, "score": min(100, 25 * n),
                        "comment": f"{n} matching verdict(s)", "enabled": True}
                       for t, n in sorted(techniques.items())],
        "gradient": {"colors": ["#ffffff", "#ffedc2", "#ff6666"],
                     "minValue": 0, "maxValue": 100},
    }


def stix_bundle(verdicts: list[dict]) -> dict:
    objects: list[dict] = []
    for v in verdicts:
        file_id = _det_id("file", v["hashes"]["sha256"])
        objects.append({"type": "file", "id": file_id,
                        "spec_version": "2.1",
                        "hashes": {"SHA-256": v["hashes"]["sha256"], "MD5": v["hashes"]["md5"]},
                        "name": v["file"], "size": v["size"]})
        analysis_id = _det_id("malware-analysis", v["hashes"]["sha256"])
        objects.append({
            "type": "malware-analysis", "id": analysis_id,
            "spec_version": "2.1", "product": "aegis-av-engine",
            "result": ("malicious" if v["verdict"] == "malicious_pattern"
                       else "suspicious" if v["verdict"] == "suspicious"
                       else "benign"),
            "analysis_sco_refs": [file_id]})
    return {"type": "bundle", "id": _det_id("bundle", "aegis-scan"),
            "objects": objects}


def sarif_log(verdicts: list[dict]) -> dict:
    results = []
    for v in verdicts:
        if v["verdict"] == "clean":
            continue
        rule_ids = [e["rule_id"] for e in v.get("evidence", [])
                    if e.get("type") == "rule_match"]
        results.append({
            "ruleId": rule_ids[0] if rule_ids else "AEGIS-HEURISTIC",
            "level": "error" if v["verdict"] == "malicious_pattern" else "warning",
            "message": {"text": f"{v['verdict']} (score {v['score']}): "
                                f"{', '.join(rule_ids) or 'heuristic scorecard'}"},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": Path(v["file"]).name}}}]})
    return {"version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [{"tool": {"driver": {"name": "Aegis AV Engine",
                                          "version": __version__}},
                      "results": results}]}
