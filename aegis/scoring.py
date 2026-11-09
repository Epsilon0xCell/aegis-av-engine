"""Explainable static scoring: OFF by default, capped, exact.

An integer linear model over a versioned feature set (groups
inspired by EMBER's published feature design, computed from this
engine's own parsers). Integer weights make every contribution
EXACT and auditable: the verdict carries each feature's value,
weight, and product, and they sum to the score by construction.
No approximate post-hoc explanations. Two hard rules:

1. The module is OFF unless the caller enables it.
2. It can raise a file to at most SUSPICIOUS. A statistical score
   never convicts on its own in this engine; conviction requires
   a signature or the deterministic scorecard.

Evaluation honesty (from the research): scores are reported
against this project's generated corpora only, with the model
card in docs/model_card.md stating the limits, including dataset
bias warnings from the TESSERACT work on malware ML evaluation.
"""
from __future__ import annotations

FEATURE_VERSION = "aegis-features@1.0.0"
# feature -> integer weight (points). Positive = more fixture-like.
WEIGHTS = {
    "entropy_above_6_x10": 3,    # entropy past 6.0 only, scaled by 10: plain text (~4.5) must score zero here
    "exec_high_entropy_sections": 18,
    "overlay_ratio_pct": 1,      # overlay bytes as % of file, capped 50
    "imports_suspicious_dlls": 12,
    "imports_total_capped": 1,   # import count, capped 20
    "no_authenticode_pe": 6,
    "zero_timestamp_pe": 5,
    "rpath_present_elf": 10,
    "unsigned_macho": 6,
    "container_members_capped": 1,
}
SUSPICIOUS_SCORE = 60  # module ceiling: can flag suspicious only

SUSPICIOUS_DLLS = {"wininet.dll", "ws2_32.dll", "urlmon.dll"}


def extract_features(verdict: dict, data_len: int) -> dict[str, int]:
    analysis = verdict.get("format_analysis") or {}
    findings = [e for e in verdict.get("evidence", [])
                if e.get("type") == "format_finding"]
    feats: dict[str, int] = {}
    feats["entropy_above_6_x10"] = max(0, int(verdict.get("entropy", 0) * 10) - 60)
    feats["exec_high_entropy_sections"] = sum(
        1 for f in findings if f.get("type") == "high_entropy_executable_sections")
    overlay = analysis.get("overlay_bytes", 0)
    feats["overlay_ratio_pct"] = min(50, (100 * overlay) // max(data_len, 1))
    imports = analysis.get("imports") or {}
    feats["imports_suspicious_dlls"] = sum(
        1 for dll in imports if dll.lower() in SUSPICIOUS_DLLS)
    feats["imports_total_capped"] = min(20, len(imports))
    is_pe = verdict.get("format") == "pe"
    feats["no_authenticode_pe"] = 1 if is_pe and not analysis.get(
        "has_authenticode_table") else 0
    feats["zero_timestamp_pe"] = 1 if is_pe and analysis.get("timestamp") == 0 else 0
    feats["rpath_present_elf"] = 1 if any(
        f.get("type") == "rpath_present" for f in findings) else 0
    feats["unsigned_macho"] = 1 if str(verdict.get("format", "")).startswith(
        "macho") and not analysis.get("has_code_signature") else 0
    container = verdict.get("container")
    feats["container_members_capped"] = min(
        20, len(container["members"])) if container else 0
    return feats


def score_features(feats: dict[str, int]) -> dict:
    contributions = []
    total = 0
    for name, weight in WEIGHTS.items():
        value = int(feats.get(name, 0))
        product = value * weight
        total += product
        if value:
            contributions.append({"feature": name, "value": value,
                                  "weight": weight, "points": product})
    contributions.sort(key=lambda c: -c["points"])
    return {"feature_version": FEATURE_VERSION, "score": total,
            "contributions": contributions,
            "exact_sum_check": sum(c["points"] for c in contributions) == total,
            "flag": "suspicious" if total >= SUSPICIOUS_SCORE else "none",
            "ceiling": "suspicious"}


def score_verdict(verdict: dict, data_len: int) -> dict:
    return score_features(extract_features(verdict, data_len))
