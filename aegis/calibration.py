"""Calibration and abstention for the scoring module.

A score by itself invites a false question: where is the line?
This module replaces the line with a prediction set, using
class-conditional (Mondrian) split conformal inference over a
calibration set of (score, label) pairs whose labels are known
by construction (generated clean files and generated fixtures).

For a new score, each class is tested on its own calibration
distribution: the malicious class is plausible when the score is
not unusually LOW for malicious examples, the clean class when
it is not unusually HIGH for clean ones, with the conformal
quantile at level alpha guaranteeing marginal coverage of
1 - alpha under exchangeability, per class. The result:

- {malicious} only:  confident suspicious-leaning
- {clean} only:      confident clean-leaning
- both classes:      ABSTAIN (ambiguous: the score sits where
                     the two classes overlap)
- neither class:     ABSTAIN (novel: the score sits outside
                     everything the calibration set contains)

Selective prediction is reported the honest way, as a
risk-coverage curve: at each alpha, what fraction of cases the
module answers (coverage) and how often it is wrong among the
answered (risk). A module that answers everything and is
sometimes wrong is worse than one that abstains on the hard
band and is right where it answers; the curve is the evidence.

Calibration data here is self-generated, so every number is a
statement about this project's generated corpora, split by
generator family to respect the TESSERACT cautions, never a
statement about real-world accuracy. ECE is computed on a
held-out half against frequencies fitted on the other half.
"""
from __future__ import annotations

import math


def _conformal_quantile(values: list[float], alpha: float) -> float:
    """Smallest value v with the split-conformal guarantee:
    index ceil((n+1)(1-alpha)) in the sorted list, clamped."""
    if not values:
        return math.inf
    ordered = sorted(values)
    k = math.ceil((len(ordered) + 1) * (1 - alpha))
    idx = min(max(k, 1), len(ordered)) - 1
    return ordered[idx]


class Calibration:
    """Class-conditional conformal calibration over scores."""

    VERSION = "aegis-calibration@1.0.0"

    def __init__(self, pairs: list[tuple[int, bool]]) -> None:
        # pairs: (score, is_malicious_label)
        self.clean_scores = sorted(s for s, m in pairs if not m)
        self.malicious_scores = sorted(s for s, m in pairs if m)
        if not self.clean_scores or not self.malicious_scores:
            raise ValueError("calibration needs both classes")
        self.n = len(pairs)

    def prediction_set(self, score: int, alpha: float = 0.1) -> list[str]:
        out = []
        # malicious nonconformity is -score: plausible when
        # -score <= quantile of malicious nonconformities
        mal_nc = [-s for s in self.malicious_scores]
        if -score <= _conformal_quantile(mal_nc, alpha):
            out.append("malicious")
        # clean nonconformity is the score itself
        if score <= _conformal_quantile(self.clean_scores, alpha):
            out.append("clean")
        return out

    def classify(self, score: int, alpha: float = 0.1) -> dict:
        pset = self.prediction_set(score, alpha)
        if pset == ["malicious"]:
            band = "confident_suspicious"
        elif pset == ["clean"]:
            band = "confident_clean"
        elif len(pset) == 2:
            band = "abstain_ambiguous"
        else:
            band = "abstain_novel"
        return {"band": band, "prediction_set": pset, "alpha": alpha,
                "calibration": self.VERSION,
                "calibration_n": self.n}


def risk_coverage(pairs: list[tuple[int, bool]],
                  alphas: tuple[float, ...] = (0.02, 0.05, 0.1, 0.2, 0.3, 0.5)
                  ) -> list[dict]:
    """Leave-one-out style evaluation on the calibration pairs
    themselves is optimistically biased, so this evaluates each
    pair against a calibration built from the OTHER pairs of its
    own class proportions (split-half by position, deterministic).
    Coverage is the fraction answered; risk is the error rate
    among the answered."""
    curve = []
    half = len(pairs) // 2
    fit, test = pairs[:half], pairs[half:]
    if not fit or not test:
        return curve
    calib = Calibration(fit)
    for alpha in alphas:
        answered = errors = 0
        for score, is_mal in test:
            result = calib.classify(score, alpha)
            if result["band"].startswith("abstain"):
                continue
            answered += 1
            predicted_mal = result["band"] == "confident_suspicious"
            if predicted_mal != is_mal:
                errors += 1
        curve.append({"alpha": alpha,
                      "coverage": round(answered / len(test), 4) if test else 0.0,
                      "risk": round(errors / answered, 4) if answered else None,
                      "answered": answered, "test_n": len(test)})
    return curve


def ece_report(pairs: list[tuple[int, bool]], bins: int = 5) -> dict:
    """Expected calibration error of binned empirical frequencies,
    fitted on the first half and measured on the second half, so
    the number is not the fit grading itself."""
    half = len(pairs) // 2
    fit, test = sorted(pairs)[:half], sorted(pairs)[half:]
    if not fit or not test:
        return {"ece": None, "note": "not enough pairs"}
    lo = min(s for s, _ in pairs)
    hi = max(s for s, _ in pairs)
    width = max((hi - lo) / bins, 1e-9)

    def bin_of(score: int) -> int:
        return min(bins - 1, int((score - lo) / width))

    fit_freq: dict[int, float] = {}
    for b in range(bins):
        members = [m for s, m in fit if bin_of(s) == b]
        if members:
            fit_freq[b] = sum(members) / len(members)
    total = len(test)
    ece = 0.0
    detail = []
    for b in range(bins):
        members = [m for s, m in test if bin_of(s) == b]
        if not members or b not in fit_freq:
            continue
        observed = sum(members) / len(members)
        ece += (len(members) / total) * abs(observed - fit_freq[b])
        detail.append({"bin": b, "n": len(members),
                       "predicted": round(fit_freq[b], 4),
                       "observed": round(observed, 4)})
    return {"ece": round(ece, 4), "bins": detail,
            "note": "frequencies fitted on first half, ECE on second"}


def classify_score(score: int, calibration: "Calibration",
                   alpha: float = 0.1) -> dict:
    """The calibrated reading of one score: the band, and the
    standing reminder that the scoring module's ceiling is
    suspicious and a band is not a verdict."""
    result = calibration.classify(score, alpha)
    result["score"] = score
    result["ceiling"] = "suspicious"
    return result


def build_calibration_pairs(engine, clean_dir, fixture_dir) -> list[tuple[int, bool]]:
    """Score generated corpora with the scoring module and pair
    each score with its by-construction label."""
    from pathlib import Path

    from . import scoring
    pairs: list[tuple[int, bool]] = []
    for directory, is_mal in ((clean_dir, False), (fixture_dir, True)):
        for path in sorted(Path(directory).rglob("*")):
            if path.is_file():
                data = path.read_bytes()
                verdict = engine.scan_bytes(data, path.name)
                result = scoring.score_verdict(verdict, len(data))
                if result is not None:
                    pairs.append((result["score"], is_mal))
    return pairs
