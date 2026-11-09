"""Prevalence-adjusted reporting: what a score means in the wild.

Detection counts measured on a balanced generated corpus do
not survive contact with real prevalence, where the malicious
base rate may be 1 percent or far below. Precision at an
assumed prevalence follows from Bayes' rule applied to the
SAME measured counts:

    precision(pi) = TPR * pi / (TPR * pi + FPR * (1 - pi))

Reporting this at several prevalences is not pessimism, it is
arithmetic honesty: a detector with a 1 percent false-positive
rate is mostly wrong at 0.1 percent prevalence no matter how
good its true-positive rate is. On this project's generated
corpora the measured FPR is currently 0, which makes adjusted
precision 1.0 at every prevalence BY ARITHMETIC, not by merit;
the function exists so the day a false positive appears, the
reporting already knows how to say what it costs.
"""
from __future__ import annotations


def rates(tp: int, fp: int, fn: int, tn: int) -> dict:
    tpr = tp / (tp + fn) if (tp + fn) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    precision_measured = tp / (tp + fp) if (tp + fp) else 1.0
    return {"tpr": round(tpr, 6), "fpr": round(fpr, 6),
            "precision_at_measured_prevalence": round(precision_measured, 6),
            "counts": {"tp": tp, "fp": fp, "fn": fn, "tn": tn}}


def precision_at_prevalence(tp: int, fp: int, fn: int, tn: int,
                            prevalence: float) -> float:
    r = rates(tp, fp, fn, tn)
    num = r["tpr"] * prevalence
    den = num + r["fpr"] * (1 - prevalence)
    return round(num / den, 6) if den else 1.0


def prevalence_report(tp: int, fp: int, fn: int, tn: int,
                      prevalences: tuple[float, ...] = (0.5, 0.1, 0.01, 0.001)
                      ) -> dict:
    return {"rates": rates(tp, fp, fn, tn),
            "precision_by_prevalence": {
                str(p): precision_at_prevalence(tp, fp, fn, tn, p)
                for p in prevalences},
            "note": "Bayes adjustment of the same measured counts; "
                    "not a new measurement"}
