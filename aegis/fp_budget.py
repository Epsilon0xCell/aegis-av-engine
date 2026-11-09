"""Per-rule false-positive budgets, enforced as data.

A detection rule earns its keep on the corpora it does NOT
fire on. This module counts, for every rule in a pack, how
many files of the clean corpus it matches, and compares the
count to a budget file:

    {"default": 0, "per_rule": {"RULE-ID": 0}}

The shipped budget is zero for every rule on the generated
clean corpus, and the budget check runs in the test suite, so
a pull request that makes a rule fire on clean files fails CI
by rule name. Budgets are policy, recorded in version control,
changed deliberately, and never silently.
"""
from __future__ import annotations

import json
from pathlib import Path

from . import formats
from .rules import RulePack


def count_clean_matches(pack: RulePack, clean_dir: Path) -> dict[str, int]:
    counts: dict[str, int] = {r["id"]: 0 for r in pack.rules}
    files = 0
    for path in sorted(Path(clean_dir).rglob("*")):
        if not path.is_file():
            continue
        data = path.read_bytes()
        facts = {"format": formats.identify(data),
                 "entropy": formats.shannon_entropy(data),
                 "size": len(data)}
        files += 1
        for m in pack.match(data, facts):
            counts[m["rule_id"]] = counts.get(m["rule_id"], 0) + 1
    return {"counts": counts, "clean_files": files}


def check_fp_budget(pack: RulePack, clean_dir: Path,
                    budget_path: Path | None = None) -> dict:
    budget = {"default": 0, "per_rule": {}}
    if budget_path is not None and Path(budget_path).exists():
        budget = json.loads(Path(budget_path).read_text())
    result = count_clean_matches(pack, clean_dir)
    violations = []
    for rule_id, n in sorted(result["counts"].items()):
        allowed = budget.get("per_rule", {}).get(
            rule_id, budget.get("default", 0))
        if n > allowed:
            violations.append({"rule": rule_id, "clean_matches": n,
                               "budget": allowed})
    return {"violations": violations, **result,
            "budget_default": budget.get("default", 0)}
