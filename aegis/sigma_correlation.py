"""Sigma correlation subset (spec 2.1.0): counts and time.

The v2 sigma-subset importer rejects correlation rules loudly.
This module is where correlations live instead, as their own
explicit subset: event_count, value_count, temporal, and
temporal_ordered, over base rules imported by sigma_import.
Aggregation correlations (value_sum, value_avg and friends)
are rejected by name, as are unknown types and conditions:
the subset is small because every construct in it has exact,
tested semantics.

Semantics (per the spec's model): events carry a numeric
"timestamp" (seconds). A correlation references base rules by
id, groups by zero or more fields, and looks inside a sliding
timespan window. event_count fires when the number of matched
events in some window satisfies the condition. value_count
counts distinct values of the named field instead. temporal
fires when every referenced rule matched at least once inside
some window (order irrelevant); temporal_ordered additionally
requires the matches to occur in the referenced rule order.
One hit per group is reported, with the first firing window.
"""
from __future__ import annotations

import json
import re

SUPPORTED_TYPES = {"event_count", "value_count", "temporal",
                   "temporal_ordered"}
AGGREGATION_TYPES = {"value_sum", "value_avg", "value_min",
                     "value_max", "value_percentile"}
_CONDITIONS = {"gte", "gt", "lte", "lt", "eq"}
_TIMESPAN_RE = re.compile(r"^(\d+)\s*([smhd])$")
_UNIT_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400}


class CorrelationError(ValueError):
    pass


def parse_timespan(text) -> int:
    if isinstance(text, (int, float)):
        return int(text)
    m = _TIMESPAN_RE.match(str(text).strip())
    if not m:
        raise CorrelationError(f"unparsable timespan: {text!r}")
    return int(m.group(1)) * _UNIT_SECONDS[m.group(2)]


def load_correlation(text: str) -> dict:
    try:
        doc = json.loads(text)
    except ValueError as exc:
        raise CorrelationError(f"not JSON: {exc}")
    corr = doc.get("correlation")
    if not isinstance(corr, dict):
        raise CorrelationError("document has no correlation object")
    ctype = corr.get("type")
    if ctype in AGGREGATION_TYPES:
        raise CorrelationError(
            f"aggregation correlation {ctype!r} is outside the "
            f"subset (aggregations need statistics this engine "
            f"does not pretend to have)")
    if ctype not in SUPPORTED_TYPES:
        raise CorrelationError(f"unsupported correlation type: {ctype!r}")
    rules = corr.get("rules")
    if isinstance(rules, str):
        rules = [rules]
    if not rules or not all(isinstance(r, str) for r in rules):
        raise CorrelationError("correlation.rules must be rule ids")
    cond = corr.get("condition", {"gte": 1})
    if not isinstance(cond, dict) or len(cond) != 1 \
            or set(cond) - _CONDITIONS:
        raise CorrelationError(
            f"condition must be exactly one of {sorted(_CONDITIONS)}")
    out = {"id": doc.get("id"), "title": doc.get("title"),
           "type": ctype, "rules": rules,
           "group_by": corr.get("group-by", []),
           "timespan_s": parse_timespan(corr.get("timespan", "5m")),
           "condition": cond,
           "field": corr.get("field")}
    if ctype == "value_count" and not out["field"]:
        raise CorrelationError("value_count requires correlation.field")
    if ctype in ("event_count", "value_count") and len(rules) != 1:
        raise CorrelationError(f"{ctype} references exactly one rule")
    return out


def _condition_holds(cond: dict, value: int) -> bool:
    (op, threshold), = cond.items()
    return {"gte": value >= threshold, "gt": value > threshold,
            "lte": value <= threshold, "lt": value < threshold,
            "eq": value == threshold}[op]


def _group_key(event: dict, fields: list[str]) -> tuple:
    return tuple(str(event.get(f)) for f in fields)


def evaluate(correlation: dict, base_rules: dict[str, dict],
             events: list[dict]) -> list[dict]:
    """base_rules maps rule id to an import_sigma rule dict."""
    missing = [r for r in correlation["rules"] if r not in base_rules]
    if missing:
        raise CorrelationError(f"unknown base rules: {missing}")
    span = correlation["timespan_s"]
    groups: dict[tuple, list[tuple[float, str, dict]]] = {}
    for event in events:
        ts = event.get("timestamp")
        if not isinstance(ts, (int, float)):
            continue
        for rid in correlation["rules"]:
            if base_rules[rid]["matches"](event):
                key = _group_key(event, correlation["group_by"])
                groups.setdefault(key, []).append(
                    (float(ts), rid, event))
    hits = []
    for key, items in sorted(groups.items()):
        items.sort(key=lambda x: x[0])
        hit = _evaluate_group(correlation, items, span)
        if hit:
            hits.append({"correlation": correlation["id"],
                         "group": dict(zip(correlation["group_by"],
                                           key)),
                         **hit})
    return hits


def _evaluate_group(corr: dict, items, span: int) -> dict | None:
    ctype = corr["type"]
    n = len(items)
    if ctype in ("event_count", "value_count"):
        for i in range(n):
            window = [it for it in items[i:]
                      if it[0] - items[i][0] <= span]
            if ctype == "event_count":
                value = len(window)
            else:
                value = len({str(it[2].get(corr["field"]))
                             for it in window})
            if _condition_holds(corr["condition"], value):
                return {"window_start": items[i][0],
                        "window_end": window[-1][0], "value": value}
        return None
    # temporal family: every referenced rule inside one window
    wanted = corr["rules"]
    for i in range(n):
        window = [it for it in items[i:] if it[0] - items[i][0] <= span]
        present = [rid for _ts, rid, _e in window]
        if ctype == "temporal":
            if all(r in present for r in wanted):
                return {"window_start": items[i][0],
                        "window_end": window[-1][0],
                        "value": len(set(present))}
        else:  # temporal_ordered
            pos = 0
            ok = True
            for r in wanted:
                found = False
                while pos < len(present):
                    if present[pos] == r:
                        found = True
                        pos += 1
                        break
                    pos += 1
                if not found:
                    ok = False
                    break
            if ok:
                return {"window_start": items[i][0],
                        "window_end": window[-1][0],
                        "value": len(wanted)}
    return None
