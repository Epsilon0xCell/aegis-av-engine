"""Sigma-subset import: JSON form only, loud about its limits.

Sigma is the detection community's interchange format, but the
full specification needs a YAML parser and a large modifier and
correlation surface that the Python standard library does not
provide. This importer therefore accepts the JSON encoding of a
deliberate SUBSET and rejects everything outside it by name:

Supported: title, id, logsource, detection selections whose
values are strings, numbers, or lists of them; the modifiers
|contains, |startswith, |endswith, |equals on field names;
wildcards * and ? inside values, matched case-insensitively;
conditions built from selection names with and, or, not and
parentheses.

Rejected loudly (SigmaImportError naming the construct):
correlation rules, unsupported modifiers such as |re, |base64,
|windash, aggregations (count(), by), timeframe, and any
condition token outside the grammar. It is named sigma-subset
everywhere it appears, because silently dropping the parts of a
rule an importer does not understand is how detections quietly
become fiction.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

SUPPORTED_MODIFIERS = {"contains", "startswith", "endswith", "equals", "eq"}


class SigmaImportError(ValueError):
    pass


def _pattern_to_regex(value: str, modifier: str | None) -> re.Pattern:
    body = value
    if modifier == "contains":
        body = f"*{value}*"
    elif modifier == "startswith":
        body = f"{value}*"
    elif modifier == "endswith":
        body = f"*{value}"
    regex = ""
    for ch in body:
        if ch == "*":
            regex += ".*"
        elif ch == "?":
            regex += "."
        else:
            regex += re.escape(ch)
    return re.compile(f"^{regex}$", re.IGNORECASE | re.DOTALL)


def _compile_selection(name: str, selection: dict) -> dict:
    if not isinstance(selection, dict):
        raise SigmaImportError(f"selection {name}: not a mapping")
    clauses = []
    for field, raw in selection.items():
        parts = field.split("|")
        base, modifiers = parts[0], parts[1:]
        for mod in modifiers:
            if mod not in SUPPORTED_MODIFIERS:
                raise SigmaImportError(
                    f"selection {name}: unsupported modifier |{mod} "
                    f"(sigma-subset supports: {sorted(SUPPORTED_MODIFIERS)})")
        values = raw if isinstance(raw, list) else [raw]
        compiled = []
        for v in values:
            if isinstance(v, (int, float)):
                compiled.append(("number", v))
            elif isinstance(v, str):
                compiled.append(("regex", _pattern_to_regex(
                    v, modifiers[0] if modifiers else "equals")))
            else:
                raise SigmaImportError(
                    f"selection {name}: unsupported value type "
                    f"{type(v).__name__}")
        clauses.append({"field": base, "values": compiled})
    return {"name": name, "clauses": clauses}


_TOKEN = re.compile(r"\s*(\(|\)|and\b|or\b|not\b|[A-Za-z_][A-Za-z0-9_]*)")


def _parse_condition(text: str, names: set[str]):
    tokens = []
    pos = 0
    while pos < len(text):
        m = _TOKEN.match(text, pos)
        if not m:
            raise SigmaImportError(f"condition: cannot parse near "
                                   f"{text[pos:pos + 16]!r}")
        tokens.append(m.group(1))
        pos = m.end()
    if any(t not in names and t not in ("and", "or", "not", "(", ")")
           for t in tokens):
        bad = [t for t in tokens
               if t not in names and t not in ("and", "or", "not", "(", ")")]
        raise SigmaImportError(f"condition: unknown selection(s) {bad}; "
                               f"aggregations and 'of' syntax are outside "
                               f"sigma-subset")
    cursor = [0]

    def peek():
        return tokens[cursor[0]] if cursor[0] < len(tokens) else None

    def parse_or():
        node = parse_and()
        while peek() == "or":
            cursor[0] += 1
            node = ("or", node, parse_and())
        return node

    def parse_and():
        node = parse_not()
        while peek() == "and":
            cursor[0] += 1
            node = ("and", node, parse_not())
        return node

    def parse_not():
        if peek() == "not":
            cursor[0] += 1
            return ("not", parse_not())
        return parse_atom()

    def parse_atom():
        tok = peek()
        if tok == "(":
            cursor[0] += 1
            node = parse_or()
            if peek() != ")":
                raise SigmaImportError("condition: missing )")
            cursor[0] += 1
            return node
        if tok in names:
            cursor[0] += 1
            return ("sel", tok)
        raise SigmaImportError(f"condition: unexpected token {tok!r}")

    tree = parse_or()
    if cursor[0] != len(tokens):
        raise SigmaImportError("condition: trailing tokens")
    return tree


def _eval_condition(tree, results: dict[str, bool]) -> bool:
    kind = tree[0]
    if kind == "sel":
        return results[tree[1]]
    if kind == "not":
        return not _eval_condition(tree[1], results)
    if kind == "and":
        return _eval_condition(tree[1], results) and _eval_condition(tree[2], results)
    return _eval_condition(tree[1], results) or _eval_condition(tree[2], results)


def _selection_matches(selection: dict, event: dict) -> bool:
    for clause in selection["clauses"]:
        actual = event.get(clause["field"])
        if actual is None:
            details = event.get("details", {})
            if isinstance(details, dict):
                actual = details.get(clause["field"])
        if actual is None:
            return False
        ok = False
        for kind, value in clause["values"]:
            if kind == "number" and actual == value:
                ok = True
            elif kind == "regex" and value.match(str(actual)):
                ok = True
        if not ok:
            return False
    return True


def import_sigma(text: str) -> dict:
    try:
        doc = json.loads(text)
    except ValueError as exc:
        raise SigmaImportError(f"not JSON (sigma-subset is JSON-only): {exc}")
    if not isinstance(doc, dict) or "title" not in doc or "detection" not in doc:
        raise SigmaImportError("rule needs at least title and detection")
    detection = doc["detection"]
    if "correlation" in doc or "correlation" in detection:
        raise SigmaImportError("correlation rules are outside sigma-subset")
    if "timeframe" in detection:
        raise SigmaImportError("timeframe is outside sigma-subset")
    selections = {}
    for name, sel in detection.items():
        if name == "condition":
            continue
        if isinstance(sel, dict) and "keywords" in sel:
            raise SigmaImportError("keyword selections are outside sigma-subset")
        selections[name] = _compile_selection(name, sel)
    condition = detection.get("condition", "selection")
    tree = _parse_condition(condition, set(selections))
    rule = {"title": doc["title"], "id": doc.get("id"),
            "level": doc.get("level"),
            "attck": (doc.get("tags") or []),
            "selections": selections, "condition": tree,
            "condition_text": condition}

    def matches(event: dict) -> bool:
        results = {name: _selection_matches(sel, event)
                   for name, sel in selections.items()}
        return _eval_condition(tree, results)

    rule["matches"] = matches
    return rule


def import_sigma_file(path: Path) -> dict:
    return import_sigma(Path(path).read_text())
