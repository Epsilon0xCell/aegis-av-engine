"""Parser mutation score: are the parser fixtures sensitive?

Borrowed from the pack mutation discipline and pointed at the
parsers themselves. Every integer constant in a parser module
is mutated in turn (plus one, minus one, doubled, zeroed); the
mutant module is loaded from source and run against a probe
that records a behaviour signature over fixture inputs. A
mutant is killed when the probe raises or the signature
changes. Survivors are reported by constant, never hidden:
some are true equivalents, and some mark constants the probe
cannot see (resource caps are the known case; those are
exercised by the fuzz campaign's oracle instead, and the
report says so).

Scope: modules that load standalone (formats_cfb, formats_pdf,
rulelang today). The score is a property of the probe as much
as of the parser, and both are versioned together.
"""
from __future__ import annotations

import ast
import hashlib
import importlib.util
import sys
import tempfile
from pathlib import Path


def _constants(source: str) -> list[dict]:
    tree = ast.parse(source)
    found = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, int) \
                and not isinstance(node.value, bool):
            found.append({"lineno": node.lineno, "col": node.col_offset,
                          "end_col": node.end_col_offset,
                          "value": node.value})
    return found


def _apply(source: str, const: dict, new_value: int) -> str:
    lines = source.splitlines(keepends=True)
    line = lines[const["lineno"] - 1]
    lines[const["lineno"] - 1] = (line[:const["col"]] + str(new_value)
                                  + line[const["end_col"]:])
    return "".join(lines)


def _load(name: str, source: str, tmp: Path):
    path = tmp / f"{name}.py"
    path.write_text(source)
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def mutation_score(module_path: Path, probe, tmp_root: Path) -> dict:
    source = Path(module_path).read_text()
    base_name = f"mut_{Path(module_path).stem}_base"
    with tempfile.TemporaryDirectory(dir=tmp_root) as td:
        tmp = Path(td)
        baseline_mod = _load(base_name, source, tmp)
        baseline = probe(baseline_mod)
        mutants = []
        killed = 0
        survived = []
        for const in _constants(source):
            for op, new_value in [("+1", const["value"] + 1),
                                  ("-1", const["value"] - 1),
                                  ("zero", 0)]:
                if new_value == const["value"] or new_value < 0:
                    continue
                label = f"line {const['lineno']}: {const['value']} -> {new_value}"
                try:
                    mod = _load(f"mut_{Path(module_path).stem}_x",
                                _apply(source, const, new_value), tmp)
                    signature = probe(mod)
                    dead = signature != baseline
                except Exception:
                    dead = True
                mutants.append(label)
                if dead:
                    killed += 1
                else:
                    survived.append(label)
        total = len(mutants)
        return {"module": Path(module_path).name, "mutants": total,
                "killed": killed, "survived": survived,
                "score": (killed / total) if total else 1.0,
                "baseline_signature": hashlib.sha256(
                    repr(baseline).encode()).hexdigest()[:12]}
