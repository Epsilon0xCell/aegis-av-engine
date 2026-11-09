"""Deterministic multiprocess directory scanning.

Throughput scales with processes; reports must not. Workers
scan files independently, and the report is assembled sorted by
canonical relative path, so a scan with 1 worker and a scan
with 8 produce byte-identical report JSON (that equality is a
test, not a hope). Each worker builds its own engine from the
pack path: engines hold caches, and shared mutable state across
processes would be a determinism and correctness hazard.
"""
from __future__ import annotations

import json
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

from .engine import Engine
from .rules import RulePack

_PACK_PATH: str | None = None
_ENGINE: Engine | None = None


def _init(pack_path: str) -> None:
    global _PACK_PATH, _ENGINE
    _PACK_PATH = pack_path
    _ENGINE = Engine(RulePack(Path(pack_path)))


def _scan_one(item: tuple[str, str]) -> dict:
    rel, full = item
    assert _ENGINE is not None
    verdict = _ENGINE.scan_file(Path(full))
    return {"path": rel, "verdict": verdict["verdict"],
            "score": verdict["score"],
            "sha256": verdict["hashes"]["sha256"],
            "format": verdict["format"]}


def scan_directory(root: Path, pack_path: Path, workers: int = 4) -> dict:
    root = Path(root)
    files = sorted(
        (p for p in root.rglob("*") if p.is_file()),
        key=lambda p: p.relative_to(root).as_posix())
    items = [(p.relative_to(root).as_posix(), str(p)) for p in files]
    if workers <= 1 or len(items) <= 1:
        _init(str(pack_path))
        results = [_scan_one(item) for item in items]
    else:
        with ProcessPoolExecutor(max_workers=workers,
                                 initializer=_init,
                                 initargs=(str(pack_path),)) as pool:
            results = list(pool.map(_scan_one, items))
    results.sort(key=lambda r: r["path"])
    summary: dict[str, int] = {}
    for r in results:
        summary[r["verdict"]] = summary.get(r["verdict"], 0) + 1
    return {"root": str(root), "files": len(results),
            "summary": summary, "results": results}


def report_json(report: dict) -> str:
    return json.dumps(report, indent=1, sort_keys=True)
