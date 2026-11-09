"""Benchmark harness: measures ONLY what it measures.

Reports throughput, per-corpus detection accounting against the
generated ground truth, determinism (a second full scan must
reproduce every verdict), and cross-run cache effect. It refuses
to emit a report without the corpus manifest hash, because an
unlabelled benchmark number is how dishonest comparisons start
(see BENCHMARK.md).
"""
from __future__ import annotations

import hashlib
import json
import platform
import time
from pathlib import Path

from . import __version__
from .engine import Engine


def run_benchmark(engine: Engine, corpus_root: Path, manifest: dict) -> dict:
    files = sorted(p for p in corpus_root.rglob("*")
                   if p.is_file() and p.name != "manifest.json")
    started = time.perf_counter()
    first = {p.relative_to(corpus_root).as_posix(): engine.scan_file(p) for p in files}
    cold_s = time.perf_counter() - started
    started = time.perf_counter()
    second = {p.relative_to(corpus_root).as_posix(): engine.scan_file(p) for p in files}
    warm_s = time.perf_counter() - started
    deterministic = all(first[k]["verdict"] == second[k]["verdict"]
                        and first[k]["score"] == second[k]["score"] for k in first)
    total_bytes = sum(p.stat().st_size for p in files)
    tp = fp = fn = tn = 0
    for rel, truth in manifest.items():
        verdict = first[rel]["verdict"]
        flagged = verdict in ("malicious_pattern", "suspicious")
        if truth == "clean":
            fp, tn = fp + flagged, tn + (not flagged)
        else:
            tp, fn = tp + flagged, fn + (not flagged)
    manifest_hash = hashlib.sha256(
        json.dumps(manifest, sort_keys=True).encode()).hexdigest()[:16]
    return {
        "engine": f"aegis@{__version__}", "rule_pack": engine.pack.name,
        "platform": platform.platform(), "python": platform.python_version(),
        "corpus_manifest_sha256_16": manifest_hash,
        "files": len(files), "bytes": total_bytes,
        "cold_scan_seconds": round(cold_s, 4),
        "warm_scan_seconds": round(warm_s, 4),
        "files_per_second_cold": round(len(files) / cold_s, 1) if cold_s else None,
        "megabytes_per_second_cold": round(total_bytes / 1e6 / cold_s, 3) if cold_s else None,
        "deterministic": deterministic,
        "fixtures_flagged_tp": tp, "fixtures_missed_fn": fn,
        "clean_flagged_fp": fp, "clean_passed_tn": tn,
        "honesty": "Axes measured by this harness on this machine and corpus only. "
                   "No vendor product was run; no vendor comparison is made or implied.",
    }
