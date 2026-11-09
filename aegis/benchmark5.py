"""Release benchmark: 5 runs, median and IQR, cold and warm apart.

Per the BENCHMARK protocol: no single-run numbers, no averaging
across operating systems (the caller runs this per OS and reports
per OS), corpus identified by its manifest hash so results from
different corpora are never compared as if they were the same.
"""
from __future__ import annotations

import hashlib
import json
import statistics
import time
from pathlib import Path
from typing import Callable


def _iqr(values: list[float]) -> float:
    if len(values) < 4:
        return max(values) - min(values)
    q = statistics.quantiles(values, n=4, method="inclusive")
    return q[2] - q[0]


def run_benchmark(engine_factory: Callable, corpus_dir: Path,
                  runs: int = 5) -> dict:
    files = sorted(p for p in corpus_dir.rglob("*") if p.is_file())
    manifest_hash = hashlib.sha256()
    for p in files:
        manifest_hash.update(p.relative_to(corpus_dir).as_posix().encode())
        manifest_hash.update(hashlib.sha256(p.read_bytes()).digest())
    cold_rates, warm_rates = [], []
    accounting = None
    deterministic = True
    reference: dict[str, str] | None = None
    for _ in range(runs):
        engine = engine_factory()
        started = time.perf_counter()
        verdicts = {}
        for p in files:
            v = engine.scan_file(p)
            verdicts[p.relative_to(corpus_dir).as_posix()] = v["verdict"]
        cold = time.perf_counter() - started
        cold_rates.append(len(files) / cold)
        started = time.perf_counter()
        for p in files:
            engine.scan_file(p)
        warm = time.perf_counter() - started
        warm_rates.append(len(files) / warm)
        if reference is None:
            reference = verdicts
        elif verdicts != reference:
            deterministic = False
    return {
        "corpus_manifest_sha256": manifest_hash.hexdigest()[:16],
        "files": len(files), "runs": runs,
        "cold_files_per_sec_median": round(statistics.median(cold_rates), 2),
        "cold_files_per_sec_iqr": round(_iqr(cold_rates), 2),
        "warm_files_per_sec_median": round(statistics.median(warm_rates), 2),
        "warm_files_per_sec_iqr": round(_iqr(warm_rates), 2),
        "deterministic_across_runs": deterministic,
        "protocol": "5+ runs, median and IQR, cold (fresh engine, cold cache) "
                    "and warm (cache hot) reported separately, per-OS, never "
                    "averaged across operating systems",
    }
