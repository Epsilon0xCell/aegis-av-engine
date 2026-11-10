"""Worker-scaling measurement for parscan.

Runs the parallel scanner over a generated corpus at worker
counts 1, 2, 4, 8 and reports wall time and files/sec for
each, plus whether the per-worker reports are identical
(they must be; parscan sorts its output canonically). No
expected curve is asserted here: the numbers are published
as measured, and on shared or throttled hardware the curve
may flatten or invert, which is also a result.
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from aegis.corpora import make_clean_corpus, make_fixture_corpus  # noqa: E402
from aegis.parscan import scan_directory  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent


def measure(corpus: Path, workers_list=(1, 2, 4, 8)) -> dict:
    rows = []
    reference = None
    for workers in workers_list:
        start = time.perf_counter()
        report = scan_directory(corpus, ROOT / "rules" / "core_rules_v2.json",
                                workers=workers)
        elapsed = time.perf_counter() - start
        canonical = json.dumps(report["summary"], sort_keys=True)
        if reference is None:
            reference = canonical
        rows.append({"workers": workers, "seconds": round(elapsed, 3),
                     "files_per_sec": round(report["files"] / elapsed, 2),
                     "summary_identical": canonical == reference})
    return {"corpus": str(corpus), "rows": rows}


if __name__ == "__main__":
    corpus = Path(sys.argv[1]) if len(sys.argv) > 1 else None
    if corpus is None:
        corpus = Path("benchmarks/scaling_corpus")
        make_clean_corpus(corpus / "clean")
        make_fixture_corpus(corpus / "fixtures")
    print(json.dumps(measure(corpus), indent=1))
