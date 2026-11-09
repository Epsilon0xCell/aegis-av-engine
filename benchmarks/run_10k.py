"""10,000-file corpus benchmark (v2 protocol).

Generates a documented corpus (the manifest is the claim):
9,500 clean files (text, JSON, CSV, small binaries, tiny PEs,
zips) and 500 fixture files, then scans with the parallel
scanner and a single-process pass, reporting throughput,
per-file latency distribution, peak RSS, and the slowest files.
Local teaching numbers, labelled as such; release claims use
the per-OS CI figures instead.
"""
import json
import random
import resource
import sys
import time
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from aegis.calibration import _cal_pe  # noqa: E402
from aegis.corpora import EICAR  # noqa: E402
from aegis.engine import Engine  # noqa: E402
from aegis.parscan import scan_directory  # noqa: E402
from aegis.rules import RulePack  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
PACK = ROOT / "rules" / "core_rules_v2.json"


def generate(root: Path) -> dict:
    rng = random.Random(20261113)
    root.mkdir(parents=True, exist_ok=True)
    counts = {"clean": 0, "fixture": 0}
    words = ("report meeting budget alpha beta gamma delta "
             "summary analysis ordinary prose line").split()
    for i in range(9500):
        kind = i % 10
        if kind < 5:
            p = root / f"doc_{i:05d}.txt"
            p.write_text(" ".join(rng.choices(words, k=rng.randrange(50, 400))))
        elif kind < 7:
            p = root / f"data_{i:05d}.json"
            p.write_text(json.dumps({"i": i, "values": [rng.random()
                                                        for _ in range(20)]}))
        elif kind == 7:
            p = root / f"blob_{i:05d}.bin"
            p.write_bytes(bytes(rng.randrange(0, 64)
                                for _ in range(rng.randrange(100, 2000))))
        elif kind == 8:
            p = root / f"app_{i:05d}.exe"
            p.write_bytes(_cal_pe(rng, timestamp=0x5E2A5A00,
                                  section_blob=bytes(256)))
        else:
            p = root / f"arc_{i:05d}.zip"
            with zipfile.ZipFile(p, "w") as z:
                z.writestr("inner.txt", "ordinary content " * 10)
        counts["clean"] += 1
    for i in range(500):
        kind = i % 4
        if kind == 0:
            p = root / f"fix_{i:05d}.bin"
            p.write_bytes(b"AEGIS-SYNTHETIC-RANSOMWARE-PATTERN\n" + b"A" * 200)
        elif kind == 1:
            p = root / f"fix_{i:05d}.bin"
            p.write_bytes(bytes(rng.randrange(256) for _ in range(4096)))
        elif kind == 2:
            p = root / f"fix_{i:05d}.txt"
            p.write_text(EICAR)
        else:
            p = root / f"fix_{i:05d}.bin"
            p.write_bytes(b"LAB-SYNTHETIC-KEYLOG-FIXTURE\n" + b"x" * 100)
        counts["fixture"] += 1
    return counts


def main() -> int:
    corpus = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("/tmp/aegis-10k")
    counts = generate(corpus)
    total_bytes = sum(p.stat().st_size for p in corpus.rglob("*") if p.is_file())
    t0 = time.perf_counter()
    report = scan_directory(corpus, PACK, workers=4)
    par_seconds = time.perf_counter() - t0
    engine = Engine(RulePack(PACK))
    lat = []
    for p in sorted(corpus.rglob("*")):
        if p.is_file():
            s = time.perf_counter()
            engine.scan_file(p)
            lat.append((time.perf_counter() - s, p.name))
    lat.sort()
    times = [t for t, _ in lat]
    out = {
        "corpus": counts, "files": report["files"],
        "total_bytes": total_bytes,
        "parallel_workers": 4,
        "parallel_seconds": round(par_seconds, 3),
        "parallel_files_per_sec": round(report["files"] / par_seconds, 2),
        "single_process_median_ms": round(times[len(times) // 2] * 1000, 3),
        "single_process_p95_ms": round(times[int(len(times) * 0.95)] * 1000, 3),
        "peak_rss_mb": round(resource.getrusage(
            resource.RUSAGE_SELF).ru_maxrss / 1024, 1),
        "slowest_10": [{"file": n, "ms": round(t * 1000, 2)}
                       for t, n in lat[-10:][::-1]],
        "summary_parallel": report["summary"],
        "scope": "local run on generated corpus; see BENCHMARK.md protocol",
    }
    print(json.dumps(out, indent=1))
    (ROOT / "benchmarks" / "results_10k_v3_local.json").write_text(
        json.dumps(out, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
