"""Command line: aegis scan <path> | aegis benchmark | aegis demo"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from .benchmark import run_benchmark
from .corpora import write_manifests
from .engine import Engine
from .rules import RulePack

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_PACK = ROOT / "rules" / "core_rules.json"


def _engine() -> Engine:
    return Engine(RulePack(DEFAULT_PACK))


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args:
        print(__doc__)
        return 2
    cmd = args[0]
    engine = _engine()
    if cmd == "scan" and len(args) == 2:
        target = Path(args[1])
        results = (engine.scan_tree(target) if target.is_dir()
                   else [engine.scan_file(target)])
        print(json.dumps(results, indent=2))
        return 0
    if cmd == "demo":
        corpus = ROOT / "benchmarks" / "corpus"
        manifest = write_manifests(corpus)
        print(json.dumps(run_benchmark(engine, corpus, manifest), indent=2))
        return 0
    if cmd == "benchmark":
        corpus = ROOT / "benchmarks" / "corpus"
        if not (corpus / "manifest.json").exists():
            write_manifests(corpus)
        manifest = json.loads((corpus / "manifest.json").read_text())
        report = run_benchmark(engine, corpus, manifest)
        out = ROOT / "benchmarks" / "results_local.json"
        out.write_text(json.dumps(report, indent=2))
        print(json.dumps(report, indent=2))
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
