"""Command line: aegis scan <path> | aegis benchmark | aegis demo | aegis lint"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from .benchmark import run_benchmark
from .corpora import write_manifests
from .engine import Engine
from .rules import RulePack

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_PACK = ROOT / "rules" / "core_rules_v2.json"


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
        if not target.exists():
            print(f"error: no such file or directory: {target}",
                  file=sys.stderr)
            return 2
        results = (engine.scan_tree(target) if target.is_dir()
                   else [engine.scan_file(target)])
        print(json.dumps(results, indent=2))
        return 0
    if cmd == "serve":
        from .daemon import serve
        port = int(args[1]) if len(args) > 1 else 8765
        print(f"Aegis daemon on http://127.0.0.1:{port} (user-space, notify/scan only, never blocking)")
        serve(Engine(RulePack(DEFAULT_PACK)), port=port)
        return 0
    if cmd == "watch":
        from .watch import watch_directory
        if len(args) < 2:
            print("usage: aegis watch <directory> [seconds]")
            return 2
        seconds = float(args[2]) if len(args) > 2 else 30.0
        events = watch_directory(Path(args[1]),
                                 Engine(RulePack(DEFAULT_PACK)), seconds)
        print(json.dumps(events, indent=2))
        return 0
    if cmd == "parscan":
        from .parscan import report_json, scan_directory
        if len(args) < 2:
            print("usage: aegis parscan <directory> [workers]")
            return 2
        workers = int(args[2]) if len(args) > 2 else 4
        print(report_json(scan_directory(Path(args[1]), DEFAULT_PACK,
                                         workers=workers)))
        return 0
    if cmd == "report" and len(args) == 3:
        from .html_report import render_report
        from .parscan import scan_directory
        report = scan_directory(Path(args[1]), DEFAULT_PACK, workers=4)
        Path(args[2]).write_text(render_report(report))
        print(f"wrote {args[2]} ({report['files']} files)")
        return 0
    if cmd == "sbom" and len(args) == 2:
        from . import __version__
        from .sbom import sbom_json
        print(sbom_json(Path(args[1]), "aegis-av-engine", __version__))
        return 0
    if cmd == "lint":
        from .rulelint import lint_pack
        problems = lint_pack(DEFAULT_PACK, ROOT / "rules" / "rule_tests.json")
        print(json.dumps({"pack": str(DEFAULT_PACK), "problems": problems}, indent=2))
        return 1 if problems else 0
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
