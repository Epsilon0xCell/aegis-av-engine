"""Deterministic source zip: the reproducible-build artifact.

Every entry is written with a fixed timestamp (SOURCE_DATE_EPOCH
if set, else the zip epoch 1980-01-01), fixed permissions, and
sorted paths, using only the standard library, so two builds of
the same tree produce byte-identical zips on any machine. CI
builds it twice and compares SHA-256; that comparison, plus the
build-provenance attestation on the release, is the project's
supply-chain claim, stated at exactly the strength it has.
"""
import hashlib
import os
import sys
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
INCLUDE_DIRS = ("aegis", "rules", "sigma_json", "tests", "docs",
                "scripts", ".github")
INCLUDE_FILES = ("README.md", "BENCHMARK.md", "CHANGELOG.md",
                 "LICENSE", "pyproject.toml")
INCLUDE_GLOBS = ("benchmarks/*.json", "benchmarks/*.md",
                 "benchmarks/*.py")


def collect() -> list[Path]:
    files: set[Path] = set()
    for d in INCLUDE_DIRS:
        for p in (ROOT / d).rglob("*"):
            if p.is_file() and "__pycache__" not in p.parts:
                files.add(p)
    for f in INCLUDE_FILES:
        if (ROOT / f).exists():
            files.add(ROOT / f)
    for g in INCLUDE_GLOBS:
        files.update(p for p in ROOT.glob(g) if p.is_file())
    return sorted(files, key=lambda p: p.relative_to(ROOT).as_posix())


def main() -> int:
    import re
    m = re.search(r'__version__\s*=\s*"([^"]+)"',
                  (ROOT / "aegis" / "__init__.py").read_text())
    version = m.group(1)
    epoch = int(os.environ.get("SOURCE_DATE_EPOCH", "315532800"))
    stamp = datetime.fromtimestamp(epoch, timezone.utc)
    date_time = (stamp.year, stamp.month, stamp.day,
                 stamp.hour, stamp.minute, stamp.second)
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else \
        ROOT / "dist" / f"aegis-av-engine-{version}-source.zip"
    out.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED,
                         compresslevel=9) as z:
        for p in collect():
            arc = p.relative_to(ROOT).as_posix()
            info = zipfile.ZipInfo(arc, date_time=date_time)
            info.create_system = 3
            info.external_attr = 0o644 << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(info, p.read_bytes(), compresslevel=9)
    digest = hashlib.sha256(out.read_bytes()).hexdigest()
    print(f"{out} sha256={digest} files={len(collect())}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
