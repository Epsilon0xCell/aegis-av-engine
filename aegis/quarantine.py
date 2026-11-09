"""Quarantine and restore, with receipts. Operates on any path the
user explicitly scans and chooses to quarantine; in this project's
own tests and benchmarks that is always corpus files."""
from __future__ import annotations

import hashlib
import json
import shutil
import time
from pathlib import Path


def quarantine_file(path: Path, qdir: Path, reason: str) -> dict:
    qdir.mkdir(parents=True, exist_ok=True)
    blob = path.read_bytes()
    dest = qdir / path.name
    shutil.move(str(path), str(dest))
    receipt = {"file": path.name, "original_path": str(path),
               "quarantine_path": str(dest), "reason": reason,
               "sha256": hashlib.sha256(blob).hexdigest(),
               "when": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    (qdir / f"{path.name}.receipt.json").write_text(json.dumps(receipt, indent=2))
    return receipt


def restore_file(name: str, qdir: Path) -> Path:
    receipt = json.loads((qdir / f"{name}.receipt.json").read_text())
    dest = Path(receipt["original_path"])
    shutil.move(str(qdir / name), str(dest))
    return dest
