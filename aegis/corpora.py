"""Corpus generation: clean files and SYNTHETIC malicious-pattern fixtures.

No real malware exists in this project, in any form. The fixture
corpus is generated here, from marker strings invented for this
project, so the full ground truth is reproducible from source. The
clean corpus is generated text, data and tiny well-formed files of
known provenance. EICAR appears as the standard AV smoke test, the
one globally sanctioned exception, and is labelled as such.
"""
from __future__ import annotations

import json
import random
from pathlib import Path

EICAR = (r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")

CLEAN_FILES = {
    "readme.txt": "Project notes. Ordinary prose about scanning engines, "
                  "benchmarks and detection engineering. " * 8,
    "notes.md": "# Meeting notes\n\nDiscussed corpus design and false positives.\n" * 6,
    "data.csv": "name,score\nalpha,10\nbeta,20\ngamma,30\n" * 10,
    "script_ok.py": "def add(a, b):\n    return a + b\n\nprint(add(2, 3))\n",
    "config.json": json.dumps({"engine": "aegis", "offline": True, "rules": 4}, indent=2),
    "essay.txt": "The quick brown fox studies detection engineering at length. " * 40,
}


def make_clean_corpus(root: Path, variants: int = 4) -> dict:
    root.mkdir(parents=True, exist_ok=True)
    manifest = {}
    rng = random.Random(7)
    for name, body in CLEAN_FILES.items():
        (root / name).write_text(body)
        manifest[name] = "clean"
        for i in range(variants):
            vname = f"{Path(name).stem}_v{i}{Path(name).suffix}"
            (root / vname).write_text(body + f"\n benign variant {i} {rng.random()}\n")
            manifest[vname] = "clean"
    return manifest


def make_fixture_corpus(root: Path) -> dict:
    root.mkdir(parents=True, exist_ok=True)
    fixtures = {
        "fixture_ransomware_pattern.bin":
            b"INERT FIXTURE\nAEGIS-SYNTHETIC-RANSOMWARE-PATTERN\n" + b"A" * 256,
        "fixture_keylog_pattern.txt":
            "LAB-SYNTHETIC-KEYLOG-FIXTURE\nsynthetic invented content\n".encode(),
        "fixture_script_dropper.ps1":
            ("# inert fixture\nAEGIS-SYNTH-download-cradle\n"
             "AEGIS-SYNTH-hidden-window\nAEGIS-SYNTH-persist-run-key\n").encode(),
        "fixture_high_entropy.bin": bytes(random.Random(3).randrange(256)
                                          for _ in range(4096)),
        "eicar_test_file.txt": EICAR.encode(),
    }
    manifest = {}
    for name, blob in fixtures.items():
        (root / name).write_bytes(blob)
        manifest[name] = ("smoke_test" if name.startswith("eicar")
                          else "malicious_pattern_fixture")
    return manifest


def write_manifests(base: Path) -> dict:
    clean = make_clean_corpus(base / "clean")
    fixtures = make_fixture_corpus(base / "fixtures")
    full = {**{f"clean/{k}": v for k, v in clean.items()},
            **{f"fixtures/{k}": v for k, v in fixtures.items()}}
    (base / "manifest.json").write_text(json.dumps(full, indent=2))
    return full
