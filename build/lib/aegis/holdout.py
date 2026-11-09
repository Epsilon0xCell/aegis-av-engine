"""Sealed hold-out protocol: fixtures the tuner never sees.

The failure mode this prevents: tuning rules against the same
files you report scores on, until the score measures memorisation
instead of detection. The protocol, enforced in code:

1. A hold-out set is generated from a SECRET seed by mutation of
   the same generators that produce the public corpora: random
   prefix/suffix padding, benign line interleaving, filename
   changes, zip wrapping. Patterns stay intact; surfaces change.
2. Before anyone scores it, a COMMITMENT is published: SHA-256
   over the sorted (name, file hash, label) list. The sealed
   manifest stays private to whoever runs the release.
3. Scoring checks the commitment first, scans, reports, and then
   DEMOTES the set: a flag file makes any second scoring run
   refuse. A hold-out is scored exactly once per release, pass or
   fail, and the result is published verbatim. After use, the set
   joins the public tuning corpus and a fresh one is generated.
"""
from __future__ import annotations

import hashlib
import io
import json
import random
import zipfile
from pathlib import Path

from .corpora import CLEAN_FILES, make_fixture_corpus
from .engine import Engine


def _mutate(blob: bytes, rng: random.Random, kind: str) -> bytes:
    pad = bytes(rng.randrange(32, 127) for _ in range(rng.randrange(0, 200)))
    if kind == "prefix":
        return pad + b"\n" + blob
    if kind == "suffix":
        return blob + b"\n" + pad
    if kind == "interleave" and b"\n" in blob:
        lines = blob.split(b"\n")
        lines.insert(rng.randrange(len(lines) + 1),
                     b"benign filler line " + pad[:16])
        return b"\n".join(lines)
    return pad + blob + pad


def generate_holdout(root: Path, seed: int) -> dict:
    root.mkdir(parents=True, exist_ok=True)
    rng = random.Random(seed)
    scratch = root / "_gen"
    fixtures = make_fixture_corpus(scratch)
    entries = []
    for name, label in fixtures.items():
        blob = (scratch / name).read_bytes()
        mutated = _mutate(blob, rng, rng.choice(["prefix", "suffix", "interleave"]))
        out_name = f"holdout_{rng.randrange(10**6):06d}_{name}"
        if rng.random() < 0.3:
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
                zf.writestr(name, mutated)
            (root / (out_name + ".zip")).write_bytes(buf.getvalue())
            entries.append({"file": out_name + ".zip", "label": label,
                            "wrapped": True})
        else:
            (root / out_name).write_bytes(mutated)
            entries.append({"file": out_name, "label": label, "wrapped": False})
    for name, body in CLEAN_FILES.items():
        mutated = _mutate(body.encode(), rng, rng.choice(["prefix", "suffix"]))
        out_name = f"holdout_{rng.randrange(10**6):06d}_{name}"
        (root / out_name).write_bytes(mutated)
        entries.append({"file": out_name, "label": "clean", "wrapped": False})
    for entry in entries:
        entry["sha256"] = hashlib.sha256(
            (root / entry["file"]).read_bytes()).hexdigest()
    manifest = {"seed_commitment": hashlib.sha256(str(seed).encode()).hexdigest(),
                "entries": sorted(entries, key=lambda e: e["file"])}
    (root / "sealed_manifest.json").write_text(json.dumps(manifest, indent=2))
    commitment = commitment_for(manifest, root)
    (root / "commitment.json").write_text(json.dumps(
        {"commitment": commitment, "files": len(entries)}, indent=2))
    import shutil
    shutil.rmtree(scratch)
    return {"commitment": commitment, "files": len(entries)}


def commitment_for(manifest: dict, root: Path) -> str:
    lines = []
    for e in manifest["entries"]:
        digest = hashlib.sha256((root / e["file"]).read_bytes()).hexdigest()
        lines.append(f"{e['file']}:{digest}:{e['label']}")
    return hashlib.sha256("\n".join(sorted(lines)).encode()).hexdigest()


class HoldoutError(Exception):
    pass


def score_holdout(engine: Engine, root: Path) -> dict:
    flag = root / "SCORED.flag"
    if flag.exists():
        raise HoldoutError(
            "this hold-out set was already scored; protocol allows exactly "
            "one scoring per release. Generate a fresh set.")
    manifest = json.loads((root / "sealed_manifest.json").read_text())
    published = json.loads((root / "commitment.json").read_text())["commitment"]
    if commitment_for(manifest, root) != published:
        raise HoldoutError("commitment mismatch: set was altered after commitment")
    tp = fp = fn = tn = 0
    misses = []
    for e in manifest["entries"]:
        verdict = engine.scan_file(root / e["file"])
        flagged = verdict["verdict"] != "clean"
        expected = e["label"] != "clean"
        if flagged and expected:
            tp += 1
        elif flagged and not expected:
            fp += 1
            misses.append({"file": e["file"], "kind": "false_positive"})
        elif not flagged and expected:
            fn += 1
            misses.append({"file": e["file"], "kind": "false_negative"})
        else:
            tn += 1
    flag.write_text("scored\n")
    return {"commitment": published, "tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "misses": misses,
            "note": "Scored exactly once under the hold-out protocol. "
                    "Publish verbatim, pass or fail."}
