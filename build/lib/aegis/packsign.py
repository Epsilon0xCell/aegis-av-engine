"""Signed rule packs with rollback protection.

Signing is asymmetric (Ed25519, implemented in aegis.ed25519 and
verified against the RFC 8032 vectors), never HMAC: anyone holding
a verification key must not be able to forge a pack. The signed
object is a manifest: pack name, version, SHA-256 of the pack
file, a monotonic sequence number, and issue/expiry times.
Rollback protection is the sequence plus expiry, not the
signature alone: the loader keeps a small state file recording
the highest sequence accepted per pack, and refuses anything
older, even if correctly signed.
"""
from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

from . import ed25519


def manifest_for(pack_path: Path, sequence: int, ttl_hours: int = 24 * 30) -> dict:
    doc = json.loads(pack_path.read_text())
    now = int(time.time())
    return {"pack": doc["pack"], "version": doc["version"],
            "sha256": hashlib.sha256(pack_path.read_bytes()).hexdigest(),
            "sequence": sequence, "issued": now,
            "expires": now + ttl_hours * 3600}


def sign_pack(pack_path: Path, seed_hex: str, sequence: int,
              out_path: Path) -> dict:
    seed = bytes.fromhex(seed_hex)
    pk = ed25519.publickey(seed)
    manifest = manifest_for(pack_path, sequence)
    canonical = json.dumps(manifest, sort_keys=True).encode()
    manifest["public_key"] = pk.hex()
    manifest["signature"] = ed25519.signature(canonical, seed, pk).hex()
    out_path.write_text(json.dumps(manifest, indent=2))
    return manifest


class PackVerificationError(Exception):
    pass


def verify_pack(pack_path: Path, manifest_path: Path,
                state_path: Path | None = None,
                now: int | None = None) -> dict:
    manifest = json.loads(manifest_path.read_text())
    canonical = json.dumps({k: manifest[k] for k in
                            ("pack", "version", "sha256", "sequence",
                             "issued", "expires")}, sort_keys=True).encode()
    pk = bytes.fromhex(manifest["public_key"])
    sig = bytes.fromhex(manifest["signature"])
    if not ed25519.checkvalid(sig, canonical, pk):
        raise PackVerificationError("signature does not verify")
    digest = hashlib.sha256(pack_path.read_bytes()).hexdigest()
    if digest != manifest["sha256"]:
        raise PackVerificationError("pack file does not match signed hash")
    now = int(time.time()) if now is None else now
    if now > manifest["expires"]:
        raise PackVerificationError("pack manifest expired")
    if state_path is not None:
        state = {}
        if state_path.exists():
            state = json.loads(state_path.read_text())
        last = state.get(manifest["pack"], -1)
        if manifest["sequence"] <= last:
            raise PackVerificationError(
                f"rollback refused: sequence {manifest['sequence']} <= {last}")
        state[manifest["pack"]] = manifest["sequence"]
        state_path.write_text(json.dumps(state))
    return manifest
