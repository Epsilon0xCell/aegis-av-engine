"""TUF-lite pack update client: freeze and rollback protection.

Two signed documents guard a pack update, borrowing TUF's
shape at deliberately reduced scope (no snapshot role, no
delegations, no threshold root: the non-goals are named in the
v3 plan):

- root.json carries the current signing key and the NEXT key,
  a key sequence number, and is signed by the current key. A
  rotation is a new root, signed by the old key, whose current
  key equals the old root's next key, with the sequence
  advanced by exactly one.
- timestamp.json names the pack version, its SHA-256, a pack
  sequence, and an expiry measured in hours, signed by the
  current key. An expired timestamp refuses the update: that
  is the freeze protection. A pack sequence at or below the
  highest accepted refuses it: that is rollback protection.

State is a small local JSON file. First install is
trust-on-first-use and the state says so; every later step is
verified against it.
"""
from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

from . import ed25519


class UpdateError(ValueError):
    pass


def _canon(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def make_root(seed: bytes, next_seed: bytes | None,
              key_sequence: int) -> dict:
    doc = {"version": 1, "key_sequence": key_sequence,
           "current_key": ed25519.publickey(seed).hex(),
           "next_key": (ed25519.publickey(next_seed).hex()
                        if next_seed else None)}
    doc["signature"] = ed25519.signature(_canon(
        {k: v for k, v in doc.items()}), seed,
        bytes.fromhex(doc["current_key"])).hex()
    return doc


def make_timestamp(seed: bytes, current_key_hex: str, pack_version: str,
                   pack_bytes: bytes, sequence: int,
                   ttl_hours: int = 72, now: float | None = None) -> dict:
    now = time.time() if now is None else now
    doc = {"pack_version": pack_version,
           "pack_sha256": hashlib.sha256(pack_bytes).hexdigest(),
           "sequence": sequence, "issued": int(now),
           "expires": int(now + ttl_hours * 3600)}
    doc["signature"] = ed25519.signature(
        _canon({k: v for k, v in doc.items()}), seed,
        bytes.fromhex(current_key_hex)).hex()
    return doc


def _check_sig(doc: dict, key_hex: str, what: str) -> None:
    body = {k: v for k, v in doc.items() if k != "signature"}
    try:
        ok = ed25519.checkvalid(bytes.fromhex(doc["signature"]),
                                _canon(body), bytes.fromhex(key_hex))
    except Exception:
        ok = False
    if not ok:
        raise UpdateError(f"{what} signature does not verify")


def verify_and_update(state_path: Path, root: dict, timestamp: dict,
                      pack_bytes: bytes, now: float | None = None) -> dict:
    now = time.time() if now is None else now
    state = (json.loads(Path(state_path).read_text())
             if Path(state_path).exists() else None)
    # root chain
    if state is None:
        _check_sig(root, root["current_key"], "root")
        trusted_key = root["current_key"]
        root_seq = root["key_sequence"]
        highest = 0
        first = True
    else:
        _check_sig(root, state["current_key"], "root")
        if root["key_sequence"] != state["root_sequence"] + 1 \
                and root["key_sequence"] != state["root_sequence"]:
            raise UpdateError(
                "root key_sequence does not advance by one "
                "(rollback or skipped rotation)")
        if root["key_sequence"] == state["root_sequence"] + 1:
            expected = state.get("next_key") or state["current_key"]
            if root["current_key"] != expected:
                raise UpdateError(
                    "rotated root's current key is not the previously "
                    "announced next key")
        elif root["current_key"] != state["current_key"]:
            raise UpdateError("root key changed without rotation")
        trusted_key = root["current_key"]
        root_seq = root["key_sequence"]
        highest = state["highest_pack_sequence"]
        first = False
    # timestamp
    _check_sig(timestamp, trusted_key, "timestamp")
    if timestamp["expires"] < now:
        raise UpdateError("timestamp expired (freeze protection)")
    if timestamp["sequence"] <= highest:
        raise UpdateError(
            f"pack sequence {timestamp['sequence']} at or below the "
            f"highest accepted {highest} (rollback protection)")
    if hashlib.sha256(pack_bytes).hexdigest() != timestamp["pack_sha256"]:
        raise UpdateError("pack bytes do not match the signed hash")
    new_state = {"current_key": trusted_key,
                 "next_key": root.get("next_key"),
                 "root_sequence": root_seq,
                 "highest_pack_sequence": timestamp["sequence"],
                 "pack_version": timestamp["pack_version"],
                 "trust_on_first_use": first,
                 "updated_at": int(now)}
    Path(state_path).write_text(json.dumps(new_state, indent=1))
    return new_state
