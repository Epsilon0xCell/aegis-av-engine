"""Witness cosignatures for the transparency log, offline.

A transparency tree head signed only by its operator proves
self-consistency, nothing more. Witnesses are independent
parties who countersign a head they have seen; a policy file
names the recognised witnesses and the quorum. This module
defines the cosignature format, a cosign helper (the offline
tool a witness would run), and quorum verification against a
policy. Until a real second party cosigns a head from this
project, the honest claim is "witness-ready": the format and
verification exist and are tested with generated keys, and no
external witness is claimed.
"""
from __future__ import annotations

from . import ed25519

DOMAIN = "aegis-witness-cosign:v1"


def _message(tree_size: int, root_hex: str) -> bytes:
    return f"{DOMAIN}:{tree_size}:{root_hex}".encode()


def cosign(tree_head: dict, witness_name: str, seed: bytes) -> dict:
    size, root = tree_head["tree_size"], tree_head["root"]
    pk = ed25519.publickey(seed)
    return {"witness": witness_name, "public_key": pk.hex(),
            "tree_size": size, "root": root,
            "signature": ed25519.signature(
                _message(size, root), seed, pk).hex()}


def verify_cosignatures(tree_head: dict, cosigs: list[dict],
                        policy: dict) -> dict:
    """policy: {"witnesses": {name: public_key_hex}, "quorum": k}"""
    recognised = policy.get("witnesses", {})
    quorum = policy.get("quorum", 1)
    valid: list[str] = []
    problems: list[str] = []
    seen: set[str] = set()
    for c in cosigs:
        name = c.get("witness")
        if name in seen:
            problems.append(f"duplicate cosignature from {name}")
            continue
        seen.add(name)
        if recognised.get(name) != c.get("public_key"):
            problems.append(f"unrecognised witness {name}")
            continue
        if c.get("tree_size") != tree_head["tree_size"] \
                or c.get("root") != tree_head["root"]:
            problems.append(f"{name} cosigned a different tree head")
            continue
        try:
            ok = ed25519.checkvalid(
                bytes.fromhex(c["signature"]),
                _message(c["tree_size"], c["root"]),
                bytes.fromhex(c["public_key"]))
        except Exception:
            ok = False
        if ok:
            valid.append(name)
        else:
            problems.append(f"{name} signature does not verify")
    return {"ok": len(valid) >= quorum, "valid": valid,
            "quorum": quorum, "problems": problems,
            "claim": "witness-ready format; quorum counts only "
                     "policy-recognised witnesses"}
