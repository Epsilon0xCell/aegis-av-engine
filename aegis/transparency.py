"""Append-only transparency log for rule packs (Merkle tree).

Modelled on Sigsum and Certificate Transparency (RFC 6962 tree
mathematics), scaled to what a local project can honestly run:
pack manifests are leaves, tree heads are Ed25519-signed, and
the log provides inclusion proofs (this manifest is in the log)
and consistency proofs (the log only ever grew; earlier entries
were not rewritten). Hashing follows the RFC: leaf
SHA256(0x00 || data), node SHA256(0x01 || left || right), split
at the largest power of two below the tree size.

The honest limit is in the name of the thing this is not: until
an independent witness cosigns tree heads, this proves
SELF-consistency (nobody can rewrite this log's history without
breaking a proof), not public transparency. The module says so,
because a log only its operator can check is evidence of a
weaker, still useful kind, and labelling it correctly is the
difference between engineering and marketing.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from . import ed25519

EMPTY_ROOT = hashlib.sha256(b"").hexdigest()


def _leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def _node(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _split(n: int) -> int:
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def _mth(leaves: list[bytes]) -> bytes:
    if not leaves:
        return hashlib.sha256(b"").digest()
    if len(leaves) == 1:
        return _leaf_hash(leaves[0])
    k = _split(len(leaves))
    return _node(_mth(leaves[:k]), _mth(leaves[k:]))


def _inclusion_path(index: int, leaves: list[bytes]) -> list[bytes]:
    if len(leaves) == 1:
        return []
    k = _split(len(leaves))
    if index < k:
        return _inclusion_path(index, leaves[:k]) + [_mth(leaves[k:])]
    return _inclusion_path(index - k, leaves[k:]) + [_mth(leaves[:k])]


def _subproof(m: int, leaves: list[bytes], b: bool) -> list[bytes]:
    n = len(leaves)
    if m == n:
        return [] if b else [_mth(leaves)]
    k = _split(n)
    if m <= k:
        return _subproof(m, leaves[:k], b) + [_mth(leaves[k:])]
    return _subproof(m - k, leaves[k:], False) + [_mth(leaves[:k])]


def verify_inclusion(leaf_data: bytes, index: int, tree_size: int,
                     proof: list[str], root_hex: str) -> bool:
    def rec(idx: int, size: int, path: list[bytes]) -> bytes:
        if size == 1:
            if path:
                raise ValueError("path too long")
            return _leaf_hash(leaf_data)
        k = _split(size)
        sibling = path[-1]
        if idx < k:
            left = rec(idx, k, path[:-1])
            return _node(left, sibling)
        right = rec(idx - k, size - k, path[:-1])
        return _node(sibling, right)

    if tree_size == 0 or index >= tree_size:
        return False
    try:
        computed = rec(index, tree_size, [bytes.fromhex(p) for p in proof])
    except (ValueError, IndexError):
        return False
    return computed.hex() == root_hex


def verify_consistency(first: int, second: int, root1_hex: str,
                       root2_hex: str, proof: list[str]) -> bool:
    """Consistency verification that mirrors the proof's own
    recursion: the proof nodes are consumed in generation order
    to rebuild BOTH roots, and the check passes only if the
    rebuilt roots equal the claimed ones and every proof node is
    consumed. (An iterative RFC-style verifier was tried first
    and failed its sweep; this structural verifier passes the
    full sweep in the tests, which is the one that ships.)"""
    try:
        path = [bytes.fromhex(p) for p in proof]
        root1 = bytes.fromhex(root1_hex)
        root2 = bytes.fromhex(root2_hex)
    except ValueError:
        return False
    if first == second:
        return not path and root1 == root2
    if first == 0:
        return not path and root1_hex == EMPTY_ROOT
    stream = iter(path)
    consumed = [0]

    def take() -> bytes:
        consumed[0] += 1
        return next(stream)

    def consume(m: int, n: int, b: bool, root_m):
        if m == n:
            if b:
                return root_m, root_m
            h = take()
            return h, h
        k = _split(n)
        if m <= k:
            rm, rk = consume(m, k, b, root_m)
            right = take()
            return rm, _node(rk, right)
        rm_right, rn_right = consume(m - k, n - k, False, None)
        left = take()
        return _node(left, rm_right), _node(left, rn_right)

    try:
        rm, rn = consume(first, second, True, root1)
    except StopIteration:
        return False
    return (consumed[0] == len(path) and rm == root1 and rn == root2)


class TransparencyLog:
    def __init__(self, path: Path, signing_seed: bytes | None = None) -> None:
        self.path = Path(path)
        self.seed = signing_seed
        if self.path.exists():
            doc = json.loads(self.path.read_text())
            self.leaves = [bytes.fromhex(x) for x in doc["leaves"]]
        else:
            self.leaves: list[bytes] = []

    def _save(self) -> None:
        self.path.write_text(json.dumps(
            {"leaves": [leaf.hex() for leaf in self.leaves]}, indent=1))

    def append(self, manifest: dict) -> dict:
        data = json.dumps(manifest, sort_keys=True,
                          separators=(",", ":")).encode()
        self.leaves.append(data)
        self._save()
        return self.tree_head()

    def root(self, size: int | None = None) -> str:
        leaves = self.leaves if size is None else self.leaves[:size]
        return _mth(leaves).hex()

    def tree_head(self) -> dict:
        head = {"tree_size": len(self.leaves), "root": self.root(),
                "witness": "none (self-consistency only)"}
        if self.seed is not None:
            pk = ed25519.publickey(self.seed)
            msg = f"{head['tree_size']}:{head['root']}".encode()
            head["signature"] = ed25519.signature(msg, self.seed, pk).hex()
            head["public_key"] = pk.hex()
        return head

    def inclusion_proof(self, index: int) -> list[str]:
        return [h.hex() for h in _inclusion_path(index, self.leaves)]

    def consistency_proof(self, first: int) -> list[str]:
        return [h.hex() for h in _subproof(first, self.leaves, True)]

    def verify_head_signature(self, head: dict) -> bool:
        if "signature" not in head:
            return False
        msg = f"{head['tree_size']}:{head['root']}".encode()
        return ed25519.checkvalid(bytes.fromhex(head["signature"]),
                                  msg, bytes.fromhex(head["public_key"]))
