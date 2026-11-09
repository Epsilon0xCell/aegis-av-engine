"""Hashing: exact digests, a bloom pre-filter, and a fuzzy digest."""
from __future__ import annotations

import hashlib


def digests(data: bytes) -> dict[str, str]:
    return {"sha256": hashlib.sha256(data).hexdigest(),
            "md5": hashlib.md5(data, usedforsecurity=False).hexdigest()}


class BloomFilter:
    """Simple deterministic bloom filter over exact hashes.

    Purpose in the pipeline: a cheap negative check. If a file's
    sha256 is definitely not in the known-bad set, the expensive
    exact lookup can be skipped, and on a large clean corpus that is
    most files, most of the time.
    """

    def __init__(self, size_bits: int = 1 << 16, hashes: int = 4) -> None:
        self.size = size_bits
        self.k = hashes
        self.bits = bytearray(size_bits // 8)

    def _positions(self, item: str):
        h = hashlib.sha256(item.encode()).digest()
        a = int.from_bytes(h[:8], "big")
        b = int.from_bytes(h[8:16], "big")
        for i in range(self.k):
            yield (a + i * b) % self.size

    def add(self, item: str) -> None:
        for p in self._positions(item):
            self.bits[p // 8] |= 1 << (p % 8)

    def __contains__(self, item: str) -> bool:
        return all(self.bits[p // 8] & (1 << (p % 8)) for p in self._positions(item))


_B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def fuzzy_digest(data: bytes, block: int = 48) -> str:
    """A small ssdeep-style fuzzy digest (documented as our own).

    Rolls over fixed blocks, emitting one base64 character per block
    from the block hash. Near-identical inputs share long common
    substrings, which is the property fuzzy matching relies on. This
    is a teaching implementation, not ssdeep or TLSH, and similarity
    is computed as a longest-common-substring ratio.
    """
    if not data:
        return "0:"
    chars = []
    for i in range(0, len(data), block):
        h = hashlib.sha256(data[i:i + block]).digest()[0]
        chars.append(_B64[h % 64])
    return f"{block}:" + "".join(chars)


def fuzzy_similarity(a: str, b: str) -> float:
    """Ratio of the longest common substring to the longer digest."""
    da, db = a.split(":", 1)[-1], b.split(":", 1)[-1]
    if not da or not db:
        return 0.0
    best = 0
    prev = [0] * (len(db) + 1)
    for i in range(1, len(da) + 1):
        cur = [0] * (len(db) + 1)
        for j in range(1, len(db) + 1):
            if da[i - 1] == db[j - 1]:
                cur[j] = prev[j - 1] + 1
                best = max(best, cur[j])
        prev = cur
    return round(best / max(len(da), len(db)), 4)
