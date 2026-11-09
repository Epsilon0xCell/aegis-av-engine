"""Aho-Corasick multi-pattern string engine.

Commercial engines match millions of byte patterns per file; the
algorithm that makes that fast is Aho-Corasick: one pass over the
input, all patterns at once, cost independent of pattern count.
This is a compact, correct implementation used for the rule
engine's byte-pattern conditions, with automaton statistics exposed
so performance discussions can cite real numbers.
"""
from __future__ import annotations

from collections import deque


class AhoCorasick:
    def __init__(self) -> None:
        self.goto: list[dict[int, int]] = [{}]
        self.fail: list[int] = [0]
        self.out: list[list[str]] = [[]]
        self.pattern_count = 0

    def add(self, pattern: bytes, tag: str) -> None:
        node = 0
        for byte in pattern:
            nxt = self.goto[node].get(byte)
            if nxt is None:
                nxt = len(self.goto)
                self.goto[node][byte] = nxt
                self.goto.append({})
                self.fail.append(0)
                self.out.append([])
            node = nxt
        self.out[node].append(tag)
        self.pattern_count += 1

    def build(self) -> None:
        queue: deque[int] = deque()
        for byte, node in self.goto[0].items():
            self.fail[node] = 0
            queue.append(node)
        while queue:
            r = queue.popleft()
            for byte, s in self.goto[r].items():
                queue.append(s)
                state = self.fail[r]
                while state and byte not in self.goto[state]:
                    state = self.fail[state]
                self.fail[s] = self.goto[state].get(byte, 0)
                self.out[s].extend(self.out[self.fail[s]])

    def search(self, data: bytes) -> dict[str, int]:
        """Return {tag: hit_count} for every pattern found in data."""
        hits: dict[str, int] = {}
        node = 0
        for byte in data:
            while node and byte not in self.goto[node]:
                node = self.fail[node]
            node = self.goto[node].get(byte, 0)
            for tag in self.out[node]:
                hits[tag] = hits.get(tag, 0) + 1
        return hits

    def feed(self, state: int, chunk: bytes) -> tuple[dict[str, int], int]:
        """Incremental search: carry the automaton state across
        chunks. Hits are identical to search() over the concatenated
        stream for ANY chunking, because the state is one integer;
        the equivalence is property-tested in the suite."""
        hits: dict[str, int] = {}
        node = state
        for byte in chunk:
            while node and byte not in self.goto[node]:
                node = self.fail[node]
            node = self.goto[node].get(byte, 0)
            for tag in self.out[node]:
                hits[tag] = hits.get(tag, 0) + 1
        return hits, node

    @property
    def state_count(self) -> int:
        return len(self.goto)
