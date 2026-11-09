"""PrefixSpan mining over behaviour telemetry: candidates only.

Frequent-sequence mining is how new chains are DISCOVERED; it
is not how anything gets DETECTED. This module implements
PrefixSpan with projected databases over sessionised telemetry
(event keys of the form "action:technique"), returning
CandidatePattern objects: a distinct type, deliberately not
the dict shape the correlator consumes, so miner output cannot
flow into detection without a human rewriting it as a weighted
chain with fixtures. A type-level test enforces the wall.

Semantics: subsequence matching (gaps allowed), support counted
in sessions, patterns bounded by max_len, and closed-pattern
filtering (a pattern whose superpattern has identical support
adds no information and is dropped).
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CandidatePattern:
    pattern: tuple[str, ...]
    support: int
    status: str = "candidate_requires_human_promotion"

    def to_dict(self) -> dict:
        return {"pattern": list(self.pattern), "support": self.support,
                "status": self.status}


def _project(sessions: list[list[str]], prefix: tuple[str, ...]):
    """Projected database: (session_index, next_position) pairs
    for sessions containing prefix as a subsequence."""
    projected = []
    for idx, session in enumerate(sessions):
        pos = 0
        ok = True
        for item in prefix:
            found = None
            while pos < len(session):
                if session[pos] == item:
                    found = pos
                    break
                pos += 1
            if found is None:
                ok = False
                break
            pos = found + 1
        if ok:
            projected.append((idx, pos))
    return projected


def mine(sessions: list[list[str]], min_support: int,
         max_len: int = 5) -> list[CandidatePattern]:
    sessions = [list(s) for s in sessions]
    found: dict[tuple[str, ...], int] = {}

    def grow(prefix: tuple[str, ...], projected):
        support = len(projected)
        if support < min_support:
            return
        if prefix:
            found[prefix] = support
        if len(prefix) >= max_len:
            return
        candidates: dict[str, list] = {}
        for sidx, pos in projected:
            seen: set[str] = set()
            for item in sessions[sidx][pos:]:
                if item not in seen:
                    seen.add(item)
                    candidates.setdefault(item, []).append(sidx)
        for item in sorted(candidates):
            sub = _project_from(sessions, projected, item)
            if len(sub) >= min_support:
                grow(prefix + (item,), sub)

    def _project_from(sess, projected, item):
        out = []
        for sidx, pos in projected:
            p = pos
            while p < len(sess[sidx]):
                if sess[sidx][p] == item:
                    out.append((sidx, p + 1))
                    break
                p += 1
        return out

    items: dict[str, int] = {}
    for s in sessions:
        for item in set(s):
            items[item] = items.get(item, 0) + 1
    for item in sorted(items):
        if items[item] >= min_support:
            grow((item,), _project(sessions, (item,)))
    # closed filtering: drop patterns with a same-support
    # superpattern present in the result set
    patterns = sorted(found, key=lambda p: (len(p), p))
    closed = []
    for pat in patterns:
        pset = list(pat)
        subsumed = False
        for other in patterns:
            if len(other) <= len(pat) or found[other] != found[pat]:
                continue
            it = iter(other)
            if all(any(x == y for y in it) for x in pset):
                subsumed = True
                break
        if not subsumed:
            closed.append(CandidatePattern(pat, found[pat]))
    return sorted(closed, key=lambda c: (-c.support, c.pattern))
