"""Segmented (windowed) entropy: the anti-dilution measurement.

One global entropy number is dilutable by construction: append
enough benign text and any high-entropy region averages away.
The published padding-attack literature (Kolosnjaji et al. on
MalConv; the GAMMA work on benign-content injection) exploits
exactly that. The defence used here follows the EMBER tradition:
entropy over sliding windows (2,048-byte windows, 1,024-byte
step), reported as a distribution: maximum, 90th percentile,
fraction of windows at or above 7.0, and the longest run of hot
windows. The maximum and the run length are monotone under
appending: padding can add cool windows, it cannot cool a hot
one that is already there. That property is what the tests pin.
"""
from __future__ import annotations

from .formats import shannon_entropy

WINDOW = 2048
STEP = 1024
HOT = 7.0


def window_entropies(data: bytes, window: int = WINDOW, step: int = STEP) -> list[float]:
    if not data:
        return []
    if len(data) <= window:
        return [shannon_entropy(data)]
    out = []
    for start in range(0, len(data) - window + 1, step):
        out.append(shannon_entropy(data[start:start + window]))
    tail = data[len(data) - window:]
    if (len(data) - window) % step:
        out.append(shannon_entropy(tail))
    return out


def segmented_stats(data: bytes) -> dict:
    ents = window_entropies(data)
    if not ents:
        return {"windows": 0, "max": 0.0, "p90": 0.0, "mean": 0.0,
                "frac_ge_7": 0.0, "longest_hot_run": 0}
    ordered = sorted(ents)
    p90 = ordered[min(len(ordered) - 1, int(0.9 * len(ordered)))]
    hot = [e >= HOT for e in ents]
    longest = run = 0
    for h in hot:
        run = run + 1 if h else 0
        longest = max(longest, run)
    return {"windows": len(ents), "max": round(max(ents), 4),
            "p90": round(p90, 4),
            "mean": round(sum(ents) / len(ents), 4),
            "frac_ge_7": round(sum(hot) / len(ents), 4),
            "longest_hot_run": longest}


class WindowEntropyTracker:
    """Streaming equivalent: feed chunks, get the same stats.

    Keeps a rolling buffer; windows are emitted on the same
    2,048/1,024 grid as the one-shot function, so streamed and
    in-memory scans agree (equivalence-tested).
    """

    def __init__(self, window: int = WINDOW, step: int = STEP) -> None:
        self.window = window
        self.step = step
        self.buffer = bytearray()
        self.entropies: list[float] = []
        self.total = 0

    def feed(self, chunk: bytes) -> None:
        self.total += len(chunk)
        self.buffer.extend(chunk)
        while len(self.buffer) >= self.window:
            self.entropies.append(shannon_entropy(bytes(self.buffer[:self.window])))
            del self.buffer[:self.step]

    def finish(self) -> dict:
        if self.total == 0:
            return segmented_stats(b"")
        if not self.entropies:
            return segmented_stats(bytes(self.buffer))
        ents = list(self.entropies)
        if self.buffer:
            ents.append(shannon_entropy(bytes(self.buffer)))
        ordered = sorted(ents)
        hot = [e >= HOT for e in ents]
        longest = run = 0
        for h in hot:
            run = run + 1 if h else 0
            longest = max(longest, run)
        return {"windows": len(ents), "max": round(max(ents), 4),
                "p90": round(ordered[min(len(ordered) - 1,
                                        int(0.9 * len(ordered)))], 4),
                "mean": round(sum(ents) / len(ents), 4),
                "frac_ge_7": round(sum(hot) / len(ents), 4),
                "longest_hot_run": longest}
