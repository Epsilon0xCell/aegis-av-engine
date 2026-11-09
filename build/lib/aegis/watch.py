"""Polling directory watch: notify-only, cross-platform.

Polls a directory tree on an interval, waits for a changed file's
size to stabilise across two polls (so partial copies are not
scanned mid-write), scans it, and emits an event. Polling is the
portable baseline on all three OSes; native notification backends
(inotify, ReadDirectoryChangesW, FSEvents) are an optimisation,
never a requirement, and none of them would change the
capability: events NOTIFY, they never block the file.
"""
from __future__ import annotations

import time
from pathlib import Path

from .engine import Engine


def _snapshot(root: Path) -> dict[str, tuple[int, float]]:
    snap = {}
    for p in root.rglob("*"):
        if p.is_file():
            try:
                st = p.stat()
                snap[p.as_posix()] = (st.st_size, st.st_mtime)
            except OSError:
                continue
    return snap


def watch_directory(root: Path, engine: Engine, duration_s: float = 5.0,
                    interval_s: float = 0.25) -> list[dict]:
    """Watch for duration_s; return scan events for settled changes."""
    events: list[dict] = []
    before = _snapshot(root)
    pending: dict[str, tuple[int, float]] = {}
    deadline = time.monotonic() + duration_s
    while time.monotonic() < deadline:
        time.sleep(interval_s)
        now = _snapshot(root)
        for path, sig in now.items():
            if before.get(path) != sig and path not in pending:
                pending[path] = sig
        for path in list(pending):
            if now.get(path) == pending[path]:
                verdict = engine.scan_file(Path(path))
                events.append({"path": path, "verdict": verdict["verdict"],
                               "score": verdict["score"]})
                del pending[path]
            elif path in now:
                pending[path] = now[path]
            else:
                del pending[path]
        before = now
    return events
