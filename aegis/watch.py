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

import struct
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
                    interval_s: float = 0.25,
                    backend: str = "poll") -> list[dict]:
    """Watch for duration_s; return scan events for settled changes.

    backend="poll" (default, every platform) diffs snapshots.
    backend="inotify" (Linux only) wakes on filesystem events
    and applies the same settle semantics. Both are user-space
    and notify-only, per the module statement.
    """
    if backend == "inotify":
        return _inotify_watch_directory(root, engine, duration_s,
                                        interval_s)
    if backend != "poll":
        raise ValueError(f"unknown watch backend: {backend!r}")
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


# ------------------------------------------------------------------
# inotify backend (Linux, ctypes): event-driven wakeups feeding
# the same settle-then-scan semantics as polling. Shipped under
# a kill criterion from the v5 research: it must pass the shared
# semantics suite in CI or be deleted, and this module says so.
# ------------------------------------------------------------------
import ctypes
import os
import select

_IN_CLOSE_WRITE = 0x00000008
_IN_MOVED_TO = 0x00000080
_IN_CREATE = 0x00000100
_IN_MODIFY = 0x00000002


def _inotify_watch_directory(root: Path, engine: Engine,
                             duration_s: float,
                             interval_s: float) -> list[dict]:
    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    fd = libc.inotify_init1(os.O_NONBLOCK)
    if fd < 0:
        raise OSError("inotify_init1 failed")
    mask = _IN_CLOSE_WRITE | _IN_MOVED_TO | _IN_CREATE | _IN_MODIFY
    wd = libc.inotify_add_watch(fd, str(root).encode(), mask)
    if wd < 0:
        os.close(fd)
        raise OSError("inotify_add_watch failed")
    events: list[dict] = []
    pending: dict[str, tuple[tuple[int, float], float]] = {}
    deadline = time.monotonic() + duration_s
    try:
        while time.monotonic() < deadline:
            timeout = max(0.0, min(0.05, deadline - time.monotonic()))
            ready, _, _ = select.select([fd], [], [], timeout)
            if ready:
                data = os.read(fd, 65536)
                pos = 0
                while pos + 16 <= len(data):
                    _wd, _mask, _cookie, name_len = struct.unpack_from(
                        "<IIII", data, pos)
                    raw_name = data[pos + 16:pos + 16 + name_len]
                    name = raw_name.split(b"\x00")[0].decode(
                        "utf-8", "replace")
                    pos += 16 + name_len
                    if not name:
                        continue
                    path = (root / name)
                    if path.is_file():
                        try:
                            st = path.stat()
                            pending[path.as_posix()] = (
                                (st.st_size, st.st_mtime),
                                time.monotonic())
                        except OSError:
                            continue
            now = time.monotonic()
            for key in list(pending):
                sig, since = pending[key]
                try:
                    st = Path(key).stat()
                    current = (st.st_size, st.st_mtime)
                except OSError:
                    del pending[key]
                    continue
                if current != sig:
                    pending[key] = (current, now)
                elif now - since >= interval_s:
                    verdict = engine.scan_file(Path(key))
                    events.append({"path": key,
                                   "verdict": verdict["verdict"],
                                   "score": verdict["score"]})
                    del pending[key]
    finally:
        os.close(fd)
    return events
