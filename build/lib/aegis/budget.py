"""One shared scan budget for everything recursive.

Constants follow the project's research (ClamAV configuration
documentation and decompression-bomb guidance), choosing the
conservative published values and saying so:

- total decompressed bytes per scan: 100 MiB
- per-entry bytes: 25 MiB
- archive recursion depth: 5 (hard ceiling 16)
- files per archive tree: 1,000 (hard ceiling 10,000)
- decompression ratio cap: 100:1 once past 1 MiB of output
- wall-clock limit per container scan: 120 s

The budget is a single object shared across nesting levels, so a
clever archive cannot reset its allowances by hiding inside
another archive. Exhaustion is a FINDING, not a crash.
"""
from __future__ import annotations

import time

TOTAL_BYTES = 100 * 1024 * 1024
PER_ENTRY_BYTES = 25 * 1024 * 1024
MAX_DEPTH = 5
MAX_FILES = 1000
RATIO_CAP = 100
RATIO_FLOOR_BYTES = 1 * 1024 * 1024
TIME_LIMIT_S = 120.0


class BudgetExceeded(Exception):
    def __init__(self, kind: str, detail: str) -> None:
        super().__init__(f"{kind}: {detail}")
        self.kind = kind
        self.detail = detail


class ScanBudget:
    def __init__(self, total: int = TOTAL_BYTES, per_entry: int = PER_ENTRY_BYTES,
                 depth: int = MAX_DEPTH, files: int = MAX_FILES,
                 ratio: int = RATIO_CAP, time_limit: float = TIME_LIMIT_S) -> None:
        self.total_limit = total
        self.per_entry = per_entry
        self.depth_limit = depth
        self.files_limit = files
        self.ratio = ratio
        self.deadline = time.monotonic() + time_limit
        self.total_used = 0
        self.files_seen = 0

    def enter_level(self, depth: int) -> None:
        if depth > self.depth_limit:
            raise BudgetExceeded("depth", f"archive nesting exceeds {self.depth_limit}")

    def count_file(self) -> None:
        self.files_seen += 1
        if self.files_seen > self.files_limit:
            raise BudgetExceeded("files", f"more than {self.files_limit} entries")

    def consume(self, n: int, compressed_size: int | None = None) -> None:
        if n > self.per_entry:
            raise BudgetExceeded("per_entry", f"entry exceeds {self.per_entry} bytes")
        self.total_used += n
        if self.total_used > self.total_limit:
            raise BudgetExceeded("total", f"scan exceeds {self.total_limit} bytes")
        if compressed_size and self.total_used > RATIO_FLOOR_BYTES:
            if self.total_used / max(compressed_size, 1) > self.ratio:
                raise BudgetExceeded(
                    "ratio", f"decompression ratio exceeds {self.ratio}:1")
        if time.monotonic() > self.deadline:
            raise BudgetExceeded("time", "scan time limit reached")
