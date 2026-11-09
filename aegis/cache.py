"""Persistent verdict cache (SQLite, stdlib).

The cache key is composite on purpose: (sha256, engine version,
ruleset hash, config hash). A content-only key is a stale-verdict
bug waiting for the first rule update: the file did not change,
but the right answer did. The ruleset hash covers the pack file
bytes; the config hash covers the verdict thresholds.

Cached verdicts are treated as untrusted input on the way out:
rows that fail JSON parsing or lack the required verdict fields
are ignored and deleted, never trusted, because the database is
just a file on disk that anything could have written to.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path

from . import __version__

CONFIG_HASH = hashlib.sha256(b"suspicious=40;malicious=70;v1").hexdigest()[:16]
REQUIRED_FIELDS = {"verdict", "score", "evidence", "rule_pack"}


def ruleset_hash(pack_path: Path) -> str:
    return hashlib.sha256(pack_path.read_bytes()).hexdigest()[:16]


class VerdictCache:
    def __init__(self, db_path: Path, pack_path: Path) -> None:
        self.db_path = Path(db_path)
        self.ruleset = ruleset_hash(pack_path)
        self.conn = sqlite3.connect(self.db_path)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS verdicts ("
            "sha256 TEXT, engine TEXT, ruleset TEXT, config TEXT, "
            "verdict TEXT, PRIMARY KEY (sha256, engine, ruleset, config))")
        self.conn.commit()

    def key(self, sha256: str) -> tuple[str, str, str, str]:
        return (sha256, __version__, self.ruleset, CONFIG_HASH)

    def get(self, sha256: str) -> dict | None:
        row = self.conn.execute(
            "SELECT verdict FROM verdicts WHERE sha256=? AND engine=? "
            "AND ruleset=? AND config=?", self.key(sha256)).fetchone()
        if row is None:
            return None
        try:
            verdict = json.loads(row[0])
        except (ValueError, TypeError):
            verdict = None
        if not isinstance(verdict, dict) or not REQUIRED_FIELDS <= verdict.keys():
            self.conn.execute(
                "DELETE FROM verdicts WHERE sha256=? AND engine=? "
                "AND ruleset=? AND config=?", self.key(sha256))
            self.conn.commit()
            return None
        verdict["from_cache"] = True
        verdict["persistent_cache"] = True
        return verdict

    def put(self, sha256: str, verdict: dict) -> None:
        stored = {k: v for k, v in verdict.items()
                  if k not in ("from_cache", "persistent_cache")}
        self.conn.execute(
            "INSERT OR REPLACE INTO verdicts VALUES (?,?,?,?,?)",
            (*self.key(sha256), json.dumps(stored)))
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()
