"""Download provenance: evidence, never a score.

Where a file came from is context an analyst wants and a
verdict must not lean on: a ZoneId of 3 (Internet) describes
most legitimate downloads too. This module reads the two
provenance stores the platforms keep and returns them as
evidence attached to scan_file verdicts. It never feeds the
score, and a test pins that invariance.

Windows: the Zone.Identifier alternate data stream, carried
here as the sibling representation (a file literally named
"<path>:Zone.Identifier" on POSIX, the ADS itself opened the
same way on Windows). macOS and Linux: extended attributes,
including com.apple.quarantine when present, whose fields
(flags, date, agent, UUID) are parsed.
"""
from __future__ import annotations

import os
from pathlib import Path

_ZONE_KEYS = {"zoneid": "zone_id", "referrerurl": "referrer_url",
              "hosturl": "host_url"}


def _read_zone_identifier(path: Path) -> dict | None:
    try:
        text = Path(str(path) + ":Zone.Identifier").read_text(
            errors="replace")
    except OSError:
        return None
    out: dict = {}
    for line in text.splitlines():
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        mapped = _ZONE_KEYS.get(key.strip().lower())
        if mapped:
            out[mapped] = value.strip()
    if "zone_id" in out:
        try:
            out["zone_id"] = int(out["zone_id"])
        except ValueError:
            pass
        out["zone_meaning"] = {
            0: "local machine", 1: "local intranet",
            2: "trusted sites", 3: "internet",
            4: "restricted sites"}.get(out["zone_id"], "unknown")
    return out or None


def _read_xattrs(path: Path) -> dict:
    out: dict = {}
    try:
        names = os.listxattr(path)
    except (OSError, AttributeError):
        return out
    for name in names:
        # provenance lives in the user namespace (and in
        # com.apple.* on macOS); system.* attributes are
        # filesystem bookkeeping, not provenance
        if not (name.startswith("user.")
                or name.startswith("com.apple.")):
            continue
        try:
            raw = os.getxattr(path, name)
        except OSError:
            continue
        value = raw.decode("utf-8", "replace")[:512]
        if name == "com.apple.quarantine":
            parts = value.split(";")
            out[name] = {"raw": value,
                         "flags": parts[0] if parts else "",
                         "agent": parts[2] if len(parts) > 2 else "",
                         "uuid": parts[3] if len(parts) > 3 else ""}
        else:
            out[name] = value
    return out


def read_provenance(path: Path) -> dict:
    zone = _read_zone_identifier(path)
    xattrs = _read_xattrs(path)
    return {"zone_identifier": zone, "xattrs": xattrs,
            "present": bool(zone or xattrs),
            "scores_affected": False}
