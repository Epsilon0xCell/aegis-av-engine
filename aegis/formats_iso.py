"""ISO 9660 (ECMA-119) member scanning, with Joliet names.

Disc images are the current bulk-delivery container: the
image is inert, its members are the content, and the classic
payload is a shortcut file sitting next to decoys. This
parser walks the primary volume descriptor's directory tree
(and a Joliet supplementary descriptor's, when present) and
extracts member bytes under caps for the caller's scanners.
UDF descriptors (BEA01/NSR02/NSR03) are detected and reported
as not parsed: full UDF is on the project's skip list, and
the report says so rather than failing quietly.
"""
from __future__ import annotations

import struct

SECTOR = 2048
MAX_FILES = 512
MAX_DEPTH = 8
MAX_MEMBER_BYTES = 4 * 1024 * 1024
MAX_TOTAL_BYTES = 16 * 1024 * 1024


def _both32(d: bytes, off: int) -> int:
    return struct.unpack_from("<I", d, off)[0]


def _dir_records(data: bytes, lba: int, size: int, joliet: bool):
    base = lba * SECTOR
    pos = 0
    while pos < size:
        at = base + pos
        if at >= len(data):
            return
        length = data[at]
        if length == 0:
            pos += SECTOR - (pos % SECTOR) if pos % SECTOR else SECTOR
            if pos > size:
                return
            continue
        record = data[at:at + length]
        if len(record) < 34:
            return
        extent = _both32(record, 2)
        dsize = _both32(record, 10)
        flags = record[25]
        name_len = record[32]
        raw_name = record[33:33 + name_len]
        if joliet:
            name = raw_name.decode("utf-16-be", "replace")
        else:
            name = raw_name.decode("ascii", "replace")
        yield {"name": name, "extent": extent, "size": dsize,
               "is_dir": bool(flags & 2)}
        pos += length


def _walk(data: bytes, root_rec: bytes, joliet: bool,
          findings: list) -> dict[str, bytes]:
    members: dict[str, bytes] = {}
    total = 0

    def visit(lba: int, size: int, prefix: str, depth: int):
        nonlocal total
        if depth > MAX_DEPTH:
            findings.append({"type": "iso_depth_cap"})
            return
        for rec in _dir_records(data, lba, size, joliet):
            if rec["name"] in ("\x00", "\x01"):
                continue
            path = f"{prefix}{rec['name']}"
            if rec["is_dir"]:
                visit(rec["extent"], rec["size"], path + "/", depth + 1)
            else:
                if len(members) >= MAX_FILES:
                    findings.append({"type": "iso_file_cap"})
                    return
                if rec["size"] > MAX_MEMBER_BYTES:
                    findings.append({"type": "iso_member_over_cap",
                                     "path": path, "size": rec["size"]})
                    continue
                start = rec["extent"] * SECTOR
                blob = data[start:start + rec["size"]]
                members[path] = blob
                total += len(blob)
                if total > MAX_TOTAL_BYTES:
                    findings.append({"type": "iso_total_cap"})
                    return

    root_extent = _both32(root_rec, 2)
    root_size = _both32(root_rec, 10)
    visit(root_extent, root_size, "", 0)
    return members


def parse_iso(data: bytes) -> dict:
    findings: list[dict] = []
    out: dict = {"format": "iso", "findings": findings, "members": {}}
    pvd_at = 16 * SECTOR
    if len(data) < pvd_at + SECTOR \
            or data[pvd_at + 1:pvd_at + 6] != b"CD001":
        findings.append({"type": "not_iso"})
        return out
    vd = data[pvd_at:pvd_at + SECTOR]
    if data[pvd_at] == 0 and vd[40:45] in (b"BEA01",):
        findings.append({"type": "iso_udf_detected_not_parsed"})
    out["volume_id"] = vd[40:72].decode("ascii", "replace").strip("\x00").strip()
    root_rec = vd[156:156 + 34]
    members = _walk(data, root_rec, False, findings)
    # Joliet supplementary descriptor: type 2 with escape
    # sequences in the identifier
    svd_at = 17 * SECTOR
    if len(data) >= svd_at + SECTOR and data[svd_at] == 2 \
            and data[svd_at + 1:svd_at + 6] == b"CD001" \
            and data[svd_at + 88:svd_at + 91] in (b"%/@", b"%/C", b"%/E"):
        svd = data[svd_at:svd_at + SECTOR]
        joliet_members = _walk(data, svd[156:156 + 34], True, findings)
        for path, blob in joliet_members.items():
            members.setdefault(path, blob)
        findings.append({"type": "iso_joliet_names",
                         "files": len(joliet_members)})
    out["members"] = members
    findings.append({"type": "iso_parsed",
                     "files": len(members),
                     "volume_id": out["volume_id"]})
    return out
