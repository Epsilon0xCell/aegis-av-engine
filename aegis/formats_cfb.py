"""CFB / OLE2 compound file parser (MS-CFB), stdlib only.

Legacy Office documents (.doc, .xls, .ppt), MSI installers, and
other OLE containers share this format: a header, a File
Allocation Table over 512 or 4096 byte sectors, a directory of
named storages and streams arranged as a red-black tree, and a
mini-stream for small streams below the 4096-byte cutoff.

The parser is defensive by construction: every chain walk
(FAT, DIFAT, MiniFAT, directory tree) carries a visited set and
a hard cap, so cyclic or hostile structures produce findings,
never hangs. Extracted stream bytes are capped in count and
total size. What it returns is an inventory: entries with
types, sizes, and the stream bytes themselves for the analysis
layers above it (MS-OVBA lives in aegis/ovba.py).
"""
from __future__ import annotations

import struct

SIGNATURE = bytes.fromhex("D0CF11E0A1B11AE1")
FREESECT = 0xFFFFFFFF
ENDOFCHAIN = 0xFFFFFFFE
FATSECT = 0xFFFFFFFD
DIFSECT = 0xFFFFFFFC
MAX_SECTORS = 200_000
MAX_STREAMS = 512
MAX_STREAM_BYTES = 4 * 1024 * 1024
MAX_TOTAL_BYTES = 16 * 1024 * 1024

OBJ_EMPTY, OBJ_STORAGE, OBJ_STREAM, OBJ_ROOT = 0, 1, 2, 5


def _u16(d, o):
    return struct.unpack_from("<H", d, o)[0]


def _u32(d, o):
    return struct.unpack_from("<I", d, o)[0]


class _Reader:
    def __init__(self, data: bytes, findings: list[dict]) -> None:
        self.data = data
        self.findings = findings
        self.sector_size = 512
        self.mini_size = 64
        self.fat: list[int] = []
        self.minifat: list[int] = []

    def sector(self, sid: int) -> bytes:
        off = (sid + 1) * self.sector_size
        if sid < 0 or off + self.sector_size > len(self.data):
            return b""
        return self.data[off:off + self.sector_size]

    def chain(self, table: list[int], start: int, unit: int,
              source: bytes | None = None) -> bytes:
        out = bytearray()
        seen: set[int] = set()
        sid = start
        while sid not in (ENDOFCHAIN, FREESECT):
            if sid in seen:
                self.findings.append({"type": "cfb_cyclic_chain",
                                      "sector": sid})
                break
            seen.add(sid)
            if len(seen) > MAX_SECTORS or sid >= len(table):
                self.findings.append({"type": "cfb_chain_out_of_range",
                                      "sector": sid})
                break
            if source is None:
                out += self.sector(sid)
            else:
                off = sid * unit
                out += source[off:off + unit]
            sid = table[sid]
        return bytes(out)


def parse_cfb(data: bytes) -> dict:
    findings: list[dict] = []
    out: dict = {"format": "cfb", "findings": findings, "entries": [],
                 "streams": {}}
    if len(data) < 512 or data[:8] != SIGNATURE:
        findings.append({"type": "not_cfb"})
        return out
    r = _Reader(data, findings)
    major = _u16(data, 26)
    r.sector_size = 4096 if major == 4 else 512
    shift = _u16(data, 30)
    if (1 << shift) != r.sector_size:
        findings.append({"type": "cfb_sector_shift_mismatch",
                         "shift": shift})
    r.mini_size = 1 << _u16(data, 32)
    num_fat = _u32(data, 44)
    first_dir = _u32(data, 48)
    cutoff = _u32(data, 56)
    first_minifat = _u32(data, 60)
    num_minifat = _u32(data, 64)
    first_difat = _u32(data, 68)
    num_difat = _u32(data, 72)
    # DIFAT: header array, then the DIFAT sector chain
    fat_sectors = [v for v in struct.unpack_from("<109I", data, 76)
                   if v != FREESECT]
    sid = first_difat
    seen_difat: set[int] = set()
    for _ in range(min(num_difat, 4096)):
        if sid in (ENDOFCHAIN, FREESECT) or sid in seen_difat:
            break
        seen_difat.add(sid)
        sec = r.sector(sid)
        if len(sec) < r.sector_size:
            break
        entries = struct.unpack_from(f"<{r.sector_size // 4}I", sec, 0)
        fat_sectors.extend(v for v in entries[:-1] if v != FREESECT)
        sid = entries[-1]
    fat_sectors = fat_sectors[:num_fat] if num_fat else fat_sectors
    for fs in fat_sectors:
        sec = r.sector(fs)
        if sec:
            r.fat.extend(struct.unpack(f"<{len(sec) // 4}I", sec))
    if not r.fat:
        findings.append({"type": "cfb_no_fat"})
        return out
    # Directory
    dir_bytes = r.chain(r.fat, first_dir, r.sector_size)
    entries = []
    for i in range(len(dir_bytes) // 128):
        e = dir_bytes[i * 128:(i + 1) * 128]
        name_len = _u16(e, 64)
        raw_name = e[:max(0, min(name_len - 2, 62))] if name_len >= 2 else b""
        name = raw_name.decode("utf-16-le", "replace")
        entries.append({
            "index": i, "name": name, "type": e[66],
            "left": _u32(e, 68), "right": _u32(e, 72),
            "child": _u32(e, 76),
            "start": _u32(e, 116),
            "size": struct.unpack_from("<Q", e, 120)[0]})
    out["entries"] = [{k: e[k] for k in ("name", "type", "size")}
                      for e in entries if e["type"] != OBJ_EMPTY]
    # MiniFAT and the root's mini stream
    if num_minifat and first_minifat not in (ENDOFCHAIN, FREESECT):
        mini_bytes = r.chain(r.fat, first_minifat, r.sector_size)
        r.minifat = list(struct.unpack(f"<{len(mini_bytes) // 4}I",
                                       mini_bytes[:len(mini_bytes) // 4 * 4]))
    root = next((e for e in entries if e["type"] == OBJ_ROOT), None)
    ministream = b""
    if root is not None:
        ministream = r.chain(r.fat, root["start"], r.sector_size)
        ministream = ministream[:root["size"]]
    # Walk the directory tree (iterative, visited set)
    paths: dict[int, str] = {}
    order: list[int] = []

    def walk(idx: int, prefix: str, depth: int) -> None:
        stack = [(idx, prefix, depth)]
        seen: set[int] = set()
        while stack:
            cur, pre, dep = stack.pop()
            if cur in (FREESECT,) or cur >= len(entries) or cur in seen \
                    or dep > 64:
                if cur < len(entries) and cur in seen:
                    findings.append({"type": "cfb_directory_loop",
                                     "entry": cur})
                continue
            seen.add(cur)
            e = entries[cur]
            if e["type"] == OBJ_ROOT:
                path = ""  # the root's own name is not a path part
            elif pre:
                path = f"{pre}/{e['name']}"
            else:
                path = e["name"]
            paths[cur] = path
            order.append(cur)
            if e["left"] != FREESECT:
                stack.append((e["left"], pre, dep + 1))
            if e["right"] != FREESECT:
                stack.append((e["right"], pre, dep + 1))
            if e["type"] in (OBJ_STORAGE, OBJ_ROOT) \
                    and e["child"] != FREESECT:
                stack.append((e["child"], path, dep + 1))

    if root is not None:
        walk(root["index"], "", 0)
    total = 0
    for idx in order:
        e = entries[idx]
        if e["type"] != OBJ_STREAM:
            continue
        if len(out["streams"]) >= MAX_STREAMS or total > MAX_TOTAL_BYTES:
            findings.append({"type": "cfb_stream_cap_reached"})
            break
        if e["size"] < cutoff and r.minifat:
            blob = r.chain(r.minifat, e["start"], r.mini_size,
                           source=ministream)
        else:
            blob = r.chain(r.fat, e["start"], r.sector_size)
        blob = blob[:e["size"]]
        if len(blob) > MAX_STREAM_BYTES:
            blob = blob[:MAX_STREAM_BYTES]
            findings.append({"type": "cfb_stream_truncated",
                             "stream": paths.get(idx, e["name"])})
        total += len(blob)
        out["streams"][paths.get(idx, e["name"])] = blob
    findings.append({"type": "cfb_parsed",
                     "entries": len(out["entries"]),
                     "streams": len(out["streams"])})
    return out
