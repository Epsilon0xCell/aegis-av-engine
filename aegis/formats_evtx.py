"""Windows Event Log (.evtx) chunk inventory with tamper
tripwires.

Scope is inventory, not rendering: BinXml record content is
deliberately not decoded (the on-disk format is not covered
by MS-EVEN6). What the inventory gives a responder is the
file's skeleton and its integrity state: the file header,
each 64 KiB chunk's header and data CRC-32 values recomputed
and compared, and the record chain walked by size. A chunk
whose checksums no longer match is a tamper tripwire: log
files are edited precisely by rewriting chunks, and edits
that do not repair both CRCs announce themselves.
Constants per Schuster (2007) and the libevtx documentation.
"""
from __future__ import annotations

import struct
import zlib

FILE_HEADER_SIZE = 4096
CHUNK_SIZE = 65536
CHUNK_HEADER_SIZE = 512
RECORD_SIGNATURE = 0x2A2A2A2A
MAX_RECORDS_PER_CHUNK = 10000


def _u32(d, o):
    return struct.unpack_from("<I", d, o)[0]


def _u64(d, o):
    return struct.unpack_from("<Q", d, o)[0]


def _crc(data: bytes) -> int:
    return zlib.crc32(data) & 0xFFFFFFFF


def parse_evtx(data: bytes) -> dict:
    findings: list[dict] = []
    out: dict = {"format": "evtx", "findings": findings,
                 "chunks": []}
    if not data.startswith(b"ElfFile\x00"):
        findings.append({"type": "not_evtx"})
        return out
    if len(data) < FILE_HEADER_SIZE:
        findings.append({"type": "evtx_truncated_header"})
        return out
    header = data[:FILE_HEADER_SIZE]
    stored_crc = _u32(header, 124)
    computed_crc = _crc(header[:120])
    out["header"] = {
        "first_chunk": _u64(header, 8),
        "last_chunk": _u64(header, 16),
        "next_record_id": _u64(header, 24),
        "chunk_count": struct.unpack_from("<H", header, 38)[0],
        "header_crc_ok": stored_crc == computed_crc}
    if stored_crc != computed_crc:
        findings.append({"type": "evtx_header_checksum_mismatch",
                         "stored": stored_crc, "computed": computed_crc})
    offset = FILE_HEADER_SIZE
    index = 0
    while offset + CHUNK_SIZE <= len(data) + CHUNK_SIZE \
            and offset < len(data):
        chunk = data[offset:offset + CHUNK_SIZE]
        if len(chunk) < CHUNK_HEADER_SIZE \
                or not chunk.startswith(b"ElfChnk\x00"):
            if chunk.strip(b"\x00"):
                findings.append({"type": "evtx_chunk_signature_bad",
                                 "chunk": index})
            break
        header_crc_stored = _u32(chunk, 124)
        header_crc = _crc(chunk[:120] + chunk[128:512])
        next_off = _u32(chunk, 48)
        data_crc_stored = _u32(chunk, 52)
        data_crc = _crc(chunk[CHUNK_HEADER_SIZE:next_off]) \
            if CHUNK_HEADER_SIZE <= next_off <= len(chunk) else None
        records = 0
        record_ids = []
        pos = CHUNK_HEADER_SIZE
        while pos + 24 <= min(next_off, len(chunk)) \
                and records < MAX_RECORDS_PER_CHUNK:
            if _u32(chunk, pos) != RECORD_SIGNATURE:
                findings.append({"type": "evtx_record_signature_bad",
                                 "chunk": index, "offset": pos})
                break
            size = _u32(chunk, pos + 4)
            if size < 24 or pos + size > len(chunk):
                findings.append({"type": "evtx_record_size_bad",
                                 "chunk": index, "offset": pos})
                break
            record_ids.append(_u64(chunk, pos + 8))
            records += 1
            pos += size
        entry = {"index": index,
                 "first_record_id": _u64(chunk, 24),
                 "last_record_id": _u64(chunk, 32),
                 "records_walked": records,
                 "record_ids_first": record_ids[:1],
                 "record_ids_last": record_ids[-1:],
                 "header_crc_ok": header_crc_stored == header_crc,
                 "data_crc_ok": (data_crc is not None
                                 and data_crc_stored == data_crc)}
        if not entry["header_crc_ok"]:
            findings.append({"type": "evtx_chunk_header_crc_mismatch",
                             "chunk": index})
        if not entry["data_crc_ok"]:
            findings.append({"type": "evtx_chunk_data_crc_mismatch",
                             "chunk": index})
        out["chunks"].append(entry)
        offset += CHUNK_SIZE
        index += 1
    findings.append({"type": "evtx_inventory",
                     "chunks": len(out["chunks"]),
                     "records": sum(c["records_walked"]
                                    for c in out["chunks"])})
    return out
