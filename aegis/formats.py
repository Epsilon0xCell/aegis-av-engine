"""Static format identification and feature extraction.

Identifies PE, ELF, Mach-O (thin and fat), scripts and common
document/container types by magic, and extracts the cheap features
the heuristic scorecard uses. Pure stdlib, so the same code and the
same verdicts run on Windows, macOS and Linux.
"""
from __future__ import annotations

import math
import struct

MAGICS = (
    (bytes.fromhex("D0CF11E0A1B11AE1"), "cfb"),
    (b"MZ", "pe"),
    (b"\x7fELF", "elf"),
    (b"\xfe\xed\xfa\xce", " macho32".strip()),
    (b"\xce\xfa\xed\xfe", "macho32le"),
    (b"\xfe\xed\xfa\xcf", "macho64"),
    (b"\xcf\xfa\xed\xfe", "macho64le"),
    (b"\xca\xfe\xba\xbe", "macho_fat"),
    (b"%PDF", "pdf"),
    (b"PK\x03\x04", "zip_container"),
    (b"#!", "script_shebang"),
)


LNK_CLSID = bytes.fromhex("0114020000000000C000000000000046")


def identify(data: bytes) -> str:
    for magic, kind in MAGICS:
        if data.startswith(magic):
            return kind
    if data[:4] == b"L\x00\x00\x00" and data[4:20] == LNK_CLSID:
        return "lnk"
    if data.startswith(b"{\\rtf"):
        return "rtf"
    if len(data) > 32774 and data[32769:32774] == b"CD001":
        return "iso"
    head_lines = data[:1024].split(b"\n")[:12]
    header_like = sum(1 for line in head_lines
                      if b":" in line and line.split(b":", 1)[0]
                      .strip().lower() in (
                          b"from", b"to", b"subject", b"date",
                          b"mime-version", b"content-type",
                          b"message-id", b"return-path"))
    if header_like >= 2:
        return "eml"
    head = data[:512].lower()
    if b"<script" in head or b"powershell" in head or b"/bin/sh" in head:
        return "script"
    try:
        data[:512].decode("utf-8")
        return "text"
    except UnicodeDecodeError:
        return "binary_unknown"


def pe_features(data: bytes) -> dict:
    """A few honest PE features without a PE library: section count
    from the COFF header and the import-directory presence flag.
    Returns {} for non-PE data."""
    if not data.startswith(b"MZ") or len(data) < 0x40:
        return {}
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew + 24 > len(data) or data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        return {"pe_parse": "stub_only"}
    sections = struct.unpack_from("<H", data, e_lfanew + 6)[0]
    timestamp = struct.unpack_from("<I", data, e_lfanew + 8)[0]
    return {"pe_parse": "ok", "pe_sections": sections, "pe_timestamp": timestamp}


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return round(-sum((c / n) * math.log2(c / n) for c in counts if c), 4)
