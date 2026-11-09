"""Deep PE parser, bounds-checked throughout.

Parses the DOS header, COFF header, optional header (PE32 and
PE32+), all 16 data directories by name, the section table with
per-section entropy, the import table (DLL names and function
counts, via RVA-to-file-offset mapping through the sections), the
overlay beyond the last section, and presence flags for TLS and
Authenticode. Parse failures are FINDINGS with offsets, never
exceptions: a malformed PE is itself a signal an analyst wants.
Spec: Microsoft PE Format documentation.
"""
from __future__ import annotations

import struct

from .formats import shannon_entropy

DIRECTORIES = ["export", "import", "resource", "exception", "security",
               "basereloc", "debug", "architecture", "globalptr", "tls",
               "loadconfig", "boundimport", "iat", "delayimport",
               "clr", "reserved"]
CHARACTERISTICS_EXEC = 0x2000


def _u16(d: bytes, o: int) -> int:
    return struct.unpack_from("<H", d, o)[0]


def _u32(d: bytes, o: int) -> int:
    return struct.unpack_from("<I", d, o)[0]


def parse_pe(data: bytes) -> dict:
    out: dict = {"format": "pe", "findings": [], "sections": [],
                 "imports": {}, "directories": {}}
    try:
        if len(data) < 0x40 or not data.startswith(b"MZ"):
            out["findings"].append({"type": "not_pe"})
            return out
        pe_off = _u32(data, 0x3C)
        out["pe_offset"] = pe_off
        if pe_off + 24 > len(data) or data[pe_off:pe_off + 4] != b"PE\x00\x00":
            out["findings"].append({"type": "pe_signature_missing",
                                    "offset": pe_off})
            return out
        coff = pe_off + 4
        out["machine"] = hex(_u16(data, coff))
        n_sections = _u16(data, coff + 2)
        out["timestamp"] = _u32(data, coff + 4)
        opt_size = _u16(data, coff + 16)
        opt = coff + 20
        magic = _u16(data, opt)
        out["pe_kind"] = "PE32+" if magic == 0x20B else "PE32" if magic == 0x10B else hex(magic)
        dd_base = opt + (112 if magic == 0x20B else 96)
        n_dirs = _u32(data, opt + (108 if magic == 0x20B else 92)) \
            if opt + (112 if magic == 0x20B else 96) <= len(data) else 0
        for i, name in enumerate(DIRECTORIES[:min(n_dirs, 16)]):
            rva, size = _u32(data, dd_base + i * 8), _u32(data, dd_base + i * 8 + 4)
            if rva or size:
                out["directories"][name] = {"rva": rva, "size": size}
        out["has_tls"] = "tls" in out["directories"]
        out["has_authenticode_table"] = "security" in out["directories"]
        sec_off = opt + opt_size
        sections_end = 0
        for i in range(min(n_sections, 96)):
            so = sec_off + i * 40
            if so + 40 > len(data):
                out["findings"].append({"type": "section_table_truncated", "index": i})
                break
            raw_name = data[so:so + 8].split(b"\x00")[0]
            name = raw_name.decode("ascii", "replace")
            vsize, vaddr = _u32(data, so + 8), _u32(data, so + 12)
            raw_size, raw_ptr = _u32(data, so + 16), _u32(data, so + 20)
            chars = _u32(data, so + 36)
            blob = data[raw_ptr:raw_ptr + raw_size] if raw_ptr + raw_size <= len(data) else b""
            out["sections"].append({
                "name": name, "virtual_size": vsize, "virtual_address": vaddr,
                "raw_size": raw_size, "entropy": shannon_entropy(blob) if blob else 0.0,
                "executable": bool(chars & CHARACTERISTICS_EXEC)})
            sections_end = max(sections_end, raw_ptr + raw_size)
        out["overlay_bytes"] = max(0, len(data) - sections_end) if sections_end else 0
        imp = out["directories"].get("import")
        if imp:
            out["imports"] = _parse_imports(data, out["sections"], imp["rva"])
        if out["overlay_bytes"] > 0:
            out["findings"].append({"type": "overlay_present",
                                    "bytes": out["overlay_bytes"]})
        exec_high = [s for s in out["sections"]
                     if s["executable"] and s["entropy"] > 7.2]
        if exec_high:
            out["findings"].append({"type": "high_entropy_executable_sections",
                                    "sections": [s["name"] for s in exec_high]})
    except (struct.error, IndexError) as exc:
        out["findings"].append({"type": "pe_parse_error", "detail": str(exc)})
    return out


def _rva_to_off(sections: list[dict], rva: int, data_len: int) -> int | None:
    for s in sections:
        start = s["virtual_address"]
        span = max(s["virtual_size"], s["raw_size"])
        if start <= rva < start + span:
            off = rva - start + (s.get("_raw_ptr") or 0)
            return off if off < data_len else None
    return None


def _parse_imports(data: bytes, sections: list[dict], imp_rva: int) -> dict:
    # sections here lack raw pointers in the public dict; recompute
    # mapping from the section table directly for correctness.
    imports: dict[str, int] = {}
    try:
        pe_off = _u32(data, 0x3C)
        coff = pe_off + 4
        n = _u16(data, coff + 2)
        opt_size = _u16(data, coff + 16)
        sec_off = coff + 20 + opt_size
        spans = []
        for i in range(min(n, 96)):
            so = sec_off + i * 40
            spans.append((_u32(data, so + 12),
                          max(_u32(data, so + 8), _u32(data, so + 16)),
                          _u32(data, so + 20)))

        def to_off(rva: int) -> int | None:
            for va, span, ptr in spans:
                if va <= rva < va + span:
                    o = ptr + (rva - va)
                    return o if o < len(data) else None
            return None

        desc = to_off(imp_rva)
        if desc is None:
            return imports
        for k in range(512):
            entry = desc + k * 20
            if entry + 20 > len(data):
                break
            oft, _ts, _fwd, name_rva, ft = struct.unpack_from("<IIIII", data, entry)
            if not any((oft, name_rva, ft)):
                break
            name_off = to_off(name_rva)
            if name_off is None:
                continue
            end = data.find(b"\x00", name_off)
            dll = data[name_off:end].decode("ascii", "replace") if end > 0 else "?"
            thunk_off = to_off(oft or ft)
            count = 0
            if thunk_off is not None:
                step = 8 if _u16(data, coff + 20) == 0x20B else 4
                for j in range(4096):
                    to = thunk_off + j * step
                    if to + step > len(data):
                        break
                    val = int.from_bytes(data[to:to + step], "little")
                    if val == 0:
                        break
                    count += 1
            imports[dll] = count
    except (struct.error, IndexError):
        return imports
    return imports
