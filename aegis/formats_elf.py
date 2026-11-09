"""ELF parser: header, program headers, dynamic dependencies."""
from __future__ import annotations

import struct

PT = {1: "LOAD", 2: "DYNAMIC", 3: "INTERP", 4: "NOTE", 6: "PHDR", 7: "TLS"}
DT_NEEDED = 1
DT_RPATH = 15
DT_RUNPATH = 29


def parse_elf(data: bytes) -> dict:
    out: dict = {"format": "elf", "findings": [], "program_headers": [],
                 "needed": [], "interpreter": None}
    try:
        if len(data) < 64 or not data.startswith(b"\x7fELF"):
            out["findings"].append({"type": "not_elf"})
            return out
        is64 = data[4] == 2
        le = data[5] != 2
        en = "<" if le else ">"
        out["bits"] = 64 if is64 else 32
        out["machine"] = struct.unpack_from(en + "H", data, 18)[0]
        if is64:
            phoff = struct.unpack_from(en + "Q", data, 32)[0]
            phentsize, phnum = struct.unpack_from(en + "HH", data, 54)
        else:
            phoff = struct.unpack_from(en + "I", data, 28)[0]
            phentsize, phnum = struct.unpack_from(en + "HH", data, 42)
        dyn_off, dyn_filesz = None, 0
        for i in range(min(phnum, 128)):
            o = phoff + i * phentsize
            if o + phentsize > len(data):
                out["findings"].append({"type": "phdr_truncated"})
                break
            if is64:
                p_type, _flags, p_off, _va, _pa, p_filesz = struct.unpack_from(
                    en + "IIQQQQ", data, o)
            else:
                p_type, p_off, _va, _pa, p_filesz = struct.unpack_from(
                    en + "IIIII", data, o)
            out["program_headers"].append(PT.get(p_type, hex(p_type)))
            if p_type == 3:
                seg = data[p_off:p_off + p_filesz]
                out["interpreter"] = seg.split(b"\x00")[0].decode("utf-8", "replace")
            if p_type == 2:
                dyn_off, dyn_filesz = p_off, p_filesz
        if dyn_off is not None:
            out["needed"] = _dynamic_needed(data, dyn_off, dyn_filesz, is64, en, out)
    except (struct.error, IndexError) as exc:
        out["findings"].append({"type": "elf_parse_error", "detail": str(exc)})
    return out


def _dynamic_needed(data, off, filesz, is64, en, out):
    needed_offsets = []
    strtab_off = None
    step = 16 if is64 else 8
    fmt = en + ("qQ" if is64 else "iI")
    for i in range(filesz // step if step else 0):
        o = off + i * step
        if o + step > len(data):
            break
        tag, val = struct.unpack_from(fmt, data, o)
        if tag == 0:
            break
        if tag == DT_NEEDED:
            needed_offsets.append(val)
        elif tag == 5:  # DT_STRTAB holds a virtual address; lab parsers
            strtab_off = val  # commonly approximate file offset equality
        elif tag in (DT_RPATH, DT_RUNPATH):
            out.setdefault("findings", []).append(
                {"type": "rpath_present", "kind": "RPATH" if tag == DT_RPATH else "RUNPATH"})
    names = []
    if strtab_off is not None:
        for no in needed_offsets:
            start = strtab_off + no
            if 0 <= start < len(data):
                end = data.find(b"\x00", start)
                if end > start:
                    names.append(data[start:end].decode("utf-8", "replace"))
    return names
