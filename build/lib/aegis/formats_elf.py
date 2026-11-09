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
        note_segments: list[tuple[int, int]] = []
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
            if p_type == 4:
                note_segments.append((p_off, p_filesz))
        if dyn_off is not None:
            out["needed"] = _dynamic_needed(data, dyn_off, dyn_filesz, is64, en, out)
        notes = []
        for seg_off, seg_size in note_segments:
            notes.extend(_parse_notes(data, seg_off, seg_size, en, out))
        if notes:
            out["notes"] = notes
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
        elif tag == 30:  # DT_FLAGS
            out.setdefault("dynamic_flags", []).append(
                {"kind": "FLAGS", "value": val})
            if val & 0x8:  # DF_BIND_NOW
                out.setdefault("findings", []).append(
                    {"type": "elf_bind_now", "detail": "full RELRO binding requested"})
        elif tag == 0x6FFFFFFB:  # DT_FLAGS_1
            out.setdefault("dynamic_flags", []).append(
                {"kind": "FLAGS_1", "value": val})
            kinds = []
            if val & 0x1:
                kinds.append("NOW")
            if val & 0x8000000:
                kinds.append("PIE")
            if kinds:
                out.setdefault("findings", []).append(
                    {"type": "elf_flags_1", "kinds": kinds})
    names = []
    if strtab_off is not None:
        for no in needed_offsets:
            start = strtab_off + no
            if 0 <= start < len(data):
                end = data.find(b"\x00", start)
                if end > start:
                    names.append(data[start:end].decode("utf-8", "replace"))
    return names


NT_GNU_BUILD_ID = 3


def _parse_notes(data: bytes, off: int, size: int, en: str, out: dict) -> list[dict]:
    """Parse ELF notes in one PT_NOTE segment. The GNU build-id
    (NT_GNU_BUILD_ID in a note named 'GNU') is a stable content
    fingerprint for the binary as linked: same role for ELF that
    imphash plays for PE, and reported as one."""
    notes: list[dict] = []
    end = min(off + size, len(data))
    pos = off
    while pos + 12 <= end:
        namesz, descsz, ntype = struct.unpack_from(en + "III", data, pos)
        name_start = pos + 12
        desc_start = name_start + ((namesz + 3) & ~3)
        desc_end = desc_start + descsz
        if desc_end > end or descsz > 4096:
            break
        name = data[name_start:name_start + max(namesz - 1, 0)].decode(
            "utf-8", "replace")
        desc = data[desc_start:desc_end]
        entry = {"name": name, "type": ntype, "desc_size": descsz}
        if name == "GNU" and ntype == NT_GNU_BUILD_ID:
            entry["build_id"] = desc.hex()
            out["build_id"] = desc.hex()
            out.setdefault("findings", []).append(
                {"type": "elf_build_id", "build_id": desc.hex()})
        notes.append(entry)
        pos = desc_start + ((descsz + 3) & ~3)
    return notes
