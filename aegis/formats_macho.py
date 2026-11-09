"""Mach-O parser: thin and fat binaries, load commands, slices."""
from __future__ import annotations

import struct

LC_NAMES = {0x1: "SEGMENT", 0x2: "SYMTAB", 0xC: "LOAD_DYLIB", 0xD: "ID_DYLIB",
            0xE: "LOAD_DYLINKER", 0x1C: "LOAD_WEAK_DYLIB", 0x21: "ENCRYPTION_INFO",
            0x2C: "ENCRYPTION_INFO_64", 0x1D: "CODE_SIGNATURE", 0x26: "FUNCTION_STARTS",
            0x29: "DYLD_INFO", 0x32: "BUILD_VERSION", 0x80000022: "DYLD_INFO_ONLY"}
FAT = 0xCAFEBABE


def _parse_thin(data: bytes, base: int, out: dict) -> None:
    magic = struct.unpack_from(">I", data, base)[0]
    is64 = magic in (0xFEEDFACF, 0xCFFAEDFE)
    le = magic in (0xCEFAEDFE, 0xCFFAEDFE)
    en = "<" if le else ">"
    ncmds = struct.unpack_from(en + "I", data, base + 16)[0]
    hdr = 32 if is64 else 28
    off = base + hdr
    cmds = []
    for _ in range(min(ncmds, 512)):
        if off + 8 > len(data):
            out["findings"].append({"type": "load_command_truncated"})
            break
        cmd, size = struct.unpack_from(en + "II", data, off)
        cmds.append(LC_NAMES.get(cmd, hex(cmd)))
        if cmd in (0x21, 0x2C) and off + 16 <= len(data):
            cryptoff, cryptsize, cryptid = struct.unpack_from(en + "III", data, off + 8)
            out["encryption_info"] = {"cryptoff": cryptoff, "cryptsize": cryptsize,
                                      "cryptid": cryptid}
        if size < 8:
            break
        off += size
    out["load_commands"] = cmds
    out["has_code_signature"] = "CODE_SIGNATURE" in cmds


def parse_macho(data: bytes) -> dict:
    out: dict = {"format": "macho", "findings": [], "slices": []}
    try:
        if len(data) < 4:
            out["findings"].append({"type": "not_macho"})
            return out
        magic_be = struct.unpack_from(">I", data, 0)[0]
        if magic_be == FAT:
            out["format"] = "macho_fat"
            n = struct.unpack_from(">I", data, 4)[0]
            for i in range(min(n, 16)):
                o = 8 + i * 20
                if o + 20 > len(data):
                    break
                _cpu, _sub, off, size, _align = struct.unpack_from(">IIIII", data, o)
                out["slices"].append({"offset": off, "size": size})
                sub: dict = {"findings": []}
                if off + 28 <= len(data):
                    _parse_thin(data, off, sub)
                out["slices"][-1]["load_commands"] = sub.get("load_commands", [])
            return out
        _parse_thin(data, 0, out)
    except (struct.error, IndexError) as exc:
        out["findings"].append({"type": "macho_parse_error", "detail": str(exc)})
    return out
