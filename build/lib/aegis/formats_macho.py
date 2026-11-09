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
        if cmd == 0x1D and off + 16 <= len(data):  # LC_CODE_SIGNATURE
            dataoff, datasize = struct.unpack_from(en + "II", data, off + 8)
            out["code_signature_blob"] = {"offset": dataoff, "size": datasize}
            _parse_superblob(data, base, dataoff, out)
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


CSMAGIC_EMBEDDED_SIGNATURE = 0xFADE0CC0
CSMAGIC_CODEDIRECTORY = 0xFADE0C02
CS_HASH = {1: "sha1", 2: "sha256", 4: "sha384"}


def _parse_superblob(data: bytes, base: int, dataoff: int, out: dict) -> None:
    """Parse the (big-endian) superblob and CodeDirectory, then do
    the part presence checks cannot: recompute every code page
    hash and compare it with the signed slot. A mismatch names
    the exact page that no longer matches its signature."""
    import hashlib as _hl
    start = base + dataoff
    if start + 12 > len(data):
        out["findings"].append({"type": "code_signature_truncated"})
        return
    magic, length, count = struct.unpack_from(">III", data, start)
    if magic != CSMAGIC_EMBEDDED_SIGNATURE:
        out["findings"].append({"type": "code_signature_bad_magic"})
        return
    out["superblob"] = {"length": length, "blob_count": count}
    for i in range(min(count, 64)):
        e = start + 12 + i * 8
        if e + 8 > len(data):
            break
        btype, boff = struct.unpack_from(">II", data, e)
        blob = start + boff
        if blob + 4 > len(data):
            continue
        bmagic = struct.unpack_from(">I", data, blob)[0]
        if bmagic != CSMAGIC_CODEDIRECTORY:
            continue
        if blob + 52 > len(data):
            continue
        (_, blen, _ver, flags, hash_off, _ident_off, n_special, n_code,
         code_limit) = struct.unpack_from(">IIIIIIIII", data, blob)
        hash_size, hash_type, _platform, page_exp = struct.unpack_from(
            ">BBBB", data, blob + 36)
        out["code_directory"] = {
            "length": blen, "flags": flags, "n_special": n_special,
            "n_code_slots": n_code, "code_limit": code_limit,
            "hash_size": hash_size, "hash_type": hash_type,
            "page_size": 1 << page_exp}
        alg = CS_HASH.get(hash_type)
        if alg is None or hash_size == 0:
            out["findings"].append({"type": "code_signature_unverifiable_hash",
                                    "hash_type": hash_type})
            return
        digestmod = getattr(_hl, alg)
        hashes_start = blob + hash_off - n_special * hash_size
        page_size = 1 << page_exp
        bad: list[int] = []
        checked = 0
        for slot in range(n_code):
            page_start = base + slot * page_size
            page_end = base + min((slot + 1) * page_size, code_limit)
            if page_start >= page_end:
                break
            stored_off = hashes_start + (n_special + slot) * hash_size
            if stored_off + hash_size > len(data):
                break
            stored = data[stored_off:stored_off + hash_size]
            actual = digestmod(data[page_start:page_end]).digest()
            checked += 1
            if stored != actual[:hash_size]:
                bad.append(slot)
        special_bad = 0
        out["page_hash_verification"] = {
            "checked": checked, "ok": checked - len(bad),
            "bad_pages": bad, "special_bad": special_bad}
        if bad:
            out["findings"].append({"type": "code_signature_page_mismatch",
                                    "pages": bad})
        elif checked:
            out["findings"].append({"type": "code_signature_pages_verified",
                                    "pages": checked})
        return
    out["findings"].append({"type": "code_signature_no_codedirectory"})
