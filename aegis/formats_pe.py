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
_IMPORT_FUNCTIONS: dict[str, list[str]] = {}


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
                "raw_size": raw_size, "raw_ptr": raw_ptr,
                "entropy": shannon_entropy(blob) if blob else 0.0,
                "executable": bool(chars & CHARACTERISTICS_EXEC)})
            sections_end = max(sections_end, raw_ptr + raw_size)
        out["overlay_bytes"] = max(0, len(data) - sections_end) if sections_end else 0
        imp = out["directories"].get("import")
        if imp:
            _IMPORT_FUNCTIONS.clear()
            out["imports"] = _parse_imports(data, out["sections"], imp["rva"])
            out["import_functions"] = dict(_IMPORT_FUNCTIONS)
        rsrc = out["directories"].get("resource")
        if rsrc:
            out["resources"] = _parse_resources(data, out["sections"],
                                                 rsrc["rva"])
            if out["resources"]:
                out["findings"].append(
                    {"type": "resources_present", "count": len(out["resources"])})
                types = {r["type"] for r in out["resources"]}
                if 16 in types:
                    out["findings"].append({"type": "version_info_present"})
                if 24 in types:
                    out["findings"].append({"type": "app_manifest_present"})
                hot = [r for r in out["resources"]
                       if r["entropy"] > 7.2 and r["size"] > 4096]
                if hot:
                    out["findings"].append(
                        {"type": "high_entropy_resource",
                         "count": len(hot)})
        dbg = out["directories"].get("debug")
        if dbg:
            out["debug"] = _parse_debug(data, out["sections"], dbg["rva"])
            if out["debug"].get("pdb_path"):
                out["findings"].append(
                    {"type": "pdb_path_present",
                     "path": out["debug"]["pdb_path"]})
        dly = out["directories"].get("delayimport")
        if dly:
            out["delay_imports"] = _parse_delay_imports(
                data, out["sections"], dly["rva"],
                out["pe_kind"] == "PE32+")
            if out["delay_imports"]:
                out["findings"].append(
                    {"type": "delay_imports_present",
                     "count": len(out["delay_imports"]),
                     "note": "delay imports are excluded from imphash, "
                             "matching pefile and YARA behaviour"})
        tls = out["directories"].get("tls")
        if tls:
            out["tls_callbacks"] = _parse_tls_callbacks(
                data, out["sections"], tls["rva"],
                out["pe_kind"] == "PE32+")
            if out["tls_callbacks"]:
                secs = sorted({c["section"] for c in out["tls_callbacks"]})
                out["findings"].append(
                    {"type": "tls_callbacks_present",
                     "count": len(out["tls_callbacks"]),
                     "sections": secs})
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


# Ordinal-name resolution exists ONLY for these DLLs in the
# reference implementations (pefile, YARA); every other DLL's
# ordinals stay ord<N>. This table is a documented subset of the
# ws2_32 ordinal map: enough for common sockets imports, and any
# ordinal not listed here stays ord<N> rather than being guessed.
WS2_32_ORDINALS = {1: "accept", 2: "bind", 3: "closesocket", 4: "connect",
                   5: "getpeername", 6: "getsockname", 7: "getsockopt",
                   8: "htonl", 9: "htons", 10: "ioctlsocket", 11: "inet_addr",
                   12: "inet_ntoa", 13: "ntohl", 14: "ntohs", 15: "recv",
                   16: "recvfrom", 17: "select", 18: "send", 19: "sendto",
                   20: "setsockopt", 21: "shutdown", 22: "socket",
                   23: "gethostbyaddr", 24: "gethostbyname", 52: "gethostname",
                   111: "WSAGetLastError", 115: "WSAStartup",
                   116: "WSACleanup", 151: "WSASocketA"}


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
            names: list[str] = []
            if thunk_off is not None:
                step = 8 if _u16(data, coff + 20) == 0x20B else 4
                ordinal_flag = 1 << (63 if step == 8 else 31)
                for j in range(4096):
                    to = thunk_off + j * step
                    if to + step > len(data):
                        break
                    val = int.from_bytes(data[to:to + step], "little")
                    if val == 0:
                        break
                    count += 1
                    if val & ordinal_flag:
                        ordinal = val & 0xFFFF
                        table = (WS2_32_ORDINALS if dll.lower() in
                                 ("ws2_32.dll", "wsock32.dll") else {})
                        names.append(table.get(ordinal, f"ord{ordinal}"))
                    else:
                        name_ptr = to_off(val)
                        if name_ptr is not None and name_ptr + 2 < len(data):
                            end = data.find(b"\x00", name_ptr + 2)
                            if end > 0:
                                names.append(data[name_ptr + 2:end].decode(
                                    "ascii", "replace"))
                            else:
                                names.append("?")
                        else:
                            names.append("?")
            imports[dll] = count
            _IMPORT_FUNCTIONS[dll] = names
    except (struct.error, IndexError):
        return imports
    return imports


RESOURCE_TYPES = {1: "cursor", 2: "bitmap", 3: "icon", 4: "menu",
                  5: "dialog", 6: "string", 7: "fontdir", 8: "font",
                  9: "accelerator", 10: "rcdata", 11: "messagetable",
                  12: "group_cursor", 14: "group_icon", 16: "version",
                  24: "manifest"}


def _parse_resources(data: bytes, sections: list[dict],
                     rsrc_rva: int) -> list[dict]:
    """Walk the 3-level resource tree (type, name, language) to
    its data entries. Bounded: at most 256 directories walked and
    128 leaves collected, every offset bounds-checked."""

    def to_off(rva: int):
        for s in sections:
            start = s["virtual_address"]
            span = max(s["virtual_size"], s["raw_size"])
            if start <= rva < start + span:
                return s["raw_ptr"] + (rva - start)
        return None

    base = to_off(rsrc_rva)
    if base is None:
        return []
    leaves: list[dict] = []
    walked = [0]

    def entries(dir_off: int):
        if dir_off + 16 > len(data) or walked[0] > 256:
            return []
        walked[0] += 1
        named, ids = _u16(data, dir_off + 12), _u16(data, dir_off + 14)
        out = []
        for i in range(min(named + ids, 512)):
            e = dir_off + 16 + i * 8
            if e + 8 > len(data):
                break
            out.append((_u32(data, e), _u32(data, e + 4)))
        return out

    def walk(dir_off: int, path: tuple, depth: int) -> None:
        if len(leaves) >= 128:
            return
        for name_field, off_field in entries(dir_off):
            ident = name_field & 0x7FFFFFFF
            is_dir = bool(off_field & 0x80000000)
            target = base + (off_field & 0x7FFFFFFF)
            if depth < 2 and is_dir:
                walk(target, path + (ident,), depth + 1)
            elif depth == 2 and not is_dir:
                if target + 16 <= len(data):
                    drva, size = _u32(data, target), _u32(data, target + 4)
                    doff = to_off(drva)
                    blob = data[doff:doff + size] if doff is not None else b""
                    if len(blob) == size:
                        leaves.append({
                            "type": path[0] if path else -1,
                            "type_name": RESOURCE_TYPES.get(
                                path[0] if path else -1, "unknown"),
                            "name": path[1] if len(path) > 1 else -1,
                            "language": ident, "size": size,
                            "entropy": round(shannon_entropy(blob), 4)
                            if blob else 0.0})

    walk(base, (), 0)
    return leaves


def _resolve_ordinal(dll: str, ordinal: int) -> str:
    """Ordinal resolution scope, shared with the import parser:
    only the documented Winsock subset resolves to names; every
    other ordinal stays ord<N>, exactly as pefile and YARA do."""
    if dll.lower() in ("ws2_32.dll", "wsock32.dll"):
        return WS2_32_ORDINALS.get(ordinal, f"ord{ordinal}")
    return f"ord{ordinal}"


def _rva_off(sections: list[dict], rva: int):
    for s in sections:
        start = s["virtual_address"]
        span = max(s["virtual_size"], s["raw_size"])
        if start <= rva < start + span:
            return s["raw_ptr"] + (rva - start)
    return None


def _parse_delay_imports(data: bytes, sections: list[dict],
                         dir_rva: int, is64: bool) -> dict:
    """Delay-load import directory: descriptors of 32 bytes,
    terminated by an all-zero entry. Kept strictly separate from
    the import table (and therefore from imphash)."""
    base = _rva_off(sections, dir_rva)
    if base is None:
        return {}
    out: dict[str, list[str]] = {}
    step = 8 if is64 else 4
    for i in range(256):
        off = base + i * 32
        if off + 32 > len(data):
            break
        fields = struct.unpack_from("<8I", data, off)
        if all(v == 0 for v in fields):
            break
        name_rva, int_rva = fields[1], fields[4]  # INT is field 4
        name_off = _rva_off(sections, name_rva)
        if name_off is None:
            continue
        end = data.find(b"\x00", name_off)
        dll = data[name_off:end].decode("ascii", "replace").lower()
        funcs: list[str] = []
        int_off = _rva_off(sections, int_rva)
        if int_off is not None:
            for j in range(4096):
                o = int_off + j * step
                if o + step > len(data):
                    break
                thunk = struct.unpack_from("<Q" if is64 else "<I",
                                           data, o)[0]
                if thunk == 0:
                    break
                if thunk & (0x8000000000000000 if is64 else 0x80000000):
                    ordinal = thunk & 0xFFFF
                    funcs.append(_resolve_ordinal(dll, ordinal))
                else:
                    noff = _rva_off(sections, thunk & 0x7FFFFFFF)
                    if noff is not None and noff + 2 < len(data):
                        e2 = data.find(b"\x00", noff + 2)
                        funcs.append(data[noff + 2:e2].decode(
                            "ascii", "replace"))
        out[dll] = funcs
    return out


def _parse_debug(data: bytes, sections: list[dict], dir_rva: int) -> dict:
    base = _rva_off(sections, dir_rva)
    if base is None:
        return {}
    out: dict = {"entries": []}
    for i in range(64):
        off = base + i * 28
        if off + 28 > len(data):
            break
        (_char, _ts, _maj, _min, dtype, size, _addr,
         ptr) = struct.unpack_from("<IIHHIIII", data, off)
        if dtype == 0 and size == 0:
            break
        entry = {"type": dtype, "size": size}
        if dtype == 2 and ptr and ptr + size <= len(data):  # CodeView
            blob = data[ptr:ptr + size]
            if blob[:4] == b"RSDS" and len(blob) > 24:
                g = struct.unpack_from("<IHH", blob, 4)
                guid = (f"{g[0]:08x}-{g[1]:04x}-{g[2]:04x}-"
                        + blob[12:14].hex() + "-" + blob[14:20].hex())
                entry.update({"format": "RSDS", "guid": guid,
                              "age": _u32(blob, 20),
                              "pdb_path": blob[24:].split(b"\x00")[0]
                              .decode("utf-8", "replace")})
            elif blob[:4] == b"NB10" and len(blob) > 16:
                entry.update({"format": "NB10",
                              "age": _u32(blob, 12),
                              "pdb_path": blob[16:].split(b"\x00")[0]
                              .decode("utf-8", "replace")})
        out["entries"].append(entry)
        if entry.get("pdb_path"):
            out["pdb_path"] = entry["pdb_path"]
            out["guid"] = entry.get("guid")
            out["age"] = entry.get("age")
    return out


def _parse_tls_callbacks(data: bytes, sections: list[dict],
                         dir_rva: int, is64: bool) -> list[dict]:
    base = _rva_off(sections, dir_rva)
    if base is None:
        return []
    pe_off = _u32(data, 0x3C)
    opt = pe_off + 4 + 20
    image_base = struct.unpack_from("<Q" if is64 else "<I", data,
                                    opt + (24 if is64 else 28))[0]
    step = 8 if is64 else 4
    if base + 4 * step > len(data):
        return []
    callbacks_va = struct.unpack_from("<Q" if is64 else "<I", data,
                                      base + 3 * step)[0]
    arr_off = _rva_off(sections, callbacks_va - image_base)
    if arr_off is None:
        return []
    out: list[dict] = []
    for i in range(64):
        o = arr_off + i * step
        if o + step > len(data):
            break
        va = struct.unpack_from("<Q" if is64 else "<I", data, o)[0]
        if va == 0:
            break
        rva = va - image_base
        section = next((s["name"] for s in sections
                        if s["virtual_address"] <= rva
                        < s["virtual_address"]
                        + max(s["virtual_size"], s["raw_size"])), None)
        out.append({"rva": rva, "section": section})
    return out
