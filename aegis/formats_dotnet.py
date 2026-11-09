""".NET metadata triage (ECMA-335), stdlib only.

Reads the CLR header and the metadata root, walks the #Strings
and #US heaps, and parses the #~ tables stream far enough to
answer the triage questions: what is this assembly called, what
does it reference, what types does it declare and import, and
what user strings does it carry? User strings are returned for
the caller's matchers with their provenance named.

Explicitly out of scope: IL disassembly, strong-name
verification, signature decoding, Portable PDB. Row layouts and
coded-index definitions follow ECMA-335 II.24; the parser is
bounded throughout and returns what parsed, with findings for
what did not.
"""
from __future__ import annotations

import struct

MAX_US_STRINGS = 128
MAX_NAME_LIST = 64

CODED = {
    "TypeDefOrRef": (2, [2, 1, 27]),
    "HasConstant": (2, [4, 8, 23]),
    "HasCustomAttribute": (5, [6, 4, 1, 2, 8, 9, 10, 0, 14, 23, 20,
                              17, 26, 27, 32, 35, 38, 39, 40, 42, 44, 43]),
    "HasFieldMarshal": (1, [4, 8]),
    "HasDeclSecurity": (2, [2, 6, 32]),
    "MemberRefParent": (3, [2, 1, 26, 6, 27]),
    "HasSemantics": (1, [20, 23]),
    "MethodDefOrRef": (1, [6, 10]),
    "MemberForwarded": (1, [4, 6]),
    "Implementation": (2, [38, 35, 39]),
    "CustomAttributeType": (3, [6, 10]),
    "ResolutionScope": (2, [0, 26, 35, 1]),
    "TypeOrMethodDef": (1, [2, 6]),
}

# column kinds: ("w", bytes) fixed width; ("s",) #Strings index;
# ("g",) #GUID index; ("b",) #Blob index; ("i", table) simple
# index; ("c", name) coded index
SCHEMAS = {
    0: [("w", 2), ("s",), ("g",), ("g",), ("g",)],
    1: [("c", "ResolutionScope"), ("s",), ("s",)],
    2: [("w", 4), ("s",), ("s",), ("c", "TypeDefOrRef"), ("i", 4),
        ("i", 6)],
    3: [("i", 4)],
    4: [("w", 2), ("s",), ("b",)],
    5: [("i", 6)],
    6: [("w", 4), ("w", 2), ("w", 2), ("s",), ("b",), ("i", 8)],
    7: [("i", 8)],
    8: [("w", 2), ("w", 2), ("s",)],
    9: [("i", 2), ("c", "TypeDefOrRef")],
    10: [("c", "MemberRefParent"), ("s",), ("b",)],
    11: [("w", 2), ("c", "HasConstant"), ("b",)],
    12: [("c", "HasCustomAttribute"), ("c", "CustomAttributeType"),
         ("b",)],
    13: [("c", "HasFieldMarshal"), ("b",)],
    14: [("w", 2), ("c", "HasDeclSecurity"), ("b",)],
    15: [("w", 2), ("w", 4), ("i", 2)],
    16: [("w", 4), ("i", 4)],
    17: [("b",)],
    18: [("i", 2), ("i", 20)],
    19: [("i", 20)],
    20: [("w", 2), ("s",), ("c", "TypeDefOrRef")],
    21: [("i", 2), ("i", 23)],
    22: [("i", 23)],
    23: [("w", 2), ("s",), ("b",)],
    24: [("w", 2), ("i", 6), ("c", "HasSemantics")],
    25: [("i", 2), ("c", "MethodDefOrRef"), ("c", "MethodDefOrRef")],
    26: [("s",)],
    27: [("b",)],
    28: [("w", 2), ("c", "MemberForwarded"), ("s",), ("i", 26)],
    29: [("w", 4), ("i", 4)],
    30: [("w", 4), ("w", 4)],
    31: [("w", 4)],
    32: [("w", 4), ("w", 2), ("w", 2), ("w", 2), ("w", 2), ("w", 4),
         ("b",), ("s",), ("s",)],
    33: [("w", 4)],
    34: [("w", 4), ("w", 4), ("w", 4)],
    35: [("w", 2), ("w", 2), ("w", 2), ("w", 2), ("w", 4), ("b",),
         ("s",), ("s",), ("b",)],
    36: [("w", 4), ("i", 35)],
    37: [("w", 4), ("w", 4), ("w", 4), ("i", 35)],
    38: [("w", 4), ("s",), ("b",)],
    39: [("w", 4), ("w", 4), ("s",), ("s",), ("c", "Implementation")],
    40: [("w", 4), ("w", 4), ("s",), ("c", "Implementation")],
    41: [("i", 2), ("i", 2)],
    42: [("w", 2), ("w", 2), ("c", "TypeOrMethodDef"), ("s",)],
    43: [("c", "MethodDefOrRef"), ("b",)],
    44: [("i", 42), ("c", "TypeDefOrRef")],
}


def _index_size(table: int, rows: dict[int, int]) -> int:
    return 2 if rows.get(table, 0) < 65536 else 4


def _coded_size(name: str, rows: dict[int, int]) -> int:
    bits, tables = CODED[name]
    biggest = max((rows.get(t, 0) for t in tables), default=0)
    return 2 if biggest < (1 << (16 - bits)) else 4


def _column_size(col, rows, heap_sizes) -> int:
    kind = col[0]
    if kind == "w":
        return col[1]
    if kind == "s":
        return 4 if heap_sizes & 0x01 else 2
    if kind == "g":
        return 4 if heap_sizes & 0x02 else 2
    if kind == "b":
        return 4 if heap_sizes & 0x04 else 2
    if kind == "i":
        return _index_size(col[1], rows)
    return _coded_size(col[1], rows)


def _read_index(data: bytes, off: int, size: int) -> int:
    return int.from_bytes(data[off:off + size], "little")


def _compressed_uint(data: bytes, off: int) -> tuple[int, int]:
    first = data[off]
    if first & 0x80 == 0:
        return first, 1
    if first & 0xC0 == 0x80:
        return ((first & 0x3F) << 8) | data[off + 1], 2
    return ((first & 0x1F) << 24) | (data[off + 1] << 16) \
        | (data[off + 2] << 8) | data[off + 3], 4


def parse_dotnet(data: bytes, pe_analysis: dict) -> dict:
    from .formats_pe import _rva_off
    findings: list[dict] = []
    out: dict = {"format": "dotnet", "findings": findings}
    sections = pe_analysis.get("sections", [])
    clr = (pe_analysis.get("directories") or {}).get("clr")
    if not clr:
        findings.append({"type": "no_clr_directory"})
        return out
    clr_off = _rva_off(sections, clr["rva"])
    if clr_off is None or clr_off + 72 > len(data):
        findings.append({"type": "clr_header_out_of_range"})
        return out
    meta_rva, meta_size = struct.unpack_from("<II", data, clr_off + 8)
    out["runtime_version"] = (f"{struct.unpack_from('<H', data, clr_off + 4)[0]}"
                              f".{struct.unpack_from('<H', data, clr_off + 6)[0]}")
    meta_off = _rva_off(sections, meta_rva)
    if meta_off is None or meta_off + 32 > len(data) \
            or data[meta_off:meta_off + 4] != b"BSJB":
        findings.append({"type": "dotnet_metadata_root_missing"})
        return out
    ver_len = struct.unpack_from("<I", data, meta_off + 12)[0]
    version = data[meta_off + 16:meta_off + 16 + ver_len].split(b"\x00")[0]
    out["metadata_version"] = version.decode("ascii", "replace")
    pos = meta_off + 16 + ((ver_len + 3) & ~3)
    n_streams = struct.unpack_from("<H", data, pos + 2)[0]
    pos += 4
    streams: dict[str, tuple[int, int]] = {}
    for _ in range(min(n_streams, 16)):
        off, size = struct.unpack_from("<II", data, pos)
        pos += 8
        name_bytes = bytearray()
        while pos < len(data) and data[pos] != 0:
            name_bytes.append(data[pos])
            pos += 1
        pos += 1
        pos = meta_off + ((pos - meta_off + 3) & ~3)
        streams[name_bytes.decode("ascii", "replace")] = (
            meta_off + off, size)
    out["streams"] = sorted(streams)

    def heap(name):
        if name in streams:
            o, s = streams[name]
            return data[o:o + s]
        return b""

    strings = heap("#Strings")

    def get_string(idx: int) -> str:
        if idx == 0 or idx >= len(strings):
            return ""
        end = strings.find(b"\x00", idx)
        return strings[idx:end if end > idx else len(strings)].decode(
            "utf-8", "replace")

    us = heap("#US")
    user_strings: list[str] = []
    p = 1  # first byte of #US is a reserved zero
    while p < len(us) and len(user_strings) < MAX_US_STRINGS:
        try:
            length, used = _compressed_uint(us, p)
        except IndexError:
            break
        blob = us[p + used:p + used + length]
        if len(blob) < 1:
            break
        text = blob[:-1].decode("utf-16-le", "replace")
        if text:
            user_strings.append(text)
        p += used + max(length, 1)
    out["user_strings"] = user_strings

    tables_heap = heap("#~") or heap("#-")
    if not tables_heap:
        findings.append({"type": "dotnet_tables_stream_missing"})
        return out
    heap_sizes = tables_heap[6]
    valid = struct.unpack_from("<Q", tables_heap, 8)[0]
    present = [t for t in range(45) if valid >> t & 1]
    rows: dict[int, int] = {}
    pos = 24
    for t in present:
        rows[t] = struct.unpack_from("<I", tables_heap, pos)[0]
        pos += 4
    out["tables"] = {str(t): rows[t] for t in present}

    def row_values(table: int, row_index: int, base: int):
        schema = SCHEMAS[table]
        off = base
        values = []
        for r in range(row_index + 1):
            values = []
            cur = off
            for col in schema:
                size = _column_size(col, rows, heap_sizes)
                values.append(_read_index(tables_heap, cur, size))
                cur += size
            row_size = cur - off
            off += row_size
            if r == row_index:
                return values, row_size
        return values, 0

    table_bases: dict[int, int] = {}
    cursor = pos
    for t in present:
        table_bases[t] = cursor
        size = sum(_column_size(c, rows, heap_sizes) for c in SCHEMAS[t])
        cursor += size * rows[t]
    out["tables_end_ok"] = cursor <= len(tables_heap)

    def strings_of(table: int, name_col: int, extra_col: int | None = None):
        names = []
        for i in range(min(rows.get(table, 0), MAX_NAME_LIST)):
            vals, _ = row_values(table, i, table_bases[table])
            names.append(get_string(vals[name_col]))
        return names

    if rows.get(0):
        vals, _ = row_values(0, 0, table_bases[0])
        out["module_name"] = get_string(vals[1])
    if rows.get(32):
        vals, _ = row_values(32, 0, table_bases[32])
        out["assembly"] = {
            "name": get_string(vals[7]),
            "version": f"{vals[1]}.{vals[2]}.{vals[3]}.{vals[4]}"}
    if rows.get(35):
        refs = []
        for i in range(min(rows[35], MAX_NAME_LIST)):
            vals, _ = row_values(35, i, table_bases[35])
            refs.append({"name": get_string(vals[6]),
                         "version": f"{vals[0]}.{vals[1]}.{vals[2]}.{vals[3]}"})
        out["assembly_refs"] = refs
    if rows.get(1):
        out["type_refs"] = strings_of(1, 1)
    if rows.get(2):
        out["type_defs"] = strings_of(2, 1)
    if rows.get(10):
        out["member_refs"] = strings_of(10, 1)
    findings.append({"type": "dotnet_assembly",
                     "module": out.get("module_name"),
                     "assembly": (out.get("assembly") or {}).get("name"),
                     "user_strings": len(user_strings),
                     "tables": len(present)})
    return out
