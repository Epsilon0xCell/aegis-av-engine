import struct
from pathlib import Path

from aegis.engine import Engine
from aegis.formats_cfb import ENDOFCHAIN, FATSECT, FREESECT, parse_cfb
from aegis.ovba import analyze_vba, decompress_container
from aegis.rules import RulePack

ROOT = Path(__file__).resolve().parent.parent
END = ENDOFCHAIN
FREE = FREESECT


def _lit_compress(data: bytes) -> bytes:
    """Literal-only MS-OVBA container (valid per spec: compressed
    chunks whose tokens are all literals)."""
    out = bytearray(b"\x01")
    for i in range(0, len(data), 4096):
        block = data[i:i + 4096]
        comp = bytearray()
        for j in range(0, len(block), 8):
            comp.append(0)
            comp += block[j:j + 8]
        header = ((2 + len(comp)) - 3) | 0x8000
        out += struct.pack("<H", header)
        out += comp
    return bytes(out)


def _dir_records() -> bytes:
    recs = bytearray()
    def rec(rid, blob):
        recs.extend(struct.pack("<HI", rid, len(blob)))
        recs.extend(blob)
    rec(0x0001, struct.pack("<I", 1))
    rec(0x0003, struct.pack("<H", 1252))
    rec(0x0004, b"Project")
    rec(0x000F, struct.pack("<H", 1))
    rec(0x0019, b"Module1")
    rec(0x001A, b"Module1")
    rec(0x0031, struct.pack("<I", 10))
    rec(0x0021, struct.pack("<I", 0))
    return bytes(recs)


def build_cfb(vba=True, purged=False, cyclic=False) -> bytes:
    sector = 512
    module_source = (b"Sub AutoOpen()\r\n"
                     b"' AEGIS-SYNTHETIC-RANSOMWARE-PATTERN\r\n"
                     b"End Sub\r\n")
    module_stream = b"PERFCACHE!" + _lit_compress(module_source)
    dir_stream = _lit_compress(_dir_records())
    vba_project = bytes(7) if purged else bytes(range(40))
    project_text = b'Name="Project"\r\nCMG="8CEF"\r\n'
    big = bytes(4600)
    # minisectors: dir(0,1) Module1(2,3) _VBA_PROJECT(4) PROJECT(5)
    mini_blobs = []
    def add_mini(blob):
        start = len(mini_blobs)
        for i in range(0, len(blob), 64):
            mini_blobs.append(blob[i:i + 64].ljust(64, b"\x00"))
        return start
    dir_start = add_mini(dir_stream)
    mod_start = add_mini(module_stream)
    vbp_start = add_mini(vba_project)
    proj_start = add_mini(project_text)
    ministream = b"".join(mini_blobs)
    minifat = [FREE] * 128
    def chain_minifat(start, blob):
        n = (len(blob) + 63) // 64
        for i in range(n):
            minifat[start + i] = start + i + 1 if i + 1 < n else END
    chain_minifat(dir_start, dir_stream)
    chain_minifat(mod_start, module_stream)
    chain_minifat(vbp_start, vba_project)
    chain_minifat(proj_start, project_text)

    def entry(name, typ, left, right, child, start, size):
        e = bytearray(128)
        nb = name.encode("utf-16-le") + b"\x00\x00"
        e[:len(nb)] = nb
        struct.pack_into("<H", e, 64, len(nb))
        e[66] = typ
        struct.pack_into("<III", e, 68, left, right, child)
        struct.pack_into("<I", e, 116, start)
        struct.pack_into("<Q", e, 120, size)
        return bytes(e)

    entries = [
        entry("Root Entry", 5, FREE, FREE, 1 if vba else 5, 2,
              len(ministream)),
        entry("VBA", 1, 5, FREE, 2, 0, 0) if vba else bytes(128),
        entry("dir", 2, FREE, 3, FREE, dir_start, len(dir_stream))
        if vba else bytes(128),
        entry("Module1", 2, FREE, 4, FREE, mod_start, len(module_stream))
        if vba else bytes(128),
        entry("_VBA_PROJECT", 2, FREE, FREE, FREE, vbp_start,
              len(vba_project)) if vba else bytes(128),
        entry("BigStream", 2, FREE, 6, FREE, 7, len(big)),
        entry("PROJECT", 2, FREE, FREE, FREE, proj_start,
              len(project_text)),
        bytes(128),
    ]
    dir_bytes = b"".join(entries)
    fat = [FREE] * 128
    fat[0] = FATSECT
    fat[1] = 6
    fat[2] = END
    fat[3] = END
    fat[6] = END
    for s in range(7, 15):
        fat[s] = s + 1
    fat[15] = 7 if cyclic else END
    header = bytearray(512)
    header[:8] = bytes.fromhex("D0CF11E0A1B11AE1")
    struct.pack_into("<HHHHH", header, 24, 0x003E, 3, 0xFFFE, 9, 6)
    struct.pack_into("<I", header, 44, 1)
    struct.pack_into("<I", header, 48, 1)
    struct.pack_into("<I", header, 56, 4096)
    struct.pack_into("<I", header, 60, 3)
    struct.pack_into("<I", header, 64, 1)
    struct.pack_into("<I", header, 68, END)
    struct.pack_into("<I", header, 72, 0)
    struct.pack_into("<I", header, 76, 0)
    for i in range(1, 109):
        struct.pack_into("<I", header, 76 + i * 4, FREE)
    big_sectors = [big[i * 512:(i + 1) * 512].ljust(512, b"\x00")
                   for i in range(9)]
    sectors = [
        struct.pack("<128I", *fat),
        dir_bytes[:512],
        ministream.ljust(512, b"\x00"),
        struct.pack("<128I", *minifat),
        bytes(512), bytes(512),
        dir_bytes[512:],
        *big_sectors,
    ]
    return bytes(header) + b"".join(sectors)


def test_decompress_literal_roundtrip_and_copy_token():
    payload = bytes(range(256)) * 3 + b"tail"
    assert decompress_container(_lit_compress(payload)) == payload
    # hand-derived copy-token vector: literal A, then copy
    # offset 1 length 19 -> 20 A's total
    chunk = struct.pack("<H", 0x8003) + bytes([0x02]) + b"A" + b"\x10\x00"
    assert decompress_container(b"\x01" + chunk) == b"A" * 20
    assert decompress_container(b"") == b""
    assert decompress_container(b"\x02garbage") == b""


def test_cfb_parse_and_vba_inventory():
    result = parse_cfb(build_cfb())
    names = {e["name"] for e in result["entries"]}
    assert {"VBA", "dir", "Module1", "_VBA_PROJECT", "BigStream",
            "PROJECT"} <= names
    assert len(result["streams"]["BigStream"]) == 4600
    vba = analyze_vba(result)
    assert vba["present"]
    assert vba["project_info"]["project_name"] == "Project"
    assert vba["project_info"]["module_count"] == 1
    (module,) = vba["modules"]
    assert module["name"] == "Module1"
    assert module["text_offset"] == 10
    assert module["source_status"] == "present"
    source = vba["module_sources"]["Module1"]
    assert b"AEGIS-SYNTHETIC-RANSOMWARE-PATTERN" in source
    types = [f["type"] for f in vba["findings"]]
    assert "vba_project_protected" in types


def test_cfb_purged_shape_and_clean_document():
    vba = analyze_vba(parse_cfb(build_cfb(purged=True)))
    assert any(f["type"] == "vba_purged_shape" for f in vba["findings"])
    clean = analyze_vba(parse_cfb(build_cfb(vba=False)))
    assert not clean["present"]
    assert clean["findings"] == []


def test_cfb_cyclic_fat_is_a_finding_not_a_hang():
    result = parse_cfb(build_cfb(cyclic=True))
    assert any(f["type"] == "cfb_cyclic_chain" for f in result["findings"])


def test_engine_scores_vba_source():
    engine = Engine(RulePack(ROOT / "rules" / "core_rules_v2.json"))
    v = engine.scan_bytes(build_cfb(), "legacy.doc")
    assert v["format"] == "cfb"
    assert v["cfb"] is not None
    assert any(e.get("type") == "vba_rule_match" for e in v["evidence"])
    assert v["verdict"] == "malicious_pattern"
