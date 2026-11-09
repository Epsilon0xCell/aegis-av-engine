import gzip
import io
import struct
import tarfile
import zipfile
from pathlib import Path

import pytest

from aegis import containers
from aegis.budget import ScanBudget
from aegis.corpora import EICAR
from aegis.engine import Engine
from aegis.formats_elf import parse_elf
from aegis.formats_macho import parse_macho
from aegis.formats_pe import parse_pe
from aegis.rules import RulePack

PACK = Path(__file__).resolve().parent.parent / "rules" / "core_rules.json"


@pytest.fixture()
def engine():
    return Engine(RulePack(PACK))


def _zip_bytes(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, blob in files.items():
            zf.writestr(name, blob)
    return buf.getvalue()


def test_zip_member_scanned_and_flagged(engine):
    blob = _zip_bytes({"inner.txt": EICAR.encode(), "ok.txt": b"hello world"})
    v = engine.scan_bytes(blob, "bundle.zip")
    assert v["container"]["kind"] == "zip"
    verdicts = {m["name"]: m["verdict"] for m in v["container"]["members"]}
    assert verdicts["inner.txt"] == "malicious_pattern"
    assert verdicts["ok.txt"] == "clean"
    assert v["verdict"] == "malicious_pattern"


def test_zip_bomb_ratio_budget(engine):
    blob = _zip_bytes({"zeros.bin": b"\x00" * (3 * 1024 * 1024)})
    budget = ScanBudget()
    result = containers.scan_container(blob, engine.scan_bytes, budget)
    kinds = [f.get("kind") for f in result.findings]
    assert "ratio" in kinds or "total" in kinds or "per_entry" in kinds


def test_nested_zip_depth_budget(engine):
    blob = EICAR.encode()
    for _ in range(8):
        blob = _zip_bytes({"level.zip": blob})
    result = containers.scan_container(blob, engine.scan_bytes, ScanBudget())
    assert any(f["type"] == "budget_exceeded" and f["kind"] == "depth"
               for f in result.findings)


def test_tar_traversal_name_blocked(engine):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        info = tarfile.TarInfo("../escape.txt")
        data = b"nope"
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
    result = containers.scan_container(buf.getvalue(), engine.scan_bytes, ScanBudget())
    assert any(f["type"] == "traversal_name" for f in result.findings)
    assert result.members == []


def test_gzip_member(engine):
    blob = gzip.compress(b"plain text content")
    v = engine.scan_bytes(blob, "f.gz")
    assert v["container"]["kind"] == "gzip"
    assert v["container"]["members"][0]["verdict"] == "clean"


def _minimal_pe() -> bytes:
    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)
    coff = struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, 0xE0, 0x0002)
    opt = bytearray(0xE0)
    struct.pack_into("<H", opt, 0, 0x10B)          # PE32
    struct.pack_into("<I", opt, 92, 16)            # number of directories
    section = bytearray(40)
    section[0:5] = b".text"
    struct.pack_into("<I", section, 8, 0x100)      # virtual size
    struct.pack_into("<I", section, 12, 0x1000)    # virtual address
    struct.pack_into("<I", section, 16, 4)         # raw size
    struct.pack_into("<I", section, 20, 0x80 + 4 + 20 + 0xE0 + 40)  # raw ptr, after the section table
    struct.pack_into("<I", section, 36, 0x2000)    # executable
    return bytes(dos) + b"PE\x00\x00" + coff + bytes(opt) + bytes(section) + b"\x90\x90\xc3\x00"


def test_pe_parser_sections_and_features():
    pe = parse_pe(_minimal_pe())
    assert pe["pe_kind"] == "PE32"
    assert len(pe["sections"]) == 1 and pe["sections"][0]["name"] == ".text"
    assert pe["sections"][0]["executable"] is True
    assert pe["overlay_bytes"] == 0


def test_pe_parser_truncated_is_finding_not_crash():
    pe = parse_pe(b"MZ" + b"\x00" * 10)
    assert pe["findings"]


def _minimal_elf() -> bytes:
    hdr = bytearray(64)
    hdr[0:4] = b"\x7fELF"
    hdr[4] = 2  # 64-bit
    hdr[5] = 1  # little endian
    struct.pack_into("<H", hdr, 16, 2)
    struct.pack_into("<H", hdr, 18, 62)
    struct.pack_into("<Q", hdr, 32, 64)   # phoff
    struct.pack_into("<H", hdr, 52, 64)   # ehsize
    struct.pack_into("<H", hdr, 54, 56)   # phentsize
    struct.pack_into("<H", hdr, 56, 1)    # phnum
    ph = struct.pack("<IIQQQQQQ", 1, 5, 0, 0x400000, 0x400000, 120, 120, 0x1000)
    return bytes(hdr) + ph


def test_elf_parser():
    elf = parse_elf(_minimal_elf())
    assert elf["bits"] == 64 and elf["program_headers"] == ["LOAD"]
    assert elf["interpreter"] is None


def test_macho_parser():
    # thin 64-bit little-endian Mach-O with one SYMTAB load command
    hdr = struct.pack("<IIIIIIII", 0xFEEDFACF, 0x01000007, 3, 2, 1, 24, 0, 0)
    lc = struct.pack("<II", 0x2, 24) + b"\x00" * 16
    m = parse_macho(hdr + lc)
    assert m["load_commands"] == ["SYMTAB"]
    assert m["has_code_signature"] is False
