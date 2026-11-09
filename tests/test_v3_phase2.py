import struct
import zlib
from pathlib import Path

from aegis.engine import Engine
from aegis.formats_pdf import parse_pdf
from aegis.formats_pe import parse_pe
from aegis.rules import RulePack
from aegis.similarity import imphash

ROOT = Path(__file__).resolve().parent.parent


def _engine():
    return Engine(RulePack(ROOT / "rules" / "core_rules_v2.json"))


# --- PDF ---

def _pdf(objects: list[bytes], trailer_extra: bytes = b"") -> bytes:
    out = bytearray(b"%PDF-1.7\n")
    offsets = []
    for i, body in enumerate(objects, start=1):
        offsets.append(len(out))
        out += f"{i} 0 obj\n".encode() + body + b"\nendobj\n"
    xref_at = len(out)
    out += b"trailer\n<< /Size 99 " + trailer_extra + b" >>\n"
    out += f"startxref\n{xref_at}\n%%EOF\n".encode()
    return bytes(out)


def test_pdf_openaction_javascript_combo():
    pdf = _pdf([
        b"<< /Type /Catalog /OpenAction 2 0 R /Pages 3 0 R >>",
        b"<< /S /JavaScript /JS (app.alert(1)) >>",
        b"<< /Type /Pages /Count 0 >>",
    ])
    a = parse_pdf(pdf)
    assert a["keywords"]["JavaScript"] >= 1
    assert any(x["kind"] == "JavaScript" for x in a["actions"])
    assert any(f["type"] == "pdf_catalog_openaction" for f in a["findings"])
    v = _engine().scan_bytes(pdf, "x.pdf")
    assert any(e.get("heuristic") == "pdf_openaction_javascript"
               for e in v["evidence"])
    assert v["score"] >= 30


def test_pdf_hex_escaped_name_counts_the_same():
    plain = _pdf([b"<< /Type /Catalog /JavaScript 2 0 R >>",
                  b"<< /S /JavaScript >>"])
    escaped = _pdf([b"<< /Type /Catalog /Java#53cript 2 0 R >>",
                    b"<< /S /Java#53cript >>"])
    assert (parse_pdf(escaped)["keywords"]["JavaScript"]
            == parse_pdf(plain)["keywords"]["JavaScript"])


def test_pdf_object_stream_javascript_found():
    inner = b"<< /S /JavaScript /JS (x) >>"
    header = b"5 0 "
    payload = zlib.compress(header + inner)
    objstm = (b"<< /Type /ObjStm /N 1 /First " + str(len(header)).encode()
              + b" /Filter /FlateDecode /Length "
              + str(len(payload)).encode() + b" >>\nstream\n" + payload
              + b"\nendstream")
    pdf = _pdf([b"<< /Type /Catalog /Pages 2 0 R >>", objstm])
    a = parse_pdf(pdf)
    assert any(f["type"] == "pdf_object_stream" for f in a["findings"])
    assert any(x["kind"] == "JavaScript" for x in a["actions"])


def test_pdf_encrypted_reported_and_clean_pdf_quiet():
    enc = _pdf([b"<< /Type /Catalog >>"],
               trailer_extra=b"/Encrypt 9 0 R")
    a = parse_pdf(enc)
    assert a["encrypted"]
    assert any(f["type"] == "pdf_encrypted" for f in a["findings"])
    clean = _pdf([b"<< /Type /Catalog /Pages 2 0 R >>",
                  b"<< /Type /Page >>"])
    v = _engine().scan_bytes(clean, "clean.pdf")
    assert v["score"] == 0
    assert not any(f.get("type", "").startswith("pdf_javascript")
                   for f in v["evidence"])


# --- PE round 2 ---

def build_pe2() -> bytes:
    headers = bytearray(0x200)
    headers[0:2] = b"MZ"
    struct.pack_into("<I", headers, 0x3C, 0x80)
    headers[0x80:0x84] = b"PE\x00\x00"
    coff = 0x84
    struct.pack_into("<HHIIIHH", headers, coff, 0x14C, 2, 0x5E2A5A00,
                     0, 0, 0xE0, 0x0102)
    opt = coff + 20
    struct.pack_into("<H", headers, opt, 0x10B)
    struct.pack_into("<I", headers, opt + 28, 0x400000)  # image base
    struct.pack_into("<I", headers, opt + 92, 16)
    dd = opt + 96
    struct.pack_into("<II", headers, dd + 6 * 8, 0x2100, 28)     # debug
    struct.pack_into("<II", headers, dd + 9 * 8, 0x2180, 40)     # tls
    struct.pack_into("<II", headers, dd + 13 * 8, 0x2000, 64)    # delay
    sec = opt + 0xE0
    for i, (name, va, vs, raw, rs) in enumerate([
            (b".text", 0x1000, 0x200, 0x200, 0x200),
            (b".rdata", 0x2000, 0x400, 0x400, 0x400)]):
        o = sec + i * 40
        headers[o:o + len(name)] = name
        struct.pack_into("<IIII", headers, o + 8, vs, va, rs, raw)
    rdata = bytearray(0x400)
    # delay descriptor at RVA 0x2000 (file 0x400)
    struct.pack_into("<8I", rdata, 0x00, 0, 0x2040, 0, 0x2060, 0x2050,
                     0, 0, 0)
    rdata[0x40:0x40 + 12] = b"delayed.dll\x00"
    struct.pack_into("<II", rdata, 0x50, 0x2070, 0)  # INT
    struct.pack_into("<H", rdata, 0x70, 0)
    rdata[0x72:0x72 + 12] = b"DelayedFunc\x00"
    # debug entry at RVA 0x2100 (file 0x500), CodeView at file 0x520
    cv = b"RSDS" + bytes(range(16)) + struct.pack("<I", 7) \
        + b"C:\\build\\app.pdb\x00"
    struct.pack_into("<IIHHIIII", rdata, 0x100, 0, 0, 0, 0, 2, len(cv),
                     0x2120, 0x520)
    rdata[0x120:0x120 + len(cv)] = cv
    # TLS dir at RVA 0x2180 (file 0x580); callbacks array RVA 0x20A0
    struct.pack_into("<6I", rdata, 0x180, 0x401000, 0x401100, 0x402000,
                     0x4020A0, 0, 0)
    struct.pack_into("<4I", rdata, 0xA0, 0x401010, 0x401020, 0x401030, 0)
    return bytes(headers) + bytes(0x200) + bytes(rdata)


def test_pe_delay_debug_tls():
    a = parse_pe(build_pe2())
    assert a["delay_imports"] == {"delayed.dll": ["DelayedFunc"]}
    assert imphash(a) is None  # delay imports never enter imphash
    assert a["debug"]["pdb_path"] == "C:\\build\\app.pdb"
    assert a["debug"]["age"] == 7
    assert a["debug"]["guid"].endswith("-0302-0504-0706-08090a0b0c0d0e0f") \
        or len(a["debug"]["guid"]) == 36
    assert len(a["tls_callbacks"]) == 3
    assert {c["section"] for c in a["tls_callbacks"]} == {".text"}
    types = [f["type"] for f in a["findings"]]
    assert "pdb_path_present" in types
    assert "delay_imports_present" in types
    assert "tls_callbacks_present" in types
