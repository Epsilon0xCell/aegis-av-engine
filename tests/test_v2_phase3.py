import hashlib
import io
import random
import struct
import zipfile
from pathlib import Path

from aegis import authenticode
from aegis.calibration import _cal_pe
from aegis.engine import Engine
from aegis.formats_elf import parse_elf
from aegis.formats_macho import parse_macho
from aegis.formats_pe import parse_pe
from aegis.rules import RulePack

ROOT = Path(__file__).resolve().parent.parent


def _engine():
    return Engine(RulePack(ROOT / "rules" / "core_rules_v2.json"))


# --- OOXML ---

def _docx(external=True, template=False, macro=False):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("[Content_Types].xml", "<Types/>")
        z.writestr("word/document.xml", "<w:document/>")
        rels = ['<?xml version="1.0"?>'
                '<Relationships xmlns="http://schemas.openxmlformats.org/'
                'package/2006/relationships">']
        if external:
            rels.append('<Relationship Id="rId1" Type="http://schemas.'
                        'openxmlformats.org/officeDocument/2006/'
                        'relationships/hyperlink" '
                        'Target="https://example.invalid/page" '
                        'TargetMode="External"/>')
        if template:
            rels.append('<Relationship Id="rId2" Type="http://schemas.'
                        'openxmlformats.org/officeDocument/2006/'
                        'relationships/attachedTemplate" '
                        'Target="https://example.invalid/t.dotm" '
                        'TargetMode="External"/>')
        rels.append("</Relationships>")
        z.writestr("word/_rels/document.xml.rels", "".join(rels))
        if macro:
            z.writestr("word/vbaProject.bin", b"fake macro project")
    return buf.getvalue()


def test_ooxml_external_relationship_finding():
    v = _engine().scan_bytes(_docx(), "a.docx")
    types = [f["type"] for f in v["container"]["findings"]]
    assert "ooxml_package" in types
    assert "ooxml_external_relationship" in types
    assert "ooxml_remote_template" not in types


def test_ooxml_remote_template_scores_and_macro_flagged():
    v = _engine().scan_bytes(_docx(template=True, macro=True), "b.docx")
    types = [f["type"] for f in v["container"]["findings"]]
    assert "ooxml_remote_template" in types
    assert "ooxml_macro_project" in types
    assert any(e.get("heuristic") == "ooxml_remote_template"
               for e in v["evidence"])
    assert v["score"] >= 25


# --- Authenticode ---

SHA256_OID = bytes([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
                    0x04, 0x02, 0x01])


def _der(tag, content):
    if len(content) < 128:
        return bytes([tag, len(content)]) + content
    return bytes([tag, 0x81, len(content)]) + content


def _signed_pe():
    rng = random.Random(3)
    pe = bytearray(_cal_pe(rng, timestamp=0x5E2A5A00,
                            section_blob=bytes(512)))
    opt = 0x98
    security_entry = opt + 96 + 4 * 8
    # placeholder pass to learn the digest over the signed region
    struct.pack_into("<II", pe, security_entry, len(pe), 8)
    digest = authenticode.image_hash(bytes(pe) + b"\x00" * 8)["digest"]
    digest_info = _der(0x30, _der(0x30, SHA256_OID + b"\x05\x00")
                       + _der(0x04, bytes.fromhex(digest)))
    blob = _der(0x30, digest_info)
    cert = struct.pack("<IHH", 8 + len(blob), 0x0200, 0x0002) + blob
    struct.pack_into("<II", pe, security_entry, len(pe), len(cert))
    return bytes(pe) + cert


def test_authenticode_match_and_tamper():
    signed = _signed_pe()
    result = authenticode.verify_authenticode(signed)
    assert result["status"] == "match", result
    tampered = bytearray(signed)
    tampered[600] ^= 0xFF  # inside the section data
    result2 = authenticode.verify_authenticode(bytes(tampered))
    assert result2["status"] == "mismatch", result2
    v = _engine().scan_bytes(bytes(tampered), "tampered.exe")
    assert v["authenticode"]["status"] == "mismatch"
    assert any(e.get("type") == "authenticode_mismatch" for e in v["evidence"])


def test_authenticode_no_table_is_reported_plainly():
    rng = random.Random(3)
    pe = _cal_pe(rng, timestamp=0x5E2A5A00, section_blob=bytes(512))
    assert authenticode.verify_authenticode(pe)["status"] == \
        "no_certificate_table"


# --- PE resources ---

def test_pe_resources_version_info():
    rng = random.Random(3)
    blob = bytearray(4096)
    pe = bytearray(_cal_pe(rng, timestamp=0x5E2A5A00,
                           section_blob=bytes(blob)))
    tree_at = 0x1000 - (0x80 + 4 + 20 + 0xE0 + 40)  # inside section bytes
    vs = b"VS_VERSION_INFO" + bytes(80)
    tree = bytearray(112 + len(vs))
    struct.pack_into("<HH", tree, 12, 0, 1)          # root: 1 id entry
    struct.pack_into("<II", tree, 16, 16, 0x80000000 | 32)
    struct.pack_into("<HH", tree, 32 + 12, 0, 1)     # name dir
    struct.pack_into("<II", tree, 32 + 16, 1, 0x80000000 | 64)
    struct.pack_into("<HH", tree, 64 + 12, 0, 1)     # language dir
    struct.pack_into("<II", tree, 64 + 16, 1033, 96)
    struct.pack_into("<II", tree, 96, 0x1000 + 112, len(vs))
    tree[112:112 + len(vs)] = vs
    pe[0x80 + 4 + 20 + 0xE0 + 40 + tree_at:
       0x80 + 4 + 20 + 0xE0 + 40 + tree_at + len(tree)] = tree
    opt = 0x98
    struct.pack_into("<I", pe, opt + 92, 16)  # NumberOfRvaAndSizes
    struct.pack_into("<II", pe, opt + 96 + 2 * 8, 0x1000, len(tree))
    analysis = parse_pe(bytes(pe))
    assert analysis["resources"], analysis["findings"]
    first = analysis["resources"][0]
    assert first["type"] == 16 and first["type_name"] == "version"
    assert any(f["type"] == "version_info_present"
               for f in analysis["findings"])


# --- Mach-O code signature page verification ---

def _signed_macho(tamper=False):
    page = 256
    header = struct.pack("<IIIIIIII", 0xFEEDFACF, 0x01000007, 3, 2,
                         1, 16, 0, 0)
    code = bytearray(header + struct.pack("<IIII", 0x1D, 16, 0, 0)
                     + bytes(1024))
    code_limit = len(code)
    n_pages = (code_limit + page - 1) // page
    # datasize is knowable before hashing (it does not depend on
    # the hashes), and page 0 covers the load command itself, so
    # both fields must be final before any page hash is computed
    ident_len = len(b"testbin\x00")
    cd_len = (52 + ident_len) + n_pages * 32
    struct.pack_into("<I", code, 32 + 8, code_limit)            # dataoff
    struct.pack_into("<I", code, 32 + 12, 12 + 8 + cd_len)     # datasize
    hashes = b"".join(
        hashlib.sha256(bytes(code[i * page:(i + 1) * page])).digest()
        for i in range(n_pages))
    ident = b"testbin\x00"
    hash_off = 52 + len(ident)
    cd = struct.pack(">IIIIIIIII", 0xFADE0C02, hash_off + len(hashes),
                     0x20100, 0, hash_off, 52, 0, n_pages, code_limit)
    cd += struct.pack(">BBBB", 32, 2, 0, 8) + struct.pack(">I", 0)
    cd += struct.pack(">I", 0)  # scatter
    cd += struct.pack(">I", 0)  # team offset (v0x20100)
    assert len(cd) == 52
    cd = cd + ident + hashes
    superblob = struct.pack(">III", 0xFADE0CC0, 12 + 8 + len(cd), 1)
    superblob += struct.pack(">II", 0, 12 + 8)
    superblob += cd
    assert len(superblob) == 12 + 8 + cd_len
    data = bytes(code) + superblob
    if tamper:
        data = bytearray(data)
        data[100] ^= 0xFF
        data = bytes(data)
    return data


def test_macho_page_hashes_verify_and_tamper():
    ok = parse_macho(_signed_macho())
    assert ok["code_directory"]["n_code_slots"] >= 4, ok
    ver = ok["page_hash_verification"]
    assert ver["ok"] == ver["checked"] and ver["checked"] >= 4, ok
    assert any(f["type"] == "code_signature_pages_verified"
               for f in ok["findings"])
    bad = parse_macho(_signed_macho(tamper=True))
    assert bad["page_hash_verification"]["bad_pages"] == [0], bad
    assert any(f["type"] == "code_signature_page_mismatch"
               for f in bad["findings"])


# --- ELF notes ---

def test_elf_build_id_and_flags():
    build_id = bytes.fromhex("ab" * 20)
    note = struct.pack("<III", 4, 20, 3) + b"GNU\x00" + build_id
    hdr = bytearray(64)
    hdr[0:4] = b"\x7fELF"
    hdr[4] = 2  # 64-bit
    hdr[5] = 1  # LE
    struct.pack_into("<HHI", hdr, 16, 2, 0x3E, 1)
    struct.pack_into("<Q", hdr, 32, 64)          # phoff
    struct.pack_into("<HH", hdr, 52, 64, 56)     # ehsize, phentsize
    struct.pack_into("<H", hdr, 56, 1)           # phnum
    phdr = struct.pack("<IIQQQQQQ", 4, 0, 120, 0, 0, len(note),
                       len(note), 4)
    data = bytes(hdr) + phdr + note
    analysis = parse_elf(data)
    assert analysis["build_id"] == "ab" * 20
    assert any(f["type"] == "elf_build_id" for f in analysis["findings"])
