import struct
from pathlib import Path

from aegis import authenticode
from aegis.engine import Engine
from aegis.formats_dotnet import parse_dotnet
from aegis.formats_pe import parse_pe
from aegis.rules import RulePack

ROOT = Path(__file__).resolve().parent.parent


# --- .NET builder ---

class _Strings:
    def __init__(self):
        self.blob = bytearray(b"\x00")
        self.index = {}

    def add(self, s: str) -> int:
        if s not in self.index:
            self.index[s] = len(self.blob)
            self.blob += s.encode() + b"\x00"
        return self.index[s]


def _us_heap(texts: list[str]) -> bytes:
    out = bytearray(b"\x00")
    for t in texts:
        raw = t.encode("utf-16-le") + b"\x00"
        assert len(raw) < 0x80
        out.append(len(raw))
        out += raw
    return bytes(out)


def _metadata() -> bytes:
    s = _Strings()
    idx = {name: s.add(name) for name in (
        "MyModule.dll", "MyApp", "MyNamespace", "mscorlib", "MyType",
        "DoThing")}
    us = _us_heap(["https://example.invalid/x",
                   "AEGIS-SYNTHETIC-RANSOMWARE-PATTERN"])
    valid = (1 << 0) | (1 << 1) | (1 << 2) | (1 << 32) | (1 << 35)
    tables = bytearray(struct.pack("<IBBBBQQ", 0, 2, 0, 0, 1, valid, 0))
    tables += struct.pack("<IIIII", 1, 1, 1, 1, 1)  # rows, id order
    body = bytearray()
    # Module: Generation, Name, Mvid, EncId, EncBaseId
    body += struct.pack("<HHHHH", 0, idx["MyModule.dll"], 1, 0, 0)
    # TypeRef: ResolutionScope (AssemblyRef=tag2, row1), Name, Namespace
    body += struct.pack("<HHH", (1 << 2) | 2, idx["MyType"],
                        idx["MyNamespace"])
    # TypeDef: Flags, Name, Namespace, Extends, FieldList, MethodList
    body += struct.pack("<IHHHHH", 0, idx["MyType"], idx["MyNamespace"],
                        0, 1, 1)
    # Assembly: HashAlg, Maj, Min, Build, Rev, Flags, PubKey, Name, Culture
    body += struct.pack("<IHHHHIHHH", 0x8004, 1, 0, 0, 0, 0, 0,
                        idx["MyApp"], 0)
    # AssemblyRef: Maj, Min, Build, Rev, Flags, PubKeyOrToken, Name,
    # Culture, HashValue
    body += struct.pack("<HHHHIHHH", 4, 0, 0, 0, 0, 0,
                        idx["mscorlib"], 0)
    body += struct.pack("<H", 0)
    tables += body
    streams = [("#~", bytes(tables)), ("#Strings", bytes(s.blob)),
               ("#US", us), ("#Blob", b"\x00")]
    version = b"v4.0.30319\x00\x00"
    root = bytearray()
    root += b"BSJB" + struct.pack("<HHI", 1, 1, 0)
    root += struct.pack("<I", len(version)) + version
    root += struct.pack("<HH", 0, len(streams))
    entries = []
    header_size = len(root)
    for name, blob in streams:
        nb = name.encode() + b"\x00"
        nb += b"\x00" * ((4 - len(nb) % 4) % 4)
        entries.append((nb, blob))
        header_size += 8 + len(nb)
    out = bytearray(root)
    pos = header_size
    for nb, blob in entries:
        out += struct.pack("<II", pos, len(blob)) + nb
        pos += len(blob)
    for _nb, blob in entries:
        out += blob
    return bytes(out)


def build_dotnet_pe() -> bytes:
    meta = _metadata()
    clr = bytearray(72)
    struct.pack_into("<I", clr, 0, 72)
    struct.pack_into("<HH", clr, 4, 2, 5)
    struct.pack_into("<II", clr, 8, 0x1000 + 72, len(meta))
    payload = bytes(clr) + meta
    headers = bytearray(0x200)
    headers[0:2] = b"MZ"
    struct.pack_into("<I", headers, 0x3C, 0x80)
    headers[0x80:0x84] = b"PE\x00\x00"
    coff = 0x84
    struct.pack_into("<HHIIIHH", headers, coff, 0x14C, 1, 0x5E2A5A00,
                     0, 0, 0xE0, 0x0102)
    opt = coff + 20
    struct.pack_into("<H", headers, opt, 0x10B)
    struct.pack_into("<I", headers, opt + 92, 16)
    struct.pack_into("<II", headers, opt + 96 + 14 * 8, 0x1000, 72)
    sec = opt + 0xE0
    headers[sec:sec + 6] = b".text\x00"
    struct.pack_into("<IIII", headers, sec + 8, len(payload), 0x1000,
                     len(payload), 0x200)
    struct.pack_into("<I", headers, sec + 36, 0x60000020)
    return bytes(headers) + payload


def test_dotnet_triage():
    data = build_dotnet_pe()
    analysis = parse_pe(data)
    dn = parse_dotnet(data, analysis)
    assert dn["module_name"] == "MyModule.dll", dn
    assert dn["assembly"] == {"name": "MyApp", "version": "1.0.0.0"}
    assert dn["assembly_refs"] == [{"name": "mscorlib",
                                     "version": "4.0.0.0"}]
    assert dn["type_refs"] == ["MyType"]
    assert dn["type_defs"] == ["MyType"]
    assert "https://example.invalid/x" in dn["user_strings"]
    engine = Engine(RulePack(ROOT / "rules" / "core_rules_v2.json"))
    v = engine.scan_bytes(data, "app.exe")
    assert v["dotnet"]["assembly"]["name"] == "MyApp"
    assert any(e.get("type") == "dotnet_user_string_match"
               for e in v["evidence"])
    assert v["verdict"] == "malicious_pattern"


# --- signer identity ---

def _der(tag, content):
    if len(content) < 128:
        return bytes([tag, len(content)]) + content
    return bytes([tag, 0x81, len(content)]) + content


def _name(cn=None, org=None):
    avas = b""
    if cn:
        oid = bytes([0x06, 0x03, 0x55, 0x04, 0x03])
        avas += _der(0x31, _der(0x30, oid + _der(0x0C, cn.encode())))
    if org:
        oid = bytes([0x06, 0x03, 0x55, 0x04, 0x0A])
        avas += _der(0x31, _der(0x30, oid + _der(0x0C, org.encode())))
    return _der(0x30, avas)


def _certificate() -> bytes:
    tbs = _der(0x30,
               _der(0xA0, _der(0x02, b"\x02"))
               + _der(0x02, b"\x12\x34")
               + _der(0x30, bytes([0x06, 0x09, 0x2A, 0x86, 0x48, 0x86,
                                   0xF7, 0x0D, 0x01, 0x01, 0x0B])
                      + _der(0x05, b""))
               + _name(cn="Test Issuer CA")
               + _der(0x30, _der(0x17, b"260101000000Z")
                      + _der(0x17, b"301231235959Z"))
               + _name(cn="Gavin Test Signing", org="Aegis Tests")
               + _der(0x30, b"\x30\x00"))
    return _der(0x30, tbs + _der(0x30, b"\x06\x01\x2a") + _der(0x03, b"\x00\xff"))


def test_signer_identity_extraction():
    from aegis import der
    certs = der.find_certificates(_certificate())
    assert len(certs) == 1
    cert = certs[0]
    assert cert["subject"]["CN"] == "Gavin Test Signing"
    assert cert["subject"]["O"] == "Aegis Tests"
    assert cert["issuer"]["CN"] == "Test Issuer CA"
    assert cert["serial_hex"] == "1234"
    assert cert["not_before"] == "260101000000Z"
    assert "NAMES this signer" in cert["meaning"]


def test_signer_identity_inside_signed_pe():
    from tests.test_v2_phase3 import _signed_pe
    # the phase-2 fixture's blob has no certificate: signers empty,
    # and nothing claims otherwise
    result = authenticode.verify_authenticode(_signed_pe())
    assert result["status"] == "match"
    assert result["signers"] == []
