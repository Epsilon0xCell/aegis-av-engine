import base64
import hashlib
import io
import struct
import zipfile
import zlib
from pathlib import Path

from aegis import formats
from aegis.engine import Engine
from aegis.formats_evtx import parse_evtx
from aegis.rules import RulePack
from tests.test_v3_phase3 import _certificate as build_certificate

ROOT = Path(__file__).resolve().parent.parent


def _crc(data: bytes) -> int:
    return zlib.crc32(data) & 0xFFFFFFFF


def build_evtx(tamper: bool = False) -> bytes:
    header = bytearray(4096)
    header[0:8] = b"ElfFile\x00"
    struct.pack_into("<Q", header, 24, 2)     # next record id
    struct.pack_into("<H", header, 38, 1)     # chunk count
    struct.pack_into("<I", header, 124, _crc(bytes(header[:120])))
    chunk = bytearray(65536)
    chunk[0:8] = b"ElfChnk\x00"
    struct.pack_into("<Q", chunk, 24, 1)      # first record id
    struct.pack_into("<Q", chunk, 32, 2)      # last record id
    pos = 512
    for record_id in (1, 2):
        body = b"record-body-" + bytes([record_id]) * 8
        size = 24 + len(body)
        size += (4 - size % 4) % 4
        struct.pack_into("<IIQ", chunk, pos, 0x2A2A2A2A, size,
                         record_id)
        chunk[pos + 24:pos + 24 + len(body)] = body
        # trailing size copy at record end
        struct.pack_into("<I", chunk, pos + size - 4, size)
        pos += size
    struct.pack_into("<I", chunk, 48, pos)    # next record offset
    struct.pack_into("<I", chunk, 52, _crc(bytes(chunk[512:pos])))
    struct.pack_into("<I", chunk, 124,
                     _crc(bytes(chunk[:120]) + bytes(chunk[128:512])))
    if tamper:
        chunk[590] ^= 0xFF  # inside the second record's body,
        # inside the CRC-covered region; checksums not repaired
    return bytes(header) + bytes(chunk)


def test_evtx_inventory_and_tamper_tripwire():
    good = parse_evtx(build_evtx())
    assert good["header"]["header_crc_ok"] is True
    assert good["chunks"][0]["records_walked"] == 2
    assert good["chunks"][0]["data_crc_ok"] is True
    bad = parse_evtx(build_evtx(tamper=True))
    assert any(f["type"] == "evtx_chunk_data_crc_mismatch"
               for f in bad["findings"])
    engine = Engine(RulePack(ROOT / "rules" / "core_rules_v2.json"))
    v = engine.scan_bytes(build_evtx(tamper=True), "Security.evtx")
    assert any(e.get("heuristic") == "evtx_tamper_evidence"
               for e in v["evidence"])
    assert engine.scan_bytes(build_evtx(), "Security.evtx")["score"] == 0


def _manifest(entries: dict[str, bytes]) -> bytes:
    lines = ["Manifest-Version: 1.0", ""]
    for name, blob in entries.items():
        digest = base64.b64encode(hashlib.sha256(blob).digest()).decode()
        lines += [f"Name: {name}", f"SHA-256-Digest: {digest}", ""]
    return ("\r\n".join(lines)).encode()


def build_jar(tamper: bool = False) -> bytes:
    entries = {"com/example/App.class": b"\xca\xfe\xba\xbe fake class"}
    manifest = _manifest(entries)
    sf = ("Signature-Version: 1.0\r\nSHA-256-Digest-Manifest: "
          + base64.b64encode(hashlib.sha256(manifest).digest()).decode()
          + "\r\n\r\n").encode()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("META-INF/MANIFEST.MF", manifest)
        zf.writestr("META-INF/CERT.SF", sf)
        zf.writestr("META-INF/CERT.RSA", build_certificate())
        blob = entries["com/example/App.class"]
        zf.writestr("com/example/App.class",
                    blob + (b"X" if tamper else b""))
    return buf.getvalue()


def test_jar_v1_digests_and_signer():
    engine = Engine(RulePack(ROOT / "rules" / "core_rules_v2.json"))
    good = engine.scan_bytes(build_jar(), "app.jar")
    assert good["archive_signing"]["v1"] == {
        "entries_checked": 1, "entries_mismatched": 0}
    assert any(f.get("type") == "jar_signer"
               and "Gavin Test Signing" in str(f)
               for f in good["evidence"])
    bad = engine.scan_bytes(build_jar(tamper=True), "app.jar")
    assert any(e.get("heuristic") == "jar_digest_mismatch"
               for e in bad["evidence"])


def _lp(payload: bytes) -> bytes:
    return struct.pack("<I", len(payload)) + payload


def build_apk_v2() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00 fake")
        zf.writestr("classes.dex", b"dex\n035\x00 fake")
    data = buf.getvalue()
    eocd = data.rfind(b"PK\x05\x06")
    cd_offset = struct.unpack_from("<I", data, eocd + 16)[0]
    cert = build_certificate()
    signed_data = _lp(b"") + _lp(_lp(cert)) + _lp(b"")
    signer = _lp(signed_data) + _lp(b"") + _lp(b"")
    v2_value = _lp(_lp(signer))  # lp(signers)= lp(concat of lp(signer))
    pair = struct.pack("<I", 0x7109871A) + v2_value
    block_body = struct.pack("<Q", len(pair)) + pair
    block_size = len(block_body) + 8 + 16  # trailing size + magic
    block = (struct.pack("<Q", block_size) + block_body
             + struct.pack("<Q", block_size) + b"APK Sig Block 42")
    out = data[:cd_offset] + block + data[cd_offset:]
    new_eocd = out.rfind(b"PK\x05\x06")
    out = (out[:new_eocd + 16]
           + struct.pack("<I", cd_offset + len(block))
           + out[new_eocd + 20:])
    return out


def test_apk_v2_signer_named():
    engine = Engine(RulePack(ROOT / "rules" / "core_rules_v2.json"))
    v = engine.scan_bytes(build_apk_v2(), "app.apk")
    assert v["format"] in ("zip", "zip_container")
    assert any(f.get("type") == "apk_package" for f in v["evidence"])
    assert any(f.get("type") == "apk_v2_signer"
               and "Gavin Test Signing" in str(f)
               for f in v["evidence"])


def test_onenote_identification_only():
    blob = bytes.fromhex("E4525C7B8CD8A74DAEB15378D02996D3") \
        + bytes(200)
    assert formats.identify(blob) == "onenote"
