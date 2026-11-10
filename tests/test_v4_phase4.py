import base64
import struct
from email.message import EmailMessage
from pathlib import Path

from aegis.engine import Engine
from aegis.formats_eml import parse_eml
from aegis.formats_iso import parse_iso
from aegis.formats_lnk import parse_lnk
from aegis.rules import RulePack
from tests.test_v3_phase1 import build_cfb

ROOT = Path(__file__).resolve().parent.parent
CLSID = bytes.fromhex("0114020000000000C000000000000046")


def _engine():
    return Engine(RulePack(ROOT / "rules" / "core_rules_v2.json"))


def build_lnk(arguments: str | None, target: str) -> bytes:
    flags = 0x02 | 0x80  # LinkInfo + Unicode
    if arguments is not None:
        flags |= 0x20
    header = bytearray(76)
    struct.pack_into("<I", header, 0, 0x4C)
    header[4:20] = CLSID
    struct.pack_into("<I", header, 20, flags)
    struct.pack_into("<I", header, 56, 1)
    path = target.encode() + b"\x00"
    info_size = 28 + len(path)
    info = bytearray(info_size)
    struct.pack_into("<IIIIIII", info, 0, info_size, 28, 0x01, 0, 28,
                     0, info_size)
    info[28:28 + len(path)] = path
    out = bytes(header) + bytes(info)
    if arguments is not None:
        enc = arguments.encode("utf-16-le")
        out += struct.pack("<H", len(arguments)) + enc
    return out


def test_lnk_with_encoded_arguments_convicts():
    inner = "# AEGIS-SYNTH-download-cradle AEGIS-SYNTH-hidden-window"
    enc = base64.b64encode(inner.encode("utf-16-le")).decode()
    lnk = build_lnk(f"-enc {enc}",
                    r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")
    parsed = parse_lnk(lnk)
    assert parsed["arguments"] == f"-enc {enc}"
    assert "powershell" in parsed["target_path"]
    v = _engine().scan_bytes(lnk, "invoice.lnk")
    assert any(e.get("type") == "script_layer_match" for e in v["evidence"])
    assert v["verdict"] == "malicious_pattern"
    plain = _engine().scan_bytes(
        build_lnk(None, r"C:\Windows\explorer.exe"), "folder.lnk")
    assert plain["verdict"] == "clean"


def test_eml_attachment_scanned_and_double_extension():
    msg = EmailMessage()
    msg["From"] = "a@example.invalid"
    msg["To"] = "b@example.invalid"
    msg["Subject"] = "invoice"
    msg.set_content("see attached")
    msg.add_attachment(b"AEGIS-SYNTHETIC-RANSOMWARE-PATTERN",
                       maintype="application", subtype="octet-stream",
                       filename="report.pdf.exe")
    data = msg.as_bytes()
    parsed = parse_eml(data)
    types = [f["type"] for f in parsed["findings"]]
    assert "eml_double_extension" in types
    v = _engine().scan_bytes(data, "mail.eml")
    assert any(e.get("type") == "eml_attachment_verdict"
               and e["verdict"] == "malicious_pattern"
               for e in v["evidence"])
    assert v["verdict"] == "malicious_pattern"


def test_rtf_embedded_cfb_scanned():
    cfb = build_cfb()
    rtf = (b"{\\rtf1\\ansi\\deff0 {\\object\\objemb"
           b"{\\*\\objclass Package} {\\*\\objdata "
           + cfb.hex().encode() + b"}}}")
    v = _engine().scan_bytes(rtf, "doc.rtf")
    assert any(e.get("type") == "rtf_embedded_verdict"
               and e["verdict"] == "malicious_pattern"
               for e in v["evidence"])
    assert v["verdict"] == "malicious_pattern"


def build_iso() -> bytes:
    sector = 2048
    lnk = build_lnk(None, r"C:\Windows\explorer.exe")
    readme = b"hello from the image\n"

    def both32(v):
        return struct.pack("<I", v) + struct.pack(">I", v)

    def record(extent, size, is_dir, name: bytes):
        body = bytearray(33 + len(name))
        body[0] = len(body)
        body[2:10] = both32(extent)
        body[10:18] = both32(size)
        body[25] = 2 if is_dir else 0
        body[32] = len(name)
        body[33:33 + len(name)] = name
        return bytes(body)

    root_records = (record(20, sector, True, b"\x00")
                    + record(20, sector, True, b"\x01")
                    + record(21, len(lnk), False, b"OPEN.LNK;1")
                    + record(22, len(readme), False, b"README.TXT;1"))
    root_dir = root_records.ljust(sector, b"\x00")
    root_rec = record(20, sector, True, b"\x00")
    pvd = bytearray(sector)
    pvd[0] = 1
    pvd[1:6] = b"CD001"
    pvd[40:52] = b"AEGIS-TEST  "
    pvd[156:156 + 34] = root_rec
    image = bytearray(23 * sector)
    image[16 * sector:17 * sector] = pvd
    image[20 * sector:21 * sector] = root_dir
    image[21 * sector:21 * sector + len(lnk)] = lnk
    image[22 * sector:22 * sector + len(readme)] = readme
    return bytes(image)


def test_iso_members_scanned():
    image = build_iso()
    parsed = parse_iso(image)
    assert set(parsed["members"]) == {"OPEN.LNK;1", "README.TXT;1"}
    v = _engine().scan_bytes(image, "disc.iso")
    assert v["delivery"]["volume_id"] == "AEGIS-TEST"
    assert v["verdict"] == "clean"  # the LNK inside is benign here
