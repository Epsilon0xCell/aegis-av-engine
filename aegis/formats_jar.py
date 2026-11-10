"""JAR / APK signing triage: v1 digests and the v2 block.

Two signing schemes, two bounded checks, one wording rule
(the Authenticode rule): a signer is NAMED from the embedded
certificate; no chain or trust evaluation is performed.

JAR v1 (and APK v1): META-INF/MANIFEST.MF carries a digest
per entry; this module recomputes each entry's digest from
the archive bytes and compares. META-INF/*.SF carries a
digest of the whole manifest, also recomputed. The signature
block (*.RSA/.DSA/.EC) contributes signer names only.

APK Signature Scheme v2: the signing block sits immediately
before the ZIP central directory, ending with the magic
"APK Sig Block 42". The v2 pair (ID 0x7109871a) is parsed
for its first signer's first certificate, which is named.
Digest verification inside the v2 block is out of scope for
triage and the output says so.
"""
from __future__ import annotations

import base64
import hashlib
import io
import struct
import zipfile

from . import der

V2_BLOCK_ID = 0x7109871A
SIG_BLOCK_MAGIC = b"APK Sig Block 42"


def _parse_manifest(text: str) -> list[dict]:
    sections = []
    current: dict = {}
    last_key = None
    for raw_line in text.replace("\r\n", "\n").split("\n"):
        if raw_line.startswith(" ") and last_key:
            current[last_key] += raw_line[1:]
            continue
        if not raw_line.strip():
            if current:
                sections.append(current)
            current, last_key = {}, None
            continue
        if ": " in raw_line:
            key, _, value = raw_line.partition(": ")
            current[key] = value
            last_key = key
    if current:
        sections.append(current)
    return sections


def _digest_name(section: dict) -> tuple[str, str] | None:
    for key, value in section.items():
        if key.endswith("-Digest") and key != "SHA-256-Digest-Manifest":
            algo = key.split("-Digest")[0].lower().replace("-", "")
            return algo, value
    return None


def _signing_block(data: bytes) -> dict | None:
    eocd = data.rfind(b"PK\x05\x06")
    if eocd < 0 or eocd + 22 > len(data):
        return None
    cd_offset = struct.unpack_from("<I", data, eocd + 16)[0]
    if cd_offset < 24 or data[cd_offset - 16:cd_offset] != SIG_BLOCK_MAGIC:
        return None
    size = struct.unpack_from("<Q", data, cd_offset - 24)[0]
    # the size counts the whole block except its own first
    # field, so the block starts size + 8 bytes before the
    # central directory
    start = cd_offset - size - 8
    if start < 0:
        return None
    pairs = {}
    body = data[start + 8:cd_offset - 24]
    pos = 0
    while pos + 12 <= len(body):
        pair_len = struct.unpack_from("<Q", body, pos)[0]
        if pair_len < 4 or pos + 8 + pair_len > len(body):
            break
        pair_id = struct.unpack_from("<I", body, pos + 8)[0]
        pairs[pair_id] = body[pos + 12:pos + 8 + pair_len]
        pos += 8 + pair_len
    return {"size": size, "pair_ids": sorted(hex(p) for p in pairs),
            "pairs": pairs}


def _v2_signer_names(block: dict) -> list[dict]:
    value = block["pairs"].get(V2_BLOCK_ID)
    if not value:
        return []

    def lp(buf, off):
        if off + 4 > len(buf):
            return None, off
        n = struct.unpack_from("<I", buf, off)[0]
        return buf[off + 4:off + 4 + n], off + 4 + n

    names = []
    signers, _ = lp(value, 0)
    if signers is None:
        return names
    off = 0
    while off < len(signers):
        signer, off = lp(signers, off)
        if signer is None:
            break
        signed_data, soff = lp(signer, 0)
        if signed_data is None:
            continue
        _digests, doff = lp(signed_data, 0)
        certs, _coff = lp(signed_data, doff)
        if certs is None:
            continue
        coff = 0
        while coff < len(certs):
            cert, coff = lp(certs, coff)
            if cert is None:
                break
            names.extend(der.find_certificates(cert))
            break  # first certificate per signer is the signer
    return names


def analyze_archive(data: bytes) -> dict:
    """Triage for ZIP-shaped archives; the caller routes by
    format. Returns {} when nothing signing-related exists."""
    findings: list[dict] = []
    out: dict = {"findings": findings}
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        return out
    names = set(zf.namelist())
    if "AndroidManifest.xml" in names:
        findings.append({"type": "apk_package"})
    manifest_name = "META-INF/MANIFEST.MF"
    if manifest_name in names:
        manifest = zf.read(manifest_name)
        sections = _parse_manifest(manifest.decode("utf-8", "replace"))
        checked = mismatched = 0
        for section in sections:
            entry = section.get("Name")
            found = _digest_name(section)
            if not entry or not found or entry not in names:
                continue
            algo, expected_b64 = found
            try:
                digest = hashlib.new(algo, zf.read(entry)).digest()
            except (ValueError, KeyError):
                continue
            checked += 1
            if base64.b64encode(digest).decode() != expected_b64.strip():
                mismatched += 1
                findings.append({"type": "jar_entry_digest_mismatch",
                                 "entry": entry})
        out["v1"] = {"entries_checked": checked,
                     "entries_mismatched": mismatched}
        findings.append({"type": "jar_v1_digests",
                         "checked": checked, "mismatched": mismatched})
        for name in sorted(names):
            if name.startswith("META-INF/") and name.endswith(".SF"):
                sf = _parse_manifest(
                    zf.read(name).decode("utf-8", "replace"))
                for section in sf:
                    expected = section.get("SHA-256-Digest-Manifest")
                    if expected:
                        actual = base64.b64encode(
                            hashlib.sha256(manifest).digest()).decode()
                        findings.append({
                            "type": "jar_manifest_digest",
                            "file": name,
                            "match": actual == expected.strip()})
            if name.startswith("META-INF/") and name.rsplit(".", 1)[-1] \
                    in ("RSA", "DSA", "EC"):
                for cert in der.find_certificates(zf.read(name)):
                    findings.append({"type": "jar_signer",
                                     "file": name, **cert})
    block = _signing_block(data)
    if block:
        findings.append({"type": "apk_signing_block",
                         "pair_ids": block["pair_ids"]})
        for cert in _v2_signer_names(block):
            findings.append({"type": "apk_v2_signer", **cert})
        out["v2"] = {"present": V2_BLOCK_ID in block["pairs"],
                     "digest_verification": "out of scope for triage"}
    return out
