"""Authenticode image-hash recomputation, honestly bounded.

Without a trust store this engine cannot and does not say
"trusted publisher". What it CAN do, with no trust store at
all, is recompute the Authenticode image hash from the file
(the hash the signer actually signed, per Microsoft's
specification: everything except the CheckSum field, the
certificate-table directory entry, and the certificate table
itself) and compare it against the messageDigest stored inside
the PKCS#7 blob. Outcomes:

- match:    the bytes are exactly what was signed
- mismatch: the file was modified or a signature transplanted
            after signing; a finding, stated in those words
- no table / no extractable digest: reported as such, never
  dressed up as either of the above
"""
from __future__ import annotations

import hashlib
import struct

from . import der

ALGORITHMS = {"sha1": hashlib.sha1, "sha256": hashlib.sha256,
              "sha384": hashlib.sha384, "sha512": hashlib.sha512,
              "md5": hashlib.md5}


def image_hash(data: bytes, algorithm: str = "sha256") -> dict:
    """Recompute the Authenticode image hash. Returns the digest
    plus the layout facts used, or a reason it cannot be done."""
    if len(data) < 0x40 or data[:2] != b"MZ":
        return {"status": "not_pe"}
    pe_off = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe_off:pe_off + 4] != b"PE\x00\x00":
        return {"status": "not_pe"}
    coff = pe_off + 4
    opt_size = struct.unpack_from("<H", data, coff + 16)[0]
    opt = coff + 20
    magic = struct.unpack_from("<H", data, opt)[0]
    is64 = magic == 0x20B
    checksum_off = opt + 64
    dir_start = opt + (112 if is64 else 96)
    security_entry_off = dir_start + 4 * 8
    if security_entry_off + 8 > opt + opt_size:
        return {"status": "no_directory_space"}
    cert_off, cert_size = struct.unpack_from("<II", data, security_entry_off)
    h = ALGORITHMS[algorithm]()
    h.update(data[:checksum_off])
    h.update(data[checksum_off + 4:security_entry_off])
    h.update(data[security_entry_off + 8:])
    # the certificate table itself is excluded: rewind what was
    # hashed past it by hashing in two parts instead when present
    if cert_size and cert_off and cert_off < len(data):
        h = ALGORITHMS[algorithm]()
        end_of_signed = len(data) - cert_size
        h.update(data[:checksum_off])
        h.update(data[checksum_off + 4:security_entry_off])
        h.update(data[security_entry_off + 8:end_of_signed])
        excess = data[cert_off + cert_size:]
        if excess:
            h.update(excess)
    return {"status": "computed", "algorithm": algorithm,
            "digest": h.hexdigest(),
            "cert_table": {"offset": cert_off, "size": cert_size}}


def verify_authenticode(data: bytes) -> dict:
    base = image_hash(data, "sha256")
    if base["status"] != "computed":
        return {"status": base["status"]}
    cert = base["cert_table"]
    if not cert["size"] or not cert["offset"]:
        return {"status": "no_certificate_table",
                "image_hash_sha256": base["digest"]}
    blob = data[cert["offset"] + 8:cert["offset"] + cert["size"]]
    infos = der.find_digest_infos(blob)
    if not infos:
        return {"status": "digest_not_extracted",
                "image_hash_sha256": base["digest"],
                "cert_table": cert}
    signers = der.find_certificates(blob)
    results = []
    matched = False
    for info in infos:
        if info["algorithm"] == "sha256":
            computed = base["digest"]
        else:
            computed = image_hash(data, info["algorithm"])["digest"]
        ok = computed == info["digest"].hex()
        matched = matched or ok
        results.append({"algorithm": info["algorithm"], "match": ok,
                        "stored": info["digest"].hex(), "computed": computed})
    return {"status": "match" if matched else "mismatch",
            "signers": signers,
            "image_hash_sha256": base["digest"], "digests": results,
            "cert_table": cert,
            "meaning": ("bytes match what was signed" if matched else
                        "file modified or signature transplanted after signing")}
