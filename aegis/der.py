"""A minimal DER reader, just enough for signature blobs.

Full ASN.1 is out of scope. What signature verification needs
is: walk constructed TLVs without choking on hostile lengths,
and find DigestInfo structures (SEQUENCE { SEQUENCE { OID,
params }, OCTET STRING }) inside a PKCS#7 blob. Every length is
bounds-checked; a malformed blob yields nothing, never an
exception and never an over-read.
"""
from __future__ import annotations


def read_tlv(data: bytes, off: int):
    """Return (tag, content_off, content_len, total_len) or None."""
    if off + 2 > len(data):
        return None
    tag = data[off]
    first = data[off + 1]
    pos = off + 2
    if first & 0x80:
        nbytes = first & 0x7F
        if nbytes == 0 or nbytes > 4 or pos + nbytes > len(data):
            return None
        length = int.from_bytes(data[pos:pos + nbytes], "big")
        pos += nbytes
    else:
        length = first
    if pos + length > len(data):
        return None
    return tag, pos, length, (pos - off) + length


def _oid_str(content: bytes) -> str:
    if not content:
        return ""
    parts = [str(content[0] // 40), str(content[0] % 40)]
    value = 0
    for byte in content[1:]:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(str(value))
            value = 0
    return ".".join(parts)


DIGEST_OIDS = {"2.16.840.1.101.3.4.2.1": ("sha256", 32),
               "2.16.840.1.101.3.4.2.2": ("sha384", 48),
               "2.16.840.1.101.3.4.2.3": ("sha512", 64),
               "1.3.14.3.2.26": ("sha1", 20),
               "2.16.840.1.101.3.4.2.4": ("md5", 16)}


def find_digest_infos(data: bytes, depth: int = 0) -> list[dict]:
    """Recursively find DigestInfo-shaped structures."""
    found: list[dict] = []
    if depth > 12 or len(data) < 4:
        return found
    off = 0
    while off < len(data):
        tlv = read_tlv(data, off)
        if tlv is None:
            break
        tag, coff, clen, total = tlv
        content = data[coff:coff + clen]
        if tag == 0x30:  # SEQUENCE: try DigestInfo shape first
            inner = read_tlv(content, 0)
            if inner and inner[0] == 0x30:
                alg_seq_end = inner[3]
                oid_tlv = read_tlv(content, inner[1])
                rest = read_tlv(content, alg_seq_end)
                if oid_tlv and oid_tlv[0] == 0x06 and rest and rest[0] == 0x04:
                    oid = _oid_str(content[oid_tlv[1]:oid_tlv[1] + oid_tlv[2]])
                    digest = content[rest[1]:rest[1] + rest[2]]
                    if oid in DIGEST_OIDS and len(digest) == DIGEST_OIDS[oid][1]:
                        found.append({"algorithm": DIGEST_OIDS[oid][0],
                                      "oid": oid, "digest": digest})
            found.extend(find_digest_infos(content, depth + 1))
        elif tag & 0xE0 == 0xA0 or tag in (0x31,):  # context constructed, SET
            found.extend(find_digest_infos(content, depth + 1))
        off += total
    return found
