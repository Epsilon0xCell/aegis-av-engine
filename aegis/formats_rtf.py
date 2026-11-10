"""RTF embedded-object extraction (RTF 1.9.1, MS-OXRTFEX).

RTF carries OLE embeddings as \\objdata followed by the object
bytes hex-encoded as text. The parser locates those blobs,
decodes them under a size cap, and returns the embedded bytes
for the caller's scanners: the document is a wrapper, the
embedded object is the content. \\objclass names are recorded
when present.
"""
from __future__ import annotations

import re

MAX_EMBEDDED = 8 * 1024 * 1024
_OBJDATA_RE = re.compile(rb"\\objdata[^a-zA-Z0-9]?", re.IGNORECASE)
_OBJCLASS_RE = re.compile(rb"\\objclass\s*([A-Za-z0-9. ]{1,60})")
_HEXCHARS = set(b"0123456789abcdefABCDEF \t\r\n")


def parse_rtf(data: bytes) -> dict:
    findings: list[dict] = []
    out: dict = {"format": "rtf", "findings": findings,
                 "embedded": []}
    if not data.startswith(b"{\\rtf"):
        findings.append({"type": "not_rtf"})
        return out
    for m in _OBJCLASS_RE.finditer(data):
        findings.append({"type": "rtf_objclass",
                         "class": m.group(1).decode(
                             "ascii", "replace").strip()})
    for m in _OBJDATA_RE.finditer(data):
        start = m.end()
        pos = start
        while pos < len(data) and data[pos] in _HEXCHARS:
            pos += 1
        hextext = re.sub(rb"\s+", b"", data[start:pos])
        if len(hextext) < 32 or len(hextext) % 2:
            continue
        try:
            blob = bytes.fromhex(hextext.decode())
        except ValueError:
            findings.append({"type": "rtf_objdata_undecodable"})
            continue
        if len(blob) > MAX_EMBEDDED:
            findings.append({"type": "rtf_objdata_over_cap",
                             "size": len(blob)})
            continue
        out["embedded"].append(blob)
        findings.append({"type": "rtf_embedded_object",
                         "size": len(blob),
                         "magic": blob[:8].hex()})
    return out
