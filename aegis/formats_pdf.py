"""PDF structural triage: what the file DOES, not what it says.

PDF is a programming environment wearing a document format.
This parser is deliberately structural and tolerant: it does
PDFiD-style keyword triage over a name-normalised copy (PDF
names hex-escape: /Java#53cript is /JavaScript), inventories
action dictionaries, unpacks FlateDecode streams and object
streams under budget, and reports xref anomalies and
encryption. It does not interpret content streams and does not
execute or evaluate JavaScript. Encrypted files are reported
and their streams are not pursued.
"""
from __future__ import annotations

import re
import zlib

KEYWORDS = ["JavaScript", "JS", "OpenAction", "AA", "Launch",
            "EmbeddedFile", "EmbeddedFiles", "Filespec", "URI",
            "SubmitForm", "RichMedia", "XFA", "ObjStm", "XRefStm",
            "Encrypt", "AcroForm", "Page"]
MAX_OBJECTS = 512
MAX_STREAM_BYTES = 4 * 1024 * 1024
ACTION_KINDS = {"JavaScript", "Launch", "URI", "SubmitForm",
                "GoToR", "ImportData", "RichMediaExecute"}

_OBJ_RE = re.compile(rb"(\d+)\s+(\d+)\s+obj\b(.*?)\bendobj", re.DOTALL)
_NAME_ESCAPE = re.compile(rb"#([0-9A-Fa-f]{2})")


def _normalise(data: bytes) -> bytes:
    return _NAME_ESCAPE.sub(
        lambda m: bytes([int(m.group(1), 16)]), data)


def _keyword_counts(norm: bytes) -> dict[str, int]:
    counts = {}
    for kw in KEYWORDS:
        n = len(re.findall(rb"/" + kw.encode() + rb"(?![A-Za-z0-9])", norm))
        if n:
            counts[kw] = n
    return counts


def _stream_bytes(body: bytes) -> tuple[bytes, bytes]:
    idx = body.find(b"stream")
    if idx < 0:
        return body, b""
    start = idx + len(b"stream")
    if body[start:start + 2] == b"\r\n":
        start += 2
    elif body[start:start + 1] in (b"\n", b"\r"):
        start += 1
    end = body.rfind(b"endstream")
    return body[:idx], body[start:end if end > start else len(body)]


def _inflate(raw: bytes) -> bytes | None:
    try:
        d = zlib.decompressobj()
        out = d.decompress(raw, MAX_STREAM_BYTES)
        return out
    except zlib.error:
        return None


def _actions_in(text: bytes, sink: list[dict], where: str) -> None:
    for m in re.finditer(rb"/S\s*/([A-Za-z]+)", text):
        kind = m.group(1).decode("ascii", "replace")
        if kind in ACTION_KINDS:
            sink.append({"kind": kind, "in": where})


def parse_pdf(data: bytes) -> dict:
    findings: list[dict] = []
    out: dict = {"format": "pdf", "findings": findings, "actions": [],
                 "objects": 0, "encrypted": False}
    if not data.startswith(b"%PDF"):
        at = data.find(b"%PDF")
        if at > 0:
            findings.append({"type": "pdf_header_not_at_start",
                             "offset": at})
        else:
            findings.append({"type": "not_pdf"})
            return out
    if b"%%EOF" not in data[-2048:]:
        findings.append({"type": "pdf_no_eof_marker"})
    norm = _normalise(data)
    counts = _keyword_counts(norm)
    out["keywords"] = counts
    if counts.get("Encrypt"):
        out["encrypted"] = True
        findings.append({"type": "pdf_encrypted",
                         "detail": "streams not pursued on encrypted files"})
    objects = _OBJ_RE.findall(data)
    out["objects"] = len(objects)
    if len(objects) > MAX_OBJECTS:
        findings.append({"type": "pdf_object_cap_reached",
                         "objects": len(objects)})
    examined_streams = 0
    objstm_objects = 0
    for num, _gen, body in objects[:MAX_OBJECTS]:
        label = f"object {num.decode()}"
        dict_part, stream = _stream_bytes(body)
        _actions_in(dict_part, out["actions"], label)
        if b"/OpenAction" in dict_part and b"/Catalog" in dict_part:
            findings.append({"type": "pdf_catalog_openaction",
                             "object": num.decode()})
        if out["encrypted"] or not stream:
            continue
        if b"FlateDecode" not in dict_part:
            continue
        inflated = _inflate(stream)
        if inflated is None:
            continue
        examined_streams += 1
        if b"/ObjStm" in dict_part:
            first_m = re.search(rb"/First\s+(\d+)", dict_part)
            n_m = re.search(rb"/N\s+(\d+)", dict_part)
            if first_m and n_m:
                first = int(first_m.group(1))
                header, bodies = inflated[:first], inflated[first:]
                pairs = header.split()
                objstm_objects += len(pairs) // 2
                _actions_in(bodies, out["actions"], f"object stream {num.decode()}")
                findings.append({"type": "pdf_object_stream",
                                 "object": num.decode(),
                                 "contained_objects": len(pairs) // 2})
        else:
            _actions_in(inflated, out["actions"], f"stream of {label}")
    out["examined_streams"] = examined_streams
    out["object_stream_objects"] = objstm_objects
    kinds = [a["kind"] for a in out["actions"]]
    if "JavaScript" in kinds:
        findings.append({"type": "pdf_javascript_action",
                         "count": kinds.count("JavaScript")})
    if "Launch" in kinds:
        findings.append({"type": "pdf_launch_action",
                         "count": kinds.count("Launch")})
    if counts.get("EmbeddedFiles") or counts.get("EmbeddedFile"):
        findings.append({"type": "pdf_embedded_files"})
    # xref sanity: startxref should point at an xref table or an
    # object header (cross-reference stream)
    m = re.search(rb"startxref\s+(\d+)", data[-4096:])
    if m:
        off = int(m.group(1))
        target = data[off:off + 16]
        if not (target.startswith(b"xref")
                or re.match(rb"\d+\s+\d+\s+obj", target)):
            findings.append({"type": "pdf_xref_anomaly",
                             "startxref": off})
    elif not out["encrypted"]:
        findings.append({"type": "pdf_no_startxref"})
    return out
