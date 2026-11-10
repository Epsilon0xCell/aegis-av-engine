"""Email (RFC 5322 / MIME) attachment extraction.

An email is a container whose members arrive with filenames
someone chose for them. This module walks the MIME tree with
the standard library's email package, inventories every part,
and returns attachment bytes for the caller's scanners.
Filename signals are recorded as findings: double extensions
(doc.pdf.exe) and executable extensions on attachments. The
message body is inventory, not content; attachments are the
content.
"""
from __future__ import annotations

import email
import hashlib
import re
from email import policy

MAX_ATTACHMENT_BYTES = 8 * 1024 * 1024
EXECUTABLE_EXTS = {".exe", ".scr", ".com", ".bat", ".cmd", ".vbs",
                   ".js", ".jse", " .wsf", ".wsf", ".hta", ".lnk",
                   ".ps1", ".msi", ".jar", ".dll"}
DOC_EXTS = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".txt",
            ".jpg", ".png", ".zip", ".rtf"}


def _extensions(filename: str) -> list[str]:
    parts = filename.lower().rsplit(".", 3)
    return ["." + p for p in parts[1:]] if len(parts) > 1 else []


def parse_eml(data: bytes) -> dict:
    findings: list[dict] = []
    out: dict = {"format": "eml", "findings": findings,
                 "attachments": [], "parts": 0}
    try:
        msg = email.message_from_bytes(data, policy=policy.default)
    except Exception as exc:
        findings.append({"type": "eml_parse_error",
                         "error": type(exc).__name__})
        return out
    out["subject"] = str(msg.get("Subject", ""))[:120]
    for part in msg.walk():
        out["parts"] += 1
        filename = part.get_filename()
        ctype = part.get_content_type()
        payload = None
        if part.get_content_maintype() != "multipart":
            try:
                payload = part.get_payload(decode=True)
            except Exception:
                payload = None
        if filename:
            exts = _extensions(filename)
            record = {"filename": filename, "content_type": ctype,
                      "size": len(payload) if payload else 0,
                      "sha256": (hashlib.sha256(payload).hexdigest()
                                 if payload else None),
                      "data": payload}
            if exts and exts[-1].strip() in EXECUTABLE_EXTS:
                findings.append({"type": "eml_executable_attachment",
                                 "filename": filename})
                if len(exts) >= 2 and exts[-2] in DOC_EXTS:
                    findings.append({"type": "eml_double_extension",
                                     "filename": filename})
            if payload and len(payload) > MAX_ATTACHMENT_BYTES:
                findings.append({"type": "eml_attachment_over_cap",
                                 "filename": filename})
                record["data"] = None
            out["attachments"].append(record)
            findings.append({"type": "eml_attachment",
                             "filename": filename,
                             "content_type": ctype,
                             "size": record["size"]})
    return out
