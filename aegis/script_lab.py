"""Script deobfuscation-lite: bounded transforms, layered truth.

Scripts hide intent behind encoding layers. This module peels
the layers that are pure functions of the text, each with a
hard budget (4 layers deep, 8 candidates per layer, 1 MiB per
layer): Base64 literals and FromBase64String arguments
(including the UTF-16LE form PowerShell's -EncodedCommand
uses), JavaScript atob, [char] code arrays, VBScript Chr()
chains, quoted-string concatenation, backtick escapes, and
hex escape runs. Every recovered layer is returned for the
caller's matchers with its kind and depth named.

Doctrine: encoding is not evidence. An encoded layer is a
finding, never a score. Scores come only from what the
recovered content matches, and from high-risk API signals that
appear only after decoding. Constructs that cannot be resolved
statically (the -f format operator, ScriptBlock.Create,
variable-driven invocation) are reported as
unresolved_constructs, never executed and never guessed at.
"""
from __future__ import annotations

import base64
import binascii
import re

MAX_DEPTH = 4
MAX_CANDIDATES = 8
MAX_LAYER_BYTES = 1024 * 1024

HIGH_RISK_APIS = [
    "invoke-expression", "invoke-command", "downloadstring",
    "downloadfile", "net.webclient", "frombase64string",
    "virtualalloc", "createprocess", "shellexecute",
    "wscript.shell", "activexobject", "add-type",
    "start-process", "certutil", "bitsadmin", "mshta",
    "regsvr32", "rundll32",
]

UNRESOLVED_PATTERNS = [
    (re.compile(r"\s-f\s"), "-f format operator"),
    (re.compile(r"scriptblock\]::create|\[scriptblock\]::create",
                re.IGNORECASE), "ScriptBlock.Create"),
    (re.compile(r"\binvoke\s*\(", re.IGNORECASE),
     "dynamic Invoke()"),
]

_B64_RE = re.compile(rb"[A-Za-z0-9+/]{24,}={0,2}")
_FROMB64_RE = re.compile(
    r"FromBase64String\(\s*['\"]([A-Za-z0-9+/=\s]{16,})['\"]\s*\)",
    re.IGNORECASE)
_ATOB_RE = re.compile(
    r"atob\(\s*['\"]([A-Za-z0-9+/=\s]{16,})['\"]\s*\)",
    re.IGNORECASE)
_CHAR_ARRAY_RE = re.compile(
    r"(?:\[char\]\s*)?(\d{2,3})((?:\s*[,+]\s*(?:\[char\]\s*)?"
    r"\d{2,3}){5,})")
_CHR_RE = re.compile(r"Chr\(\s*(\d{1,3})\s*\)", re.IGNORECASE)
_CONCAT_RE = re.compile(r"(['\"])((?:(?!\1).){1,60})\1\s*\+\s*"
                        r"(['\"])((?:(?!\3).){1,60})\3")
_HEX_RUN_RE = re.compile(rb"(?:\\x[0-9A-Fa-f]{2}){6,}")


def _try_b64(text: str) -> list[tuple[str, bytes]]:
    out = []
    cleaned = re.sub(r"\s+", "", text)
    try:
        raw = base64.b64decode(cleaned, validate=True)
    except (binascii.Error, ValueError):
        return out
    if len(raw) >= 4 and len(raw) % 2 == 0:
        # UTF-16LE text is recognised by its shape, not by the
        # decoder's permissiveness: for the ASCII-dominant text
        # scripts actually carry, most high bytes are zero. A
        # bare decode accepts almost any even-length bytes as
        # CJK codepoints, which misclassified plain ASCII
        # payloads during development.
        high = raw[1::2]
        if high and high.count(0) / len(high) >= 0.4:
            try:
                decoded = raw.decode("utf-16-le")
                out.append(("base64_utf16", decoded.encode()))
                return out
            except UnicodeDecodeError:
                pass
    try:
        decoded = raw.decode("utf-8")
        if all(32 <= ord(c) < 127 or c in "\r\n\t" for c in decoded):
            out.append(("base64_ascii", raw))
    except UnicodeDecodeError:
        pass
    return out


def _extract_layers(data: bytes) -> list[tuple[str, bytes]]:
    """One peeling step: all candidate layers inside data."""
    found: list[tuple[str, bytes]] = []
    try:
        text = data.decode("utf-8", "replace")
    except Exception:
        return found
    for m in _FROMB64_RE.finditer(text):
        for kind, blob in _try_b64(m.group(1)):
            found.append((f"frombase64string_{kind}", blob))
    for m in _ATOB_RE.finditer(text):
        for kind, blob in _try_b64(m.group(1)):
            found.append((f"atob_{kind}", blob))
    seen_b64 = set()
    for m in _B64_RE.finditer(data):
        token = m.group().decode()
        if token in seen_b64:
            continue
        seen_b64.add(token)
        for kind, blob in _try_b64(token):
            found.append((kind, blob))
    for m in _CHAR_ARRAY_RE.finditer(text):
        nums = [int(x) for x in re.findall(r"\d{2,3}", m.group(0))]
        if all(0 <= n < 256 for n in nums):
            found.append(("char_array",
                          bytes(nums).decode("utf-8", "replace")
                          .encode()))
    chr_hits = _CHR_RE.findall(text)
    if len(chr_hits) >= 6:
        found.append(("chr_chain",
                      bytes(int(n) for n in chr_hits
                            if int(n) < 256).decode(
                                "utf-8", "replace").encode()))
    joined = _CONCAT_RE.findall(text)
    if joined:
        merged = "".join(a + b for _q1, a, _q2, b in
                         [(m[0], m[1], m[2], m[3]) for m in joined])
        if len(merged) >= 8:
            found.append(("concat_strings", merged.encode()))
    if "`" in text:
        found.append(("backtick_removed",
                      text.replace("`", "").encode()))
    for m in _HEX_RUN_RE.finditer(data):
        raw = bytes(int(m.group()[i + 2:i + 4], 16)
                    for i in range(0, len(m.group()), 4))
        found.append(("hex_escapes", raw))
    dedup: list[tuple[str, bytes]] = []
    seen = set()
    for kind, blob in found:
        if not blob or len(blob) > MAX_LAYER_BYTES:
            continue
        key = (kind, blob[:64], len(blob))
        if key not in seen:
            seen.add(key)
            dedup.append((kind, blob))
    return dedup[:MAX_CANDIDATES]


def _signals_in(data: bytes) -> list[str]:
    text = data.decode("utf-8", "replace").lower()
    return sorted({api for api in HIGH_RISK_APIS if api in text})


def analyze_script(data: bytes) -> dict:
    findings: list[dict] = []
    layers: list[dict] = []
    raw_signals = _signals_in(data)
    all_layers: list[tuple[int, str, bytes]] = [(0, "raw", data)]
    queue = [(0, data)]
    while queue:
        depth, blob = queue.pop(0)
        if depth >= MAX_DEPTH:
            continue
        for kind, inner in _extract_layers(blob):
            layers.append({"kind": kind, "depth": depth + 1,
                           "size": len(inner),
                           "preview": inner[:80].decode(
                               "utf-8", "replace")})
            all_layers.append((depth + 1, kind, inner))
            queue.append((depth + 1, inner))
            findings.append({"type": "script_encoded_layer",
                             "kind": kind, "depth": depth + 1})
    decoded_signals: set[str] = set()
    for depth, kind, blob in all_layers:
        if depth > 0:
            decoded_signals.update(_signals_in(blob))
    new_signals = sorted(decoded_signals - set(raw_signals))
    if new_signals:
        findings.append({"type": "script_signal_after_decode",
                         "signals": new_signals})
    text = data.decode("utf-8", "replace")
    unresolved = sorted({name for rx, name in UNRESOLVED_PATTERNS
                         if rx.search(text)})
    for name in unresolved:
        findings.append({"type": "unresolved_construct",
                         "construct": name})
    return {"layers": layers, "layer_data": all_layers,
            "raw_signals": raw_signals,
            "decoded_only_signals": new_signals,
            "unresolved_constructs": unresolved,
            "findings": findings}
