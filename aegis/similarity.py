"""Structural fingerprints: section hashes and imphash.

Section SHA-256 hashes survive the classic mutations: appending
an overlay, editing resources, or re-signing changes the file
hash completely and changes no section hash. GAMMA-style
injection ADDS a section; it does not rewrite .text.

Imphash follows the Mandiant/pefile algorithm exactly in shape:
for each imported DLL in table order, the DLL name lowercased
with its extension stripped, a dot, and each imported function
lowercased, all comma-joined, MD5 of the string. Ordinal imports
resolve to names ONLY for ws2_32/wsock32 (and oleaut32 in the
reference tables); everything else stays ord<N>, because
resolving more broadly would produce hashes that disagree with
every other implementation. Our ws2_32 table is a documented
subset, so imphash parity is claimed only for name-imported
binaries and the table-covered ordinals, and the docs say so.
"""
from __future__ import annotations

import hashlib


def section_hashes(data: bytes, analysis: dict) -> dict[str, str]:
    out: dict[str, str] = {}
    for s in analysis.get("sections", []):
        ptr, size = s.get("raw_ptr"), s.get("raw_size")
        if ptr is None or not size:
            continue
        blob = data[ptr:ptr + size]
        if len(blob) == size:
            out[s["name"]] = hashlib.sha256(blob).hexdigest()
    return out


def imphash(analysis: dict) -> str | None:
    functions = analysis.get("import_functions")
    if not functions:
        return None
    parts = []
    for dll, names in functions.items():
        base = dll.lower()
        for ext in (".dll", ".ocx", ".sys", ".drv"):
            if base.endswith(ext):
                base = base[: -len(ext)]
                break
        for fn in names:
            parts.append(f"{base}.{fn.lower()}")
    if not parts:
        return None
    return hashlib.md5(",".join(parts).encode()).hexdigest()
