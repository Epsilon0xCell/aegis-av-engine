"""Content views: raw vs loaded vs residual.

The game-changer from the v2 research is content-aware
normalisation. An append/padding attack adds bytes the loader
never executes. So the engine distinguishes:

- raw:      the whole file, what a naive scanner sees
- loaded:   what the format actually maps or executes; for PE,
            the file minus overlay and minus the Authenticode
            certificate table (both lie outside the loaded image)
- residual: the bytes outside the loaded view (overlay + certs)

Rules and entropy are then interpreted per view: a pattern hit
in the loaded view cannot be diluted by residual padding, a hit
that exists ONLY in the residual is real but down-weighted in
interpretation, and a hot loaded region hidden under cool
residual bulk is a dilution finding in its own right.
"""
from __future__ import annotations


def split_views(data: bytes, fmt: str, analysis: dict | None) -> dict:
    if fmt != "pe" or not analysis:
        return {"raw": data, "loaded": data, "residual": b"",
                "loaded_fraction": 1.0}
    overlay = int(analysis.get("overlay_bytes") or 0)
    loaded_end = len(data) - overlay if overlay else len(data)
    residual_parts = []
    if overlay:
        residual_parts.append(data[loaded_end:])
    loaded = bytearray(data[:loaded_end])
    security = (analysis.get("directories") or {}).get("security")
    if security and security.get("size"):
        off, size = security["rva"], security["size"]  # file offset, not RVA
        if 0 <= off < len(loaded) and size > 0:
            residual_parts.append(bytes(loaded[off:off + size]))
            del loaded[off:off + size]
    loaded_b = bytes(loaded)
    residual = b"".join(residual_parts)
    return {"raw": data, "loaded": loaded_b, "residual": residual,
            "loaded_fraction": round(len(loaded_b) / max(len(data), 1), 4)}
