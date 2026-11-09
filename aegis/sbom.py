"""CycloneDX SBOM from the built release zip's real inventory.

The SBOM is generated from the artifact it describes: the zip
is opened, every member is hashed, and the inventory becomes
CycloneDX (ECMA-424) file components with SHA-256 hashes. It
is an inventory and integrity manifest, not a vulnerability
report, and the description says so. Output is deterministic:
components sorted by path, no timestamps from the wall clock
(the timestamp is the zip's own newest entry date).
"""
from __future__ import annotations

import hashlib
import json
import zipfile
from pathlib import Path


def generate_sbom(zip_path: Path, name: str, version: str) -> dict:
    components = []
    newest = None
    with zipfile.ZipFile(zip_path) as zf:
        for info in sorted(zf.infolist(), key=lambda i: i.filename):
            if info.is_dir():
                continue
            data = zf.read(info)
            components.append({
                "type": "file", "name": info.filename,
                "hashes": [{"alg": "SHA-256",
                            "content": hashlib.sha256(data).hexdigest()}],
                "properties": [{"name": "aegis:size",
                                "value": str(len(data))}]})
            stamp = "%04d-%02d-%02dT%02d:%02d:%02dZ" % info.date_time
            newest = stamp if newest is None or stamp > newest else newest
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "timestamp": newest or "1980-01-01T00:00:00Z",
            "component": {"type": "application", "name": name,
                          "version": version,
                          "description": "Deterministic source release. "
                                         "This SBOM is an inventory "
                                         "and integrity manifest."},
            "tools": [{"vendor": "Aegis", "name": "aegis-sbom",
                       "version": version}]},
        "components": components}


def sbom_json(zip_path: Path, name: str, version: str) -> str:
    return json.dumps(generate_sbom(zip_path, name, version),
                      indent=1, sort_keys=True)
