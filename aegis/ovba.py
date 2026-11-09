"""MS-OVBA analysis over a parsed CFB: the VBA project inventory.

Three layers, each bounded:
1. The compressed-container decompressor (MS-OVBA 2.3.1), used
   for the dir stream and module source. Copy tokens resolve
   against the current 4096-byte decompressed chunk; every loop
   is capped, and malformed containers stop with what was
   decoded rather than raising.
2. The dir stream's PROJECTINFORMATION records: system kind,
   code page, project name, and the module table (name, stream
   name, source offset, type).
3. Project-level signals: the PROJECT stream's protection
   attributes (a locked project), the _VBA_PROJECT stream's
   shape (the 7-byte stream left behind by VBA purging tools is
   a divergence finding: a project whose compiled state was
   stripped while its dir stream still advertises modules).

Decompressed module source is returned for the caller's
matchers; nothing here executes or interprets VBA.
"""
from __future__ import annotations

import struct

MAX_DECOMPRESSED = 8 * 1024 * 1024


def decompress_container(data: bytes) -> bytes:
    """MS-OVBA compressed container -> bytes. Tolerant: returns
    what decoded cleanly before any malformed chunk."""
    if not data or data[0] != 0x01:
        return b""
    out = bytearray()
    pos = 1
    while pos + 2 <= len(data) and len(out) < MAX_DECOMPRESSED:
        header = struct.unpack_from("<H", data, pos)[0]
        pos += 2
        chunk_size = (header & 0x0FFF) + 3
        compressed = bool(header & 0x8000)
        chunk_end = min(pos - 2 + chunk_size, len(data))
        if not compressed:
            take = min(4096, chunk_end - pos)
            out += data[pos:pos + take]
            pos = chunk_end
            continue
        chunk_start_len = len(out)
        while pos < chunk_end and len(out) - chunk_start_len < 4096:
            flags = data[pos]
            pos += 1
            for bit in range(8):
                if pos >= chunk_end or len(out) - chunk_start_len >= 4096:
                    break
                if not (flags >> bit) & 1:
                    out.append(data[pos])
                    pos += 1
                else:
                    if pos + 2 > chunk_end:
                        pos = chunk_end
                        break
                    token = struct.unpack_from("<H", data, pos)[0]
                    pos += 2
                    position = len(out) - chunk_start_len
                    offset_bits = max(4, position.bit_length())
                    if (1 << offset_bits) < position:
                        offset_bits += 1
                    length_mask = 0xFFFF >> offset_bits
                    length = (token & length_mask) + 3
                    offset = (token >> (16 - offset_bits)) + 1
                    src = len(out) - offset
                    if src < chunk_start_len or src < 0:
                        pos = chunk_end
                        break
                    for _ in range(length):
                        if len(out) - chunk_start_len >= 4096:
                            break
                        out.append(out[src])
                        src += 1
        pos = chunk_end
    return bytes(out)


def _records(data: bytes):
    pos = 0
    while pos + 6 <= len(data):
        rid, size = struct.unpack_from("<HI", data, pos)
        pos += 6
        if pos + size > len(data):
            break
        yield rid, data[pos:pos + size]
        pos += size


def parse_dir_stream(decompressed: bytes, codepage: int = 1252) -> dict:
    info: dict = {"modules": []}
    current: dict | None = None

    def text(blob: bytes) -> str:
        return blob.decode(f"cp{codepage}", "replace")

    for rid, blob in _records(decompressed):
        if rid == 0x0001 and len(blob) == 4:
            info["sys_kind"] = struct.unpack("<I", blob)[0]
        elif rid == 0x0003 and len(blob) == 2:
            codepage = struct.unpack("<H", blob)[0]
            info["code_page"] = codepage
        elif rid == 0x0004:
            info["project_name"] = text(blob)
        elif rid == 0x000F and len(blob) == 2:
            info["module_count"] = struct.unpack("<H", blob)[0]
        elif rid == 0x0019:
            current = {"name": text(blob)}
            info["modules"].append(current)
        elif current is not None and rid == 0x001A:
            size = len(blob) // 2
            current["stream_name"] = text(blob)
            _ = size
        elif current is not None and rid == 0x0031 and len(blob) == 4:
            current["text_offset"] = struct.unpack("<I", blob)[0]
        elif current is not None and rid == 0x0021 and len(blob) == 4:
            current["module_type"] = struct.unpack("<I", blob)[0]
    return info


def analyze_vba(cfb: dict) -> dict:
    """cfb: the dict from formats_cfb.parse_cfb (with streams)."""
    streams = cfb.get("streams", {})
    findings: list[dict] = []
    out: dict = {"present": False, "findings": findings,
                 "modules": [], "module_sources": {}}
    vba_keys = [k for k in streams
                if k.rsplit("/", 1)[-1].lower() in ("dir", "_vba_project")
                or "/vba/" in k.lower()]
    dir_key = next((k for k in streams
                    if k.rsplit("/", 1)[-1].lower() == "dir"
                    and "vba" in k.lower()), None)
    project_blob_key = next((k for k in streams
                             if k.rsplit("/", 1)[-1].lower()
                             == "_vba_project"), None)
    if dir_key is None and project_blob_key is None and not vba_keys:
        return out
    out["present"] = True
    findings.append({"type": "vba_project_present"})
    if project_blob_key is not None:
        blob = streams[project_blob_key]
        out["vba_project_stream_size"] = len(blob)
        if len(blob) <= 7:
            findings.append({"type": "vba_purged_shape",
                             "detail": "_VBA_PROJECT stream is 7 bytes or "
                                       "smaller: compiled project state "
                                       "stripped (purging-tool shape)"})
    project_stream = next((streams[k] for k in streams
                           if k.rsplit("/", 1)[-1] == "PROJECT"), None)
    if project_stream is not None:
        text = project_stream.decode("cp1252", "replace")
        if "CMG=" in text or "DPB=" in text:
            findings.append({"type": "vba_project_protected",
                             "detail": "PROJECT stream carries CMG/DPB "
                                       "protection attributes"})
    if dir_key is not None:
        decompressed = decompress_container(streams[dir_key])
        info = parse_dir_stream(decompressed)
        out["project_info"] = {k: v for k, v in info.items()
                               if k != "modules"}
        base = dir_key.rsplit("/", 1)[0]
        for module in info["modules"]:
            stream_name = module.get("stream_name") or module.get("name")
            key = next((k for k in streams
                        if k.rsplit("/", 1)[-1] == stream_name), None)
            entry = dict(module)
            if key is None:
                entry["source_status"] = "stream_missing"
                findings.append({"type": "vba_module_stream_missing",
                                 "module": module.get("name")})
            else:
                blob = streams[key]
                offset = module.get("text_offset", 0)
                if offset >= len(blob):
                    entry["source_status"] = "no_source"
                    findings.append({"type": "vba_module_source_absent",
                                     "module": module.get("name")})
                else:
                    source = decompress_container(blob[offset:])
                    entry["source_status"] = "present"
                    entry["source_bytes"] = len(source)
                    out["module_sources"][module.get("name", key)] = source
            out["modules"].append(entry)
            findings.append({"type": "vba_module", **{
                k: entry[k] for k in ("name", "stream_name", "text_offset",
                                      "module_type", "source_status")
                if k in entry}})
        _ = base
    return out
