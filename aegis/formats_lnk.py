"""Windows Shell Link (.lnk) parsing, per MS-SHLLINK.

A shortcut is a delivery vehicle: the file itself is inert,
but its target and arguments are a command line someone is
meant to double-click. This parser extracts exactly that: the
link target path from LinkInfo, and the StringData fields in
spec order (name, relative path, working directory, arguments,
icon location). The arguments string is the payload position;
the engine hands it to the script layer analyser unchanged.
"""
from __future__ import annotations

import struct

CLSID = bytes.fromhex("0114020000000000C000000000000046")
FLAG_IDLIST = 0x01
FLAG_LINKINFO = 0x02
FLAG_NAME = 0x04
FLAG_RELPATH = 0x08
FLAG_WORKINGDIR = 0x10
FLAG_ARGUMENTS = 0x20
FLAG_ICON = 0x40
FLAG_UNICODE = 0x80


def _u16(d, o):
    return struct.unpack_from("<H", d, o)[0]


def _u32(d, o):
    return struct.unpack_from("<I", d, o)[0]


def parse_lnk(data: bytes) -> dict:
    findings: list[dict] = []
    out: dict = {"format": "lnk", "findings": findings}
    if len(data) < 76 or _u32(data, 0) != 0x4C \
            or data[4:20] != CLSID:
        findings.append({"type": "not_lnk"})
        return out
    flags = _u32(data, 20)
    out["flags"] = flags
    out["show_command"] = _u32(data, 56)
    pos = 76
    if flags & FLAG_IDLIST:
        if pos + 2 > len(data):
            findings.append({"type": "lnk_truncated_idlist"})
            return out
        pos += 2 + _u16(data, pos)
    if flags & FLAG_LINKINFO:
        if pos + 28 <= len(data):
            info_size = _u32(data, pos)
            header_size = _u32(data, pos + 4)
            local_base_off = _u32(data, pos + 16)
            if header_size >= 28 and local_base_off:
                at = pos + local_base_off
                end = data.find(b"\x00", at)
                if at < len(data) and end > at:
                    out["target_path"] = data[at:end].decode(
                        "utf-8", "replace")
            pos += info_size if info_size else 0
    unicode_ = bool(flags & FLAG_UNICODE)

    def read_string(p: int):
        if p + 2 > len(data):
            return None, p
        count = _u16(data, p)
        p += 2
        if unicode_:
            raw = data[p:p + count * 2]
            return raw.decode("utf-16-le", "replace"), p + count * 2
        raw = data[p:p + count]
        return raw.decode("utf-8", "replace"), p + count

    for flag, key in [(FLAG_NAME, "name"), (FLAG_RELPATH, "relative_path"),
                      (FLAG_WORKINGDIR, "working_dir"),
                      (FLAG_ARGUMENTS, "arguments"),
                      (FLAG_ICON, "icon_location")]:
        if flags & flag:
            value, pos = read_string(pos)
            if value is not None:
                out[key] = value
    if out.get("target_path"):
        findings.append({"type": "lnk_target_path",
                         "path": out["target_path"]})
    if out.get("arguments"):
        findings.append({"type": "lnk_arguments",
                         "arguments": out["arguments"][:200]})
    lowered = (out.get("target_path", "") + " "
               + out.get("arguments", "")).lower()
    hosts = [h for h in ("powershell", "mshta", "wscript", "cscript",
                         "rundll32", "cmd.exe", "cmd /c")
             if h in lowered]
    if hosts:
        findings.append({"type": "lnk_script_host", "hosts": hosts})
    return out
