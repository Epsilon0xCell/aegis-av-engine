"""Container scanning: ZIP (and OOXML), TAR, GZIP. Memory only.

Nothing is ever extracted to disk. Members are streamed in bounded
chunks, their decompressed bytes counted against the shared
ScanBudget as they are produced, and each member is scanned by the
engine callback. Nested containers recurse against the SAME
budget. PDF is metadata-only in this engine: identified, hashed,
never parsed, because a full PDF parser is an attack surface this
project declines to own (see research report).
"""
from __future__ import annotations

import gzip
import io
import tarfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from .budget import BudgetExceeded, ScanBudget

CHUNK = 64 * 1024


@dataclass
class MemberResult:
    name: str
    verdict: dict | None = None
    note: str = ""


@dataclass
class ContainerResult:
    kind: str
    members: list[MemberResult] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)


def _read_bounded(stream, budget: ScanBudget, compressed_size: int) -> bytes:
    out = bytearray()
    while True:
        chunk = stream.read(CHUNK)
        if not chunk:
            break
        budget.consume(len(chunk), compressed_size=compressed_size)
        out.extend(chunk)
        if len(out) > budget.per_entry:
            raise BudgetExceeded("per_entry", "entry too large while streaming")
    return bytes(out)


def scan_container(data: bytes, scan_bytes, budget: ScanBudget | None = None,
                   depth: int = 0, name: str = "<container>") -> ContainerResult:
    """scan_bytes: callable(bytes, name) -> verdict dict (the engine)."""
    budget = budget or ScanBudget()
    budget.enter_level(depth)
    kind = "unknown"
    result = ContainerResult(kind=kind)
    try:
        if zipfile.is_zipfile(io.BytesIO(data)):
            kind = "zip"
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                for info in zf.infolist():
                    if info.is_dir():
                        continue
                    budget.count_file()
                    if info.filename.startswith(("/", "..")) or ".." in Path(info.filename).parts:
                        result.findings.append({"type": "traversal_name",
                                                "member": info.filename})
                        continue
                    with zf.open(info) as fh:
                        blob = _read_bounded(fh, budget, len(data))
                    result.members.append(_scan_member(
                        blob, info.filename, scan_bytes, budget, depth, result))
        elif data[:2] == b"\x1f\x8b":
            kind = "gzip"
            budget.count_file()
            with gzip.GzipFile(fileobj=io.BytesIO(data)) as gz:
                blob = _read_bounded(gz, budget, len(data))
            result.members.append(_scan_member(
                blob, name + ":gzip-member", scan_bytes, budget, depth, result))
        elif data[257:262] == b"ustar":
            kind = "tar"
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tf:
                for member in tf.getmembers():
                    if not member.isfile():
                        continue
                    budget.count_file()
                    if member.name.startswith(("/", "..")) or ".." in Path(member.name).parts:
                        result.findings.append({"type": "traversal_name",
                                                "member": member.name})
                        continue
                    fh = tf.extractfile(member)
                    if fh is None:
                        continue
                    blob = _read_bounded(fh, budget, len(data))
                    result.members.append(_scan_member(
                        blob, member.name, scan_bytes, budget, depth, result))
        else:
            result.kind = "not_a_container"
            return result
    except BudgetExceeded as exc:
        result.findings.append({"type": "budget_exceeded", "kind": exc.kind,
                                "detail": exc.detail})
    except (zipfile.BadZipFile, tarfile.TarError, OSError) as exc:
        result.findings.append({"type": "container_parse_error",
                                "detail": f"{type(exc).__name__}"})
    result.kind = kind
    return result


def _scan_member(blob: bytes, member_name: str, scan_bytes,
                 budget: ScanBudget, depth: int,
                 result: ContainerResult) -> MemberResult:
    if zipfile.is_zipfile(io.BytesIO(blob)) or blob[:2] == b"\x1f\x8b":
        nested = scan_container(blob, scan_bytes, budget, depth + 1, member_name)
        result.findings.extend(
            {"nested_in": member_name, **f} for f in nested.findings)
        worst = _worst_verdict([m.verdict for m in nested.members
                                if m.verdict is not None])
        return MemberResult(name=member_name, verdict=worst,
                            note=f"nested {nested.kind} container, "
                                 f"{len(nested.members)} members")
    return MemberResult(name=member_name, verdict=scan_bytes(blob, member_name))


_RANK = {"clean": 0, "suspicious": 1, "malicious_pattern": 2}


def _worst_verdict(verdicts: list[dict]) -> dict | None:
    if not verdicts:
        return None
    return max(verdicts, key=lambda v: _RANK.get(v["verdict"], 0))
