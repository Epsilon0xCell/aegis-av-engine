"""OOXML relationship analysis: the document attack surface.

An OOXML file (.docx, .xlsx, .pptx) is a zip of XML parts plus
relationship files. The parts that matter for detection are the
relationships, because they are where a document reaches OUTSIDE
itself:

- any relationship with TargetMode="External" is a live external
  reference (remote images, linked data, hyperlinks)
- an attachedTemplate relationship is remote template injection
  (MITRE ATT&CK T1221): Word fetches a template from the target
  when the document opens, and the template can carry macros the
  document itself never contained
- a vbaProject.bin part means the document carries a macro
  project, whatever the extension claims

Analysis is metadata-only: relationship targets and types are
reported as findings; nothing is fetched, ever.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET

ATTACHED_TEMPLATE = "attachedtemplate"


def analyze_ooxml(parts: dict[str, bytes]) -> list[dict]:
    if "[Content_Types].xml" not in parts:
        return []
    findings: list[dict] = [{"type": "ooxml_package",
                             "parts": len(parts)}]
    for name in parts:
        if name.rsplit("/", 1)[-1].lower() == "vbaproject.bin":
            findings.append({"type": "ooxml_macro_project", "member": name})
    for name, blob in parts.items():
        if not name.endswith(".rels"):
            continue
        owner = name.replace("_rels/", "").removesuffix(".rels")
        try:
            root = ET.fromstring(blob)
        except ET.ParseError:
            findings.append({"type": "ooxml_rels_parse_error", "member": name})
            continue
        for rel in root.iter():
            if not rel.tag.endswith("Relationship"):
                continue
            target = rel.get("Target", "")
            rtype = rel.get("Type", "")
            if rel.get("TargetMode") != "External":
                continue
            short = rtype.rsplit("/", 1)[-1]
            if ATTACHED_TEMPLATE in rtype.lower():
                findings.append({"type": "ooxml_remote_template",
                                 "part": owner, "target": target,
                                 "attck": "T1221"})
            else:
                findings.append({"type": "ooxml_external_relationship",
                                 "part": owner, "rel_type": short,
                                 "target": target})
    return findings
