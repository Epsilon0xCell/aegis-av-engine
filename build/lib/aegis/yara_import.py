"""YARA-subset importer: real YARA syntax, bounded, loud.

Mirrors the sigma-subset philosophy for the other detection
interchange format. Supported: multiple rules per file; meta
(collected, not interpreted); text strings with the ascii,
wide, nocase, and fullword modifiers; hex strings in this
engine's native pattern syntax; conditions built from string
references ($id true when present, #id occurrence counts),
any/all/none/N of them and of explicit or wildcard string
sets, filesize comparisons with KB and MB suffixes, uint16 and
uint32 reads at constant offsets, math.entropy over a constant
range (computed exactly as Shannon entropy of that range), and
pe.number_of_sections when the caller supplies the fact.

Rejected, whole rule, by name: regular-expression strings, the
xor and base64 modifiers, for loops, @ and ! offset and length
references, imports other than math and pe, pe.* surface other
than number_of_sections, external variables, and any condition
token outside the grammar. A rule that cannot be imported
whole is not imported in part.
"""
from __future__ import annotations

import re
import struct
from pathlib import Path

from .formats import shannon_entropy
from .rulelang import HexPattern


class YaraImportError(ValueError):
    pass


SUPPORTED_MODIFIERS = {"ascii", "wide", "nocase", "fullword"}
REJECTED_MODIFIERS = {"xor", "base64", "base64wide"}


def _strip_comments(text: str) -> str:
    out = []
    i = 0
    in_str = False
    while i < len(text):
        ch = text[i]
        if in_str:
            out.append(ch)
            if ch == "\\" and i + 1 < len(text):
                out.append(text[i + 1])
                i += 2
                continue
            if ch == '"':
                in_str = False
            i += 1
            continue
        if ch == '"':
            in_str = True
            out.append(ch)
            i += 1
        elif text.startswith("//", i):
            while i < len(text) and text[i] != "\n":
                i += 1
        elif text.startswith("/*", i):
            end = text.find("*/", i)
            i = len(text) if end < 0 else end + 2
        else:
            out.append(ch)
            i += 1
    return "".join(out)


def _unescape(raw: str) -> bytes:
    out = bytearray()
    i = 0
    while i < len(raw):
        ch = raw[i]
        if ch == "\\" and i + 1 < len(raw):
            nxt = raw[i + 1]
            if nxt == "x" and i + 3 < len(raw) + 1 and i + 4 <= len(raw):
                out.append(int(raw[i + 2:i + 4], 16))
                i += 4
                continue
            out += {"n": b"\n", "r": b"\r", "t": b"\t", "\\": b"\\",
                    '"': b'"'}.get(nxt, nxt.encode())
            i += 2
        else:
            out += ch.encode("utf-8", "replace")
            i += 1
    return bytes(out)


_WORD = set(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_")


def _count_occurrences(data: bytes, needle: bytes, nocase: bool,
                       fullword: bool) -> int:
    if not needle:
        return 0
    hay = data.lower() if nocase else data
    ndl = needle.lower() if nocase else needle
    count = 0
    pos = 0
    while True:
        at = hay.find(ndl, pos)
        if at < 0:
            return count
        if fullword:
            before = hay[at - 1] if at > 0 else 0x20
            after_at = at + len(ndl)
            after = hay[after_at] if after_at < len(hay) else 0x20
            if before in _WORD or after in _WORD:
                pos = at + 1
                continue
        count += 1
        pos = at + 1


class YaraString:
    def __init__(self, sid: str, kind: str, value, modifiers: set[str]):
        self.id = sid
        self.kind = kind  # "text" | "hex"
        self.value = value
        self.modifiers = modifiers
        self.hex = HexPattern(value) if kind == "hex" else None

    def count(self, data: bytes) -> int:
        if self.kind == "hex":
            return 1 if self.hex.search(data) else 0
        needles = []
        raw = self.value
        if "wide" in self.modifiers and "ascii" not in self.modifiers:
            needles = [raw.decode("latin-1").encode("utf-16-le")]
        else:
            needles = [raw]
            if "wide" in self.modifiers:
                needles.append(raw.decode("latin-1").encode("utf-16-le"))
        return sum(_count_occurrences(data, n,
                                      "nocase" in self.modifiers,
                                      "fullword" in self.modifiers)
                   for n in needles)


_TOKEN_RE = re.compile(r"""
    \s*(?:(?P<str>\$[A-Za-z0-9_]+)
    | (?P<cnt>\#[A-Za-z0-9_]+)
    | (?P<at>[@!][A-Za-z0-9_]+)
    | (?P<num>0x[0-9A-Fa-f]+|\d+(?:\.\d+)?\s*(?:KB|MB)?)
    | (?P<op>==|!=|<=|>=|<|>|=)
    | (?P<name>[A-Za-z_][A-Za-z0-9_.]*)
    | (?P<punct>[()\[\],*+\-]))
""", re.VERBOSE)


class _CondParser:
    def __init__(self, text: str, rule_name: str, string_ids: set[str]):
        if re.search(r"\bfor\b", text):
            raise YaraImportError(
                f"rule {rule_name}: for loops are outside yara-subset")
        self.rule = rule_name
        self.ids = string_ids
        self.tokens = []
        pos = 0
        while pos < len(text):
            if text[pos:].strip() == "":
                break
            m = _TOKEN_RE.match(text, pos)
            if not m or m.end() == pos:
                raise YaraImportError(
                    f"rule {rule_name}: condition token not in the "
                    f"yara-subset grammar near {text[pos:pos + 20]!r}")
            pos = m.end()
            kind = m.lastgroup
            self.tokens.append((kind, m.group().strip()))
        self.i = 0
        self.constructs: set[str] = set()

    def peek(self):
        return self.tokens[self.i] if self.i < len(self.tokens) else (None, None)

    def next(self):
        tok = self.peek()
        self.i += 1
        return tok

    def expect(self, value: str):
        kind, val = self.next()
        if val != value:
            raise YaraImportError(
                f"rule {self.rule}: expected {value!r}, found {val!r}")

    def parse(self):
        node = self.parse_or()
        if self.i != len(self.tokens):
            raise YaraImportError(
                f"rule {self.rule}: trailing condition tokens")
        return node

    def parse_or(self):
        node = self.parse_and()
        while self.peek()[1] == "or":
            self.next()
            node = ("or", node, self.parse_and())
        return node

    def parse_and(self):
        node = self.parse_not()
        while self.peek()[1] == "and":
            self.next()
            node = ("and", node, self.parse_not())
        return node

    def parse_not(self):
        if self.peek()[1] == "not":
            self.next()
            return ("not", self.parse_not())
        return self.parse_atom()

    def _number(self, raw: str) -> float:
        raw = raw.replace(" ", "")
        if raw.lower().startswith("0x"):
            return float(int(raw, 16))
        mult = 1
        if raw.endswith("KB"):
            mult, raw = 1024, raw[:-2]
        elif raw.endswith("MB"):
            mult, raw = 1024 * 1024, raw[:-2]
        return float(raw) * mult

    def parse_atom(self):
        kind, val = self.next()
        if val == "(":
            node = self.parse_or()
            self.expect(")")
            return node
        if kind == "at":
            raise YaraImportError(
                f"rule {self.rule}: offset/length references ({val}) are "
                f"outside yara-subset")
        if kind == "str":
            sid = val[1:]
            if sid not in self.ids:
                raise YaraImportError(
                    f"rule {self.rule}: unknown string {val}")
            # could be the start of an "of" expression? no: $id alone
            return ("str", sid)
        if kind == "cnt":
            sid = val[1:]
            if sid not in self.ids:
                raise YaraImportError(
                    f"rule {self.rule}: unknown count {val}")
            self.constructs.add("count comparisons")
            return self._maybe_compare(("count", sid))
        if kind == "name":
            if val == "for":
                raise YaraImportError(
                    f"rule {self.rule}: for loops are outside yara-subset")
            if val in ("any", "all", "none") or val.isdigit():
                return self._parse_of(val)
            if val == "filesize":
                self.constructs.add("filesize")
                return self._maybe_compare(("filesize",))
            if val in ("uint16", "uint32"):
                self.constructs.add(val)
                self.expect("(")
                k2, offset = self.next()
                if k2 != "num":
                    raise YaraImportError(
                        f"rule {self.rule}: {val} needs a constant offset")
                self.expect(")")
                return self._maybe_compare(
                    ("uint", 2 if val == "uint16" else 4,
                     int(self._number(offset))))
            if val == "math.entropy":
                self.constructs.add("math.entropy (exact Shannon over "
                                    "the range)")
                self.expect("(")
                _k, a = self.next()
                self.expect(",")
                k2, b = self.next()
                self.expect(")")
                size = -1 if (k2 == "name" and b == "filesize") \
                    else int(self._number(b))
                return self._maybe_compare(
                    ("entropy", int(self._number(a)), size))
            if val.startswith("pe."):
                if val != "pe.number_of_sections":
                    raise YaraImportError(
                        f"rule {self.rule}: {val} is outside the "
                        f"yara-subset pe surface (pe.number_of_sections "
                        f"only)")
                self.constructs.add("pe.number_of_sections")
                return self._maybe_compare(("pe_sections",))
            if val == "true":
                return ("const", True)
            if val == "false":
                return ("const", False)
            raise YaraImportError(
                f"rule {self.rule}: external variable or unknown "
                f"identifier {val!r} is outside yara-subset")
        if kind == "num":
            if self.peek()[1] == "of":
                return self._parse_of(str(int(self._number(val))))
            return self._maybe_compare(("const_num", self._number(val)))
        raise YaraImportError(
            f"rule {self.rule}: unexpected token {val!r}")

    def _parse_of(self, quant: str):
        kind, val = self.next()
        if val != "of":
            raise YaraImportError(
                f"rule {self.rule}: expected 'of' after {quant}")
        self.constructs.add("of expressions")
        kind, val = self.next()
        if val == "them":
            members = sorted(self.ids)
        elif val == "(":
            members = []
            while True:
                k2, v2 = self.next()
                if v2 == ")":
                    break
                if v2 == ",":
                    continue
                if k2 != "str":
                    raise YaraImportError(
                        f"rule {self.rule}: bad of-set member {v2!r}")
                sid = v2[1:]
                if self.peek()[1] == "*":
                    self.next()
                    members.extend(sorted(
                        s for s in self.ids if s.startswith(sid)))
                else:
                    if sid not in self.ids:
                        raise YaraImportError(
                            f"rule {self.rule}: unknown string {v2}")
                    members.append(sid)
        else:
            raise YaraImportError(
                f"rule {self.rule}: unsupported of target {val!r}")
        return ("of", quant, members)

    def _maybe_compare(self, lhs):
        kind, val = self.peek()
        if kind == "op":
            self.next()
            k2, raw = self.next()
            if k2 == "num":
                rhs = ("const_num", self._number(raw))
            elif k2 == "name" and raw == "filesize":
                rhs = ("filesize",)
            else:
                raise YaraImportError(
                    f"rule {self.rule}: unsupported comparison operand "
                    f"{raw!r}")
            return ("cmp", val, lhs, rhs)
        return lhs


class YaraRule:
    def __init__(self, name, strings, condition, constructs, meta):
        self.name = name
        self.strings = strings
        self.condition = condition
        self.constructs = constructs
        self.meta = meta

    def evaluate(self, data: bytes, facts: dict | None = None) -> dict:
        facts = facts or {}
        counts = {s.id: s.count(data) for s in self.strings}
        ctx = {"counts": counts, "data": data,
               "filesize": facts.get("filesize", len(data)),
               "pe_sections": facts.get("pe_sections"),
               "undefined": []}
        matched = _eval(self.condition, ctx)
        return {"rule": self.name, "matched": bool(matched),
                "counts": counts, "undefined": ctx["undefined"]}


def _operand(node, ctx):
    kind = node[0]
    if kind == "count":
        return ctx["counts"].get(node[1], 0)
    if kind == "filesize":
        return ctx["filesize"]
    if kind == "const_num":
        return node[1]
    if kind == "uint":
        _k, size, off = node
        chunk = ctx["data"][off:off + size]
        if len(chunk) < size:
            return None
        return int.from_bytes(chunk, "little")
    if kind == "entropy":
        _k, a, b = node
        size = ctx["filesize"] if b < 0 else b
        return shannon_entropy(ctx["data"][a:a + size])
    if kind == "pe_sections":
        if ctx["pe_sections"] is None:
            ctx["undefined"].append("pe.number_of_sections")
        return ctx["pe_sections"]
    return None


def _eval(node, ctx) -> bool:
    kind = node[0]
    if kind == "and":
        return _eval(node[1], ctx) and _eval(node[2], ctx)
    if kind == "or":
        return _eval(node[1], ctx) or _eval(node[2], ctx)
    if kind == "not":
        return not _eval(node[1], ctx)
    if kind == "const":
        return node[1]
    if kind == "str":
        return ctx["counts"].get(node[1], 0) > 0
    if kind == "of":
        _k, quant, members = node
        hits = sum(1 for m in members if ctx["counts"].get(m, 0) > 0)
        if quant == "any":
            return hits >= 1
        if quant == "all":
            return hits == len(members) and len(members) > 0
        if quant == "none":
            return hits == 0
        return hits >= int(quant)
    if kind == "cmp":
        _k, op, lhs, rhs = node
        left = _operand(lhs, ctx)
        right = _operand(rhs, ctx)
        if left is None or right is None:
            return False
        return {"==": left == right, "!=": left != right,
                "<": left < right, ">": left > right,
                "<=": left <= right, ">=": left >= right,
                "=": left == right}[op]
    value = _operand(node, ctx)
    return bool(value)


def _parse_strings_section(section: str, rule_name: str):
    strings = []
    i = 0
    entry_re = re.compile(r"\$([A-Za-z0-9_]+)\s*=\s*")
    while True:
        m = entry_re.search(section, i)
        if not m:
            break
        sid = m.group(1)
        j = m.end()
        while j < len(section) and section[j] in " \t":
            j += 1
        if j >= len(section):
            break
        if section[j] == '"':
            k = j + 1
            raw = []
            while k < len(section):
                if section[k] == "\\" and k + 1 < len(section):
                    raw.append(section[k:k + 2])
                    k += 2
                    continue
                if section[k] == '"':
                    break
                raw.append(section[k])
                k += 1
            value = _unescape("".join(raw))
            j = k + 1
            kind = "text"
        elif section[j] == "{":
            depth = 0
            k = j
            while k < len(section):
                if section[k] == "{":
                    depth += 1
                elif section[k] == "}":
                    depth -= 1
                    if depth == 0:
                        break
                k += 1
            value = section[j + 1:k].strip()
            j = k + 1
            kind = "hex"
        elif section[j] == "/":
            raise YaraImportError(
                f"rule {rule_name}: regular-expression strings are "
                f"outside yara-subset")
        else:
            raise YaraImportError(
                f"rule {rule_name}: cannot parse string ${sid}")
        modifiers = set()
        tail = section[j:section.find("\n", j) if "\n" in section[j:]
                       else len(section)]
        for word in re.findall(r"[A-Za-z]+", tail):
            if word in REJECTED_MODIFIERS:
                raise YaraImportError(
                    f"rule {rule_name}: modifier {word} is outside "
                    f"yara-subset")
            if word in SUPPORTED_MODIFIERS:
                modifiers.add(word)
        strings.append(YaraString(sid, kind, value, modifiers))
        i = j
    return strings


def import_yara(text: str) -> dict:
    cleaned = _strip_comments(text)
    for m in re.finditer(r'import\s+"([^"]+)"', cleaned):
        if m.group(1) not in ("math", "pe"):
            raise YaraImportError(
                f'import "{m.group(1)}" is outside yara-subset')
    rules = []
    report = []
    for m in re.finditer(r"rule\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?::[^{]*)?\{",
                         cleaned):
        name = m.group(1)
        start = m.end()
        depth = 1
        k = start
        in_str = False
        while k < len(cleaned) and depth:
            ch = cleaned[k]
            if in_str:
                if ch == "\\":
                    k += 1
                elif ch == '"':
                    in_str = False
            elif ch == '"':
                in_str = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
            k += 1
        body = cleaned[start:k - 1]
        sections = {}
        marks = [(mm.start(), mm.end(), mm.group(1)) for mm in
                 re.finditer(r"(?<![A-Za-z_])(meta|strings|condition)\s*:",
                             body)]
        for n, (at, after, sec) in enumerate(marks):
            end = marks[n + 1][0] if n + 1 < len(marks) else len(body)
            sections[sec] = body[after:end]
        strings = _parse_strings_section(sections.get("strings", ""), name)
        if "condition" not in sections:
            raise YaraImportError(f"rule {name}: no condition section")
        parser = _CondParser(sections["condition"], name,
                             {s.id for s in strings})
        condition = parser.parse()
        meta = {}
        for line in sections.get("meta", "").splitlines():
            if "=" in line:
                key, val = line.split("=", 1)
                meta[key.strip()] = val.strip().strip('"')
        rules.append(YaraRule(name, strings, condition,
                              sorted(parser.constructs), meta))
        mods = sorted({mod for s in strings for mod in s.modifiers})
        report.append({"rule": name, "strings": len(strings),
                       "modifiers": mods,
                       "constructs": sorted(parser.constructs),
                       "notes": ["math.entropy computed exactly as "
                                 "Shannon entropy of the range"]})
    if not rules:
        raise YaraImportError("no rules found")
    return {"rules": rules, "report": report}


def import_yara_file(path: Path) -> dict:
    return import_yara(Path(path).read_text())
