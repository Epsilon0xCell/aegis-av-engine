"""Rule language v2 primitives: hex patterns and condition ASTs.

Hex pattern subset (YARA-inspired, deliberately smaller):
- byte tokens:        4D 5A
- full wildcard:      ??
- nibble wildcard:    4?  ?A
- fixed jump:         [4]
- ranged jump:        [2-6]
No alternation groups and no regex in v2.0; jumps are capped at
256 bytes, per the research, to keep matching cost predictable.
Matching anchors on the longest literal byte run, then verifies
the full token sequence left and right of the anchor.

Conditions are JSON ASTs evaluated over a context of matched
string ids plus file facts, so rules stay declarative data:
  {"all_of": ["$a", "$b"]}        {"any_of": ["$a", "$b"]}
  {"count_at_least": {"of": ["$a", "$b", "$c"], "n": 2}}
  {"and": [cond, cond]}           {"or": [cond, cond]}
  {"not": cond}
  {"format_is": "pe"}             {"entropy_above": 7.2}
  {"size_above": 1024}
"""
from __future__ import annotations

MAX_JUMP = 256


class PatternError(ValueError):
    pass


def _parse_token(tok: str):
    if tok.startswith("[") and tok.endswith("]"):
        body = tok[1:-1]
        if "-" in body:
            lo, hi = body.split("-", 1)
            lo_i, hi_i = int(lo), int(hi)
        else:
            lo_i = hi_i = int(body)
        if not (0 <= lo_i <= hi_i <= MAX_JUMP):
            raise PatternError(f"jump out of range: {tok}")
        return ("jump", lo_i, hi_i)
    if len(tok) != 2:
        raise PatternError(f"bad token: {tok!r}")
    if tok == "??":
        return ("any",)
    if tok[0] == "?":
        return ("nibble_lo", int(tok[1], 16))
    if tok[1] == "?":
        return ("nibble_hi", int(tok[0], 16))
    return ("byte", int(tok, 16))


class HexPattern:
    """Token-sequence matcher with backtracking over ranged jumps.

    Candidate start positions come from the longest literal byte
    run (the anchor) via bytes.find; the full sequence is then
    verified by a small recursive matcher, so ranged jumps before
    and after the anchor are handled exactly.
    """

    def __init__(self, text: str) -> None:
        self.text = text
        self.tokens = [_parse_token(t) for t in text.split()]
        if not self.tokens:
            raise PatternError("empty hex pattern")
        self.anchor, self.anchor_tok = self._find_anchor()
        prefix = self.tokens[: self.anchor_tok]
        self._prefix_min = sum(1 if t[0] != "jump" else t[1] for t in prefix)
        self._prefix_max = sum(1 if t[0] != "jump" else t[2] for t in prefix)

    def _find_anchor(self) -> tuple[bytes, int]:
        best, best_tok, run, run_tok = b"", 0, bytearray(), 0
        for i, tok in enumerate(self.tokens):
            if tok[0] == "byte":
                if not run:
                    run_tok = i
                run.append(tok[1])
                if len(run) > len(best):
                    best, best_tok = bytes(run), run_tok
            else:
                run = bytearray()
        return best, best_tok

    def _match_from(self, ti: int, pos: int, data: bytes) -> bool:
        if ti == len(self.tokens):
            return True
        tok = self.tokens[ti]
        if tok[0] == "jump":
            return any(self._match_from(ti + 1, pos + k, data)
                       for k in range(tok[1], tok[2] + 1)
                       if pos + k <= len(data))
        if pos >= len(data) or not _token_matches(tok, data[pos]):
            return False
        return self._match_from(ti + 1, pos + 1, data)

    def search(self, data: bytes) -> bool:
        if not self.anchor:
            return any(self._match_from(0, s, data)
                       for s in range(len(data) + 1))
        start = 0
        while True:
            idx = data.find(self.anchor, start)
            if idx < 0:
                return False
            for back in range(self._prefix_min, self._prefix_max + 1):
                s = idx - back
                if s >= 0 and self._match_from(0, s, data):
                    return True
            start = idx + 1


def _token_matches(tok, byte: int) -> bool:
    kind = tok[0]
    if kind == "byte":
        return byte == tok[1]
    if kind == "any":
        return True
    if kind == "nibble_hi":
        return (byte >> 4) == tok[1]
    if kind == "nibble_lo":
        return (byte & 0xF) == tok[1]
    return False


def evaluate_condition(cond: dict, matched: set[str], facts: dict) -> bool:
    if "all_of" in cond:
        return all(s in matched for s in cond["all_of"])
    if "any_of" in cond:
        return any(s in matched for s in cond["any_of"])
    if "count_at_least" in cond:
        spec = cond["count_at_least"]
        return sum(1 for s in spec["of"] if s in matched) >= spec["n"]
    if "and" in cond:
        return all(evaluate_condition(c, matched, facts) for c in cond["and"])
    if "or" in cond:
        return any(evaluate_condition(c, matched, facts) for c in cond["or"])
    if "not" in cond:
        return not evaluate_condition(cond["not"], matched, facts)
    if "format_is" in cond:
        return facts.get("format") == cond["format_is"]
    if "entropy_above" in cond:
        return float(facts.get("entropy", 0)) > float(cond["entropy_above"])
    if "size_above" in cond:
        return int(facts.get("size", 0)) > int(cond["size_above"])
    raise PatternError(f"unknown condition node: {cond}")
