"""Seeded property and fuzz tests: parsers and the engine must
never raise, whatever bytes arrive, and the string engine must
agree with naive search on random cases."""
import random
from pathlib import Path

from aegis import containers
from aegis.engine import Engine
from aegis.formats_elf import parse_elf
from aegis.formats_macho import parse_macho
from aegis.formats_pe import parse_pe
from aegis.rules import RulePack
from aegis.strings_engine import AhoCorasick
from tests.test_containers_formats import _minimal_elf, _minimal_pe

ROOT = Path(__file__).resolve().parent.parent
RNG = random.Random(20261109)


def _rand_bytes(n: int) -> bytes:
    return bytes(RNG.randrange(256) for _ in range(n))


def test_parsers_never_raise_on_random_and_truncated():
    seeds = [_minimal_pe(), _minimal_elf(),
             b"\xcf\xfa\xed\xfe" + _rand_bytes(60)]
    for seed in seeds:
        for cut in range(0, len(seed) + 1, 7):
            parse_pe(seed[:cut])
            parse_elf(seed[:cut])
            parse_macho(seed[:cut])
    for _ in range(200):
        blob = _rand_bytes(RNG.randrange(0, 512))
        parse_pe(blob)
        parse_elf(blob)
        parse_macho(blob)


def test_engine_and_containers_never_raise():
    engine = Engine(RulePack(ROOT / "rules" / "core_rules_v2.json"))
    prefixes = [b"MZ", b"\x7fELF", b"PK\x03\x04", b"\x1f\x8b", b"%PDF"]
    for _ in range(120):
        blob = RNG.choice(prefixes) + _rand_bytes(RNG.randrange(0, 600))
        v = engine.scan_bytes(blob, "fuzz.bin")
        assert v["verdict"] in ("clean", "suspicious", "malicious_pattern")
        containers.scan_container(blob, engine.scan_bytes)


def test_aho_corasick_matches_naive_search():
    for trial in range(60):
        patterns = set()
        while len(patterns) < 5:
            patterns.add(bytes(RNG.randrange(97, 100)
                               for _ in range(RNG.randrange(1, 5))))
        ac = AhoCorasick()
        for i, p in enumerate(sorted(patterns)):
            ac.add(p, f"p{i}")
        ac.build()
        text = bytes(RNG.randrange(97, 100) for _ in range(200))
        hits = ac.search(text)
        for i, p in enumerate(sorted(patterns)):
            # overlapping occurrences: AC reports a match ending at
            # every position; str.count would miss overlaps
            expected = sum(1 for k in range(len(text)) if text.startswith(p, k))
            assert hits.get(f"p{i}", 0) == expected, (trial, p, expected, hits)
