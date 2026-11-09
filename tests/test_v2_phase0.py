import random
from pathlib import Path

from aegis.corpora import EICAR
from aegis.engine import Engine
from aegis.rules import RulePack
from aegis.segmented import segmented_stats
from aegis.strings_engine import AhoCorasick
from aegis.views import split_views
from tests.test_containers_formats import _minimal_pe

ROOT = Path(__file__).resolve().parent.parent


def _engine():
    return Engine(RulePack(ROOT / "rules" / "core_rules_v2.json"))


def test_segmented_max_survives_padding():
    rng = random.Random(5)
    hot = bytes(rng.randrange(256) for _ in range(8192))
    padded = hot + b"the quick brown fox jumps over the lazy dog. " * 1500
    stats = segmented_stats(padded)
    assert stats["max"] >= 7.5
    assert stats["frac_ge_7"] < 0.5  # most windows are cool padding
    plain = segmented_stats(b"ordinary text. " * 5000)
    assert plain["max"] < 6.0


def test_diluted_fixture_now_flagged():
    # the exact weakness class from the v1 hold-out: random bytes
    # diluted with printable text until global entropy collapses
    rng = random.Random(11)
    blob = bytes(rng.randrange(256) for _ in range(8192))
    blob = blob + b"benign filler text, perfectly ordinary. " * 1400
    v = _engine().scan_bytes(blob, "diluted.bin")
    assert v["verdict"] != "clean", v["evidence"]
    assert any(e.get("heuristic") == "entropy_dilution" for e in v["evidence"])


def test_views_split_pe_overlay():
    pe = _minimal_pe()
    overlay = bytes(range(256)) * 4
    from aegis.formats_pe import parse_pe
    data = pe + overlay
    analysis = parse_pe(data)
    split = split_views(data, "pe", analysis)
    assert split["residual"] == overlay
    assert split["loaded"] == pe
    assert split["loaded_fraction"] < 1.0


def test_ac_feed_equivalence_across_chunkings():
    pack = RulePack(ROOT / "rules" / "core_rules_v2.json")
    data = (b"noise " * 40 + EICAR.encode() + b" more " * 40
            + b"AEGIS-SYNTHETIC-RANSOMWARE-PATTERN" + b"tail" * 30)
    expected = pack.automaton.search(data)
    for chunk_size in (1, 7, 4096, 65536):
        state, hits = 0, {}
        for i in range(0, len(data), chunk_size):
            delta, state = pack.automaton.feed(state, data[i:i + chunk_size])
            for tag, n in delta.items():
                hits[tag] = hits.get(tag, 0) + n
        assert hits == expected, chunk_size


def test_scan_stream_matches_memory_for_text_fixtures(tmp_path):
    engine = _engine()
    cases = {"eicar.txt": EICAR.encode(),
             "clean.txt": b"perfectly ordinary meeting notes\n" * 30,
             "ransom.txt": b"header\nAEGIS-SYNTHETIC-RANSOMWARE-PATTERN\n"}
    for name, blob in cases.items():
        p = tmp_path / name
        p.write_bytes(blob)
        streamed = engine.scan_stream(p, chunk_size=64)
        memory = engine.scan_bytes(blob, name)
        assert streamed["verdict"] == memory["verdict"], (name, streamed, memory)
        assert streamed["hashes"]["sha256"] == memory["hashes"]["sha256"]
