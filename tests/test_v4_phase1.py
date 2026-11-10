from pathlib import Path

from aegis import formats_cfb, formats_pdf, rulelang
from aegis.fieldfuzz import run_campaign
from aegis.parsemutate import mutation_score
from tests.test_v3_phase1 import build_cfb
from tests.test_v3_phase2 import _pdf

ROOT = Path(__file__).resolve().parent.parent


def _seeds() -> list[bytes]:
    return [build_cfb(), build_cfb(cyclic=True),
            _pdf([b"<< /Type /Catalog /OpenAction 2 0 R >>",
                  b"<< /S /JavaScript /JS (x) >>"]),
            b"MZ" + bytes(512), b"%PDF-1.7\n", b""]


def test_field_fuzz_campaign_no_crashes():
    targets = {
        "cfb": lambda b: formats_cfb.parse_cfb(b),
        "pdf": lambda b: formats_pdf.parse_pdf(b),
        "hex": lambda b: rulelang.HexPattern("4D 5A [2-6] 90").search(b),
    }
    result = run_campaign(targets, _seeds(), iterations=600,
                          seed=20261109)
    assert result["cases"] == 600
    assert result["crashes"] == [], result["crashes"][:3]


def test_field_fuzz_oracle_catches_a_broken_target():
    def broken(data: bytes):
        if data.startswith(b"CRASH"):
            raise ValueError("boom")
        return None

    result = run_campaign({"broken": broken}, [b"CRASH-pad"],
                          iterations=30, seed=7)
    assert result["crashes"], "the oracle must catch the planted crash"


def _cfb_probe(mod):
    base = bytearray(build_cfb())
    fatsect_dir = bytearray(base)
    fatsect_dir[3712 + 116:3712 + 120] = (0xFFFFFFFD).to_bytes(4, "little")
    freesect_chain = bytearray(base)
    freesect_chain[512 + 8 * 4:512 + 8 * 4 + 4] = \
        (0xFFFFFFFF).to_bytes(4, "little")
    out = []
    for blob in (build_cfb(), build_cfb(cyclic=True),
                 build_cfb(purged=True), bytes(fatsect_dir),
                 bytes(freesect_chain)):
        r = mod.parse_cfb(blob)
        out.append((tuple(sorted((e["name"], e["size"])
                                 for e in r["entries"])),
                    tuple(sorted(f["type"] for f in r["findings"])),
                    tuple(sorted((k, len(v))
                                 for k, v in r["streams"].items()))))
    return tuple(out)


def _pdf_probe(mod):
    docs = [
        _pdf([b"<< /Type /Catalog /OpenAction 2 0 R >>",
              b"<< /S /JavaScript /JS (x) >>"]),
        _pdf([b"<< /Type /Catalog >>"], trailer_extra=b"/Encrypt 9 0 R"),
        b"%PDF-1.4\nstartxref\n99999\n%%EOF\n",
        b"junk%PDF-1.7\n%%EOF\n",
    ]
    return tuple((tuple(sorted(d["keywords"].items())),
                  tuple(a["kind"] for a in d["actions"]),
                  tuple(f["type"] for f in d["findings"]))
                 for d in (mod.parse_pdf(x) for x in docs))


def _hex_probe(mod):
    samples = [b"MZ\x00\x00\x90", b"MZ\x90", b"MZ" + bytes(300) + b"\x90",
               b"\x4D\x5A\x4F\x90", b"\x4D\x5A\xFF\xA0\x90",
               b"MZ" + bytes(255) + b"\x90", b"MZ" + bytes(256) + b"\x90"]
    out = []
    for pattern in ("4D 5A ?? 90", "4D 5A [2-6] 90", "4D 5A [256] 90",
                    "4D 5A [255] 90", "4D 5A [0] 90", "4D 5A 4? 90",
                    "4D 5A ?0 90", "4D 5A [1-3] A0"):
        try:
            hp = mod.HexPattern(pattern)
            out.append(tuple(hp.search(s) for s in samples))
        except Exception as exc:
            out.append(type(exc).__name__)
    return tuple(out)


def test_parser_mutation_scores(tmp_path):
    # Per-module gates, because the instrument must fit the
    # module: formats_cfb and rulelang are constant-driven and
    # carry score floors. formats_pdf is regex- and text-driven;
    # its integers are caps and tail windows that a behaviour
    # signature over small documents cannot see (measured score
    # 0.016), so its mutation result is reported in full and
    # its windows are covered by direct boundary tests below
    # instead of a score floor. Hiding the 0.016 behind a
    # lowered floor would be exactly the theatre this project
    # exists to avoid.
    floors = {"formats_cfb.py": 0.55, "rulelang.py": 0.4,
              "formats_pdf.py": None}
    for filename, probe in [("formats_cfb.py", _cfb_probe),
                            ("formats_pdf.py", _pdf_probe),
                            ("rulelang.py", _hex_probe)]:
        result = mutation_score(ROOT / "aegis" / filename, probe,
                                tmp_path)
        print(filename, result["score"], "mutants:",
              result["mutants"], "survivors:",
              len(result["survived"]))
        assert result["mutants"] > 10
        floor = floors[filename]
        if floor is not None:
            assert result["score"] >= floor, result


def test_pdf_tail_window_boundaries():
    doc = _pdf([b"<< /Type /Catalog >>"])
    near = formats_pdf.parse_pdf(doc + b"%" + b"x" * 100)
    assert not any(f["type"] == "pdf_no_eof_marker"
                   for f in near["findings"])
    far = formats_pdf.parse_pdf(doc + b"%" + b"x" * 5000)
    assert any(f["type"] == "pdf_no_eof_marker"
               for f in far["findings"])
