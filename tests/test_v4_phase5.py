from pathlib import Path

from aegis.engine import Engine
from aegis.rules import RulePack

ROOT = Path(__file__).resolve().parent.parent


def _fixtures() -> dict[str, bytes]:
    hex_blob = b"MZ" + bytes(8) + b"AEGIS" + bytes(64)
    return {
        "eicar.txt": (b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$"
                      b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"),
        "fixture.bin": b"AEGIS-SYNTHETIC-RANSOMWARE-PATTERN" + bytes(50),
        "hexpe.bin": hex_blob,
        "clean.txt": b"an ordinary document with nothing to hide\n" * 4,
        # hex match straddling many small chunks
        "straddle.bin": bytes(300) + b"MZ" + bytes(8) + b"AEGIS"
        + bytes(300),
    }


def test_streaming_hex_parity(tmp_path):
    engine = Engine(RulePack(ROOT / "rules" / "core_rules_v2.json"))
    for name, data in _fixtures().items():
        path = tmp_path / name
        path.write_bytes(data)
        memory = engine.scan_bytes(data, name)
        for chunk in (1, 7, 64, 65536):
            streamed = engine.scan_stream(path, chunk_size=chunk)
            assert streamed["verdict"] == memory["verdict"], (
                name, chunk, streamed["verdict"], memory["verdict"])
            assert streamed["score"] == memory["score"], (
                name, chunk, streamed["score"], memory["score"])
            assert (streamed["hashes"]["sha256"]
                    == memory["hashes"]["sha256"])
        note = next(e for e in streamed["evidence"]
                    if e["type"] == "stream_note")
        assert "hex" in note["detail"] \
            and "not evaluated" not in note["detail"]


def test_streaming_hex_rule_actually_fires(tmp_path):
    engine = Engine(RulePack(ROOT / "rules" / "core_rules_v2.json"))
    path = tmp_path / "hexpe.bin"
    path.write_bytes(_fixtures()["hexpe.bin"])
    streamed = engine.scan_stream(path, chunk_size=7)
    assert any(e.get("rule_id") == "AEGIS-HEX-001"
               for e in streamed["evidence"])
