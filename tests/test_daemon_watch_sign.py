import json
import time
from pathlib import Path

import pytest

from aegis import ed25519, packsign
from aegis.daemon import handle_request
from aegis.engine import Engine
from aegis.rules import RulePack
from aegis.watch import watch_directory

ROOT = Path(__file__).resolve().parent.parent
SEED = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"


@pytest.fixture()
def engine():
    return Engine(RulePack(ROOT / "rules" / "core_rules_v2.json"))


def test_ed25519_rfc8032_vector():
    pk = ed25519.publickey(bytes.fromhex(SEED))
    assert pk.hex() == "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    sig = ed25519.signature(b"", bytes.fromhex(SEED), pk)
    assert ed25519.checkvalid(sig, b"", pk)
    assert not ed25519.checkvalid(sig, b"tampered", pk)


def test_signed_pack_roundtrip_and_rollback(tmp_path):
    pack = ROOT / "rules" / "core_rules_v2.json"
    manifest_path = tmp_path / "manifest.json"
    state = tmp_path / "state.json"
    packsign.sign_pack(pack, SEED, sequence=7, out_path=manifest_path)
    out = packsign.verify_pack(pack, manifest_path, state_path=state)
    assert out["sequence"] == 7
    with pytest.raises(packsign.PackVerificationError):
        packsign.verify_pack(pack, manifest_path, state_path=state)  # rollback/replay
    tampered = tmp_path / "tampered.json"
    doc = json.loads(pack.read_text())
    doc["version"] = "9.9.9"
    tampered.write_text(json.dumps(doc))
    with pytest.raises(packsign.PackVerificationError):
        packsign.verify_pack(tampered, manifest_path, state_path=tmp_path / "s2.json")


def test_daemon_handle_routes(engine, tmp_path):
    status, doc = handle_request(engine, "GET", "/ping")
    assert status == 200 and doc["status"] == "ok"
    f = tmp_path / "f.txt"
    f.write_bytes(b"boring text")
    status, doc = handle_request(engine, "POST", "/scan",
                                 json.dumps({"path": str(f)}).encode())
    assert status == 200 and doc["verdict"] == "clean"
    status, _ = handle_request(engine, "GET", "/ping", token="s3cret")
    assert status == 401
    status, _ = handle_request(engine, "GET", "/ping", token="s3cret",
                               auth_header="s3cret")
    assert status == 200


def test_watch_detects_new_file(engine, tmp_path):
    import threading

    def create_later():
        time.sleep(0.6)
        (tmp_path / "dropped.txt").write_bytes(
            b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")

    threading.Thread(target=create_later, daemon=True).start()
    events = watch_directory(tmp_path, engine, duration_s=2.5, interval_s=0.2)
    assert any(e["verdict"] == "malicious_pattern" for e in events), events
