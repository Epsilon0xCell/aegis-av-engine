import json
import time
import zipfile
from pathlib import Path

import pytest

from aegis import packupdate, witness
from aegis.behaviour import analyse
from aegis.engine import Engine
from aegis.mining import CandidatePattern, mine
from aegis.rules import RulePack
from aegis.sbom import generate_sbom
from aegis.transparency import TransparencyLog

ROOT = Path(__file__).resolve().parent.parent
SEED = bytes(range(32))
SEED2 = bytes(range(32, 64))


def _sessions():
    ransomware = ["process_create:T1490", "file_encrypt:T1486",
                  "beacon:T1071.001"]
    keylog = ["hook_install:T1056.001", "log_append:T1056.001",
              "beacon:T1071.001"]
    benign = ["file_read", "file_write", "process_create:T1490"]
    return [ransomware, list(ransomware), keylog, list(keylog), benign]


def test_mining_finds_candidate_chains():
    candidates = mine(_sessions(), min_support=2)
    patterns = [c.pattern for c in candidates]
    assert ("process_create:T1490", "file_encrypt:T1486") in patterns \
        or ("process_create:T1490", "file_encrypt:T1486",
            "beacon:T1071.001") in patterns
    assert all(isinstance(c, CandidatePattern) for c in candidates)
    assert all(c.status == "candidate_requires_human_promotion"
               for c in candidates)
    # the wall: miner output is not correlator input. analyse
    # consumes event dicts; a CandidatePattern is not one.
    assert not isinstance(candidates[0], dict)


def test_packupdate_happy_rotation_and_rejections(tmp_path):
    state = tmp_path / "state.json"
    pack = b'{"rules": []}'
    root = packupdate.make_root(SEED, SEED2, key_sequence=1)
    ts = packupdate.make_timestamp(SEED, root["current_key"], "3.0.0",
                                   pack, sequence=1)
    out = packupdate.verify_and_update(state, root, ts, pack)
    assert out["trust_on_first_use"] is True
    # rotation: new root signed by old key, current = announced next
    root2 = packupdate.make_root(SEED2, None, key_sequence=2)
    # root2 is self-signed by SEED2; the protocol requires the OLD
    # key's signature on a rotation, so sign it with SEED instead:
    from aegis import ed25519
    body = {k: v for k, v in root2.items() if k != "signature"}
    root2["signature"] = ed25519.signature(
        packupdate._canon(body), SEED,
        bytes.fromhex(root["current_key"])).hex()
    ts2 = packupdate.make_timestamp(SEED2, root2["current_key"], "3.0.1",
                                    pack, sequence=2)
    out2 = packupdate.verify_and_update(state, root2, ts2, pack)
    assert out2["root_sequence"] == 2
    # rollback: replaying sequence 2 refuses
    with pytest.raises(packupdate.UpdateError):
        packupdate.verify_and_update(state, root2, ts2, pack)
    # freeze: expired timestamp refuses
    old_ts = packupdate.make_timestamp(SEED2, root2["current_key"],
                                       "3.0.2", pack, sequence=3,
                                       ttl_hours=1,
                                       now=time.time() - 7200)
    with pytest.raises(packupdate.UpdateError):
        packupdate.verify_and_update(state, root2, old_ts, pack)
    # tampered pack refuses
    ts3 = packupdate.make_timestamp(SEED2, root2["current_key"], "3.0.2",
                                    pack, sequence=3)
    with pytest.raises(packupdate.UpdateError):
        packupdate.verify_and_update(state, root2, ts3, b"tampered")


def test_witness_quorum(tmp_path):
    log = TransparencyLog(tmp_path / "log.json", signing_seed=SEED)
    head = log.append({"manifest": 1})
    policy = {"witnesses": {"w1": None, "w2": None}, "quorum": 2}
    from aegis import ed25519
    policy["witnesses"] = {
        "w1": ed25519.publickey(SEED).hex(),
        "w2": ed25519.publickey(SEED2).hex()}
    c1 = witness.cosign(head, "w1", SEED)
    c2 = witness.cosign(head, "w2", SEED2)
    assert not witness.verify_cosignatures(head, [c1], policy)["ok"]
    out = witness.verify_cosignatures(head, [c1, c2], policy)
    assert out["ok"] and out["valid"] == ["w1", "w2"]
    bad = dict(c2, root="00" * 32)
    out2 = witness.verify_cosignatures(head, [c1, bad], policy)
    assert not out2["ok"] and out2["problems"]


def test_sbom_from_zip(tmp_path):
    zp = tmp_path / "rel.zip"
    with zipfile.ZipFile(zp, "w") as zf:
        zf.writestr("aegis/x.py", "print(1)\n")
        zf.writestr("README.md", "hi\n")
    doc = generate_sbom(zp, "aegis-av-engine", "3.0.0")
    assert doc["bomFormat"] == "CycloneDX"
    names = [c["name"] for c in doc["components"]]
    assert names == ["README.md", "aegis/x.py"]
    again = generate_sbom(zp, "aegis-av-engine", "3.0.0")
    assert json.dumps(doc, sort_keys=True) == json.dumps(again,
                                                         sort_keys=True)


def test_lazy_tlsh_policy(tmp_path):
    engine = Engine(RulePack(ROOT / "rules" / "core_rules_v2.json"))
    clean = engine.scan_bytes(b"an ordinary text file\n" * 10, "a.txt")
    assert clean["tlsh"] is None
    assert "tlsh_skipped" in clean
    marker = (ROOT / "aegis" / "corpora.py").read_bytes()[:0] \
        + b"AEGIS-SYNTHETIC-RANSOMWARE-PATTERN" + bytes(200)
    bad = engine.scan_bytes(marker, "b.bin")
    assert bad["tlsh"] is not None and bad["tlsh"].startswith("T1")
    assert engine.tlsh_of(marker) == bad["tlsh"]
