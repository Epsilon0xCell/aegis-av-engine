import base64
from pathlib import Path

from aegis.engine import Engine
from aegis.rules import RulePack
from aegis.script_lab import analyze_script

ROOT = Path(__file__).resolve().parent.parent


def _engine():
    return Engine(RulePack(ROOT / "rules" / "core_rules_v2.json"))


def test_encoded_command_layer_convicts():
    inner = ("IEX (New-Object Net.WebClient).DownloadString('x')\n"
             "# AEGIS-SYNTH-download-cradle AEGIS-SYNTH-hidden-window\n")
    enc = base64.b64encode(inner.encode("utf-16-le")).decode()
    outer = f"powershell -enc {enc}\n".encode()
    v = _engine().scan_bytes(outer, "run.ps1")
    assert any(e.get("type") == "script_layer_match" for e in v["evidence"])
    assert any(e.get("heuristic") == "script_obfuscated_high_risk"
               for e in v["evidence"])
    assert v["verdict"] == "malicious_pattern"


def test_char_array_and_atob_layers():
    marker = "AEGIS-SYNTHETIC-RANSOMWARE-PATTERN"
    nums = ",".join(str(b) for b in marker.encode())
    script = f"var s = [{nums}];\n".encode()
    a = analyze_script(script)
    assert any(l["kind"] == "char_array" for l in a["layers"])
    js = ("var x = atob('" + base64.b64encode(
        b"payload AEGIS-SYNTHETIC-RANSOMWARE-PATTERN").decode()
        + "');").encode()
    v = _engine().scan_bytes(js, "x.js")
    assert any(e.get("type") == "script_layer_match" for e in v["evidence"])


def test_benign_base64_does_not_convict():
    harmless = base64.b64encode(
        "Write-Host 'backup finished ok'".encode("utf-16-le")).decode()
    script = (f"$cmd = '{harmless}'\n"
              "Write-Host 'nightly backup'\n").encode()
    v = _engine().scan_bytes(script, "backup.ps1")
    assert v["verdict"] == "clean"
    assert any(e.get("type") == "script_encoded_layer"
               and e.get("kind", "").startswith("base64")
               for e in v["evidence"])  # the layer is reported...
    # ...but encoding alone scores nothing


def test_unresolved_constructs_reported_not_executed():
    script = b"$x = 'a' -f $y\n[scriptblock]::Create($z)\n"
    a = analyze_script(script)
    assert "-f format operator" in a["unresolved_constructs"]
    assert "ScriptBlock.Create" in a["unresolved_constructs"]


def test_vbs_chr_chain():
    text = "".join(f"Chr({b})&" for b in b"wscript.shell")
    a = analyze_script(("s = " + text).encode())
    assert any(l["kind"] == "chr_chain" for l in a["layers"])
