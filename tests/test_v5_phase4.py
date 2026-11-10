import sys
import threading
import time
from pathlib import Path

import pytest

from aegis.corpora import make_clean_corpus, make_fixture_corpus
from aegis.engine import Engine
from aegis.rules import RulePack
from aegis.watch import watch_directory

ROOT = Path(__file__).resolve().parent.parent
EICAR = (b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$"
         b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")


def _engine():
    return Engine(RulePack(ROOT / "rules" / "core_rules_v2.json"))


def test_mmap_scan_and_empty_file(tmp_path):
    target = tmp_path / "e.txt"
    target.write_bytes(EICAR)
    v = _engine().scan_file_mmap(target)
    assert v["verdict"] == "malicious_pattern"
    assert v["scan_method"] == "mmap"
    empty = tmp_path / "empty.bin"
    empty.write_bytes(b"")
    v2 = _engine().scan_file_mmap(empty)
    assert v2["file"] == str(empty)


def _watch_semantics(tmp_path: Path, backend: str):
    def drop():
        time.sleep(0.6)
        (tmp_path / "dropped.txt").write_bytes(EICAR)
    threading.Thread(target=drop).start()
    events = watch_directory(tmp_path, _engine(), duration_s=3.0,
                             backend=backend)
    assert any(e["verdict"] == "malicious_pattern" for e in events), \
        (backend, events)


def test_watch_poll_semantics(tmp_path):
    _watch_semantics(tmp_path, "poll")


@pytest.mark.skipif(sys.platform != "linux",
                    reason="inotify backend is Linux-only")
def test_watch_inotify_semantics(tmp_path):
    # Kill criterion (v5 research): this backend ships only
    # while it passes the shared semantics suite in CI.
    _watch_semantics(tmp_path, "inotify")


def test_scaling_reports_identical_summaries(tmp_path):
    corpus = tmp_path / "corpus"
    make_clean_corpus(corpus / "clean")
    make_fixture_corpus(corpus / "fixtures")
    from benchmarks.scaling import measure
    result = measure(corpus, workers_list=(1, 2))
    assert all(r["summary_identical"] for r in result["rows"])
    assert all(r["files_per_sec"] > 0 for r in result["rows"])
