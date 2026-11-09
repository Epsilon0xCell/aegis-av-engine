from aegis.corpora import make_clean_corpus, make_fixture_corpus
from aegis.formats import shannon_entropy


def test_fixture_properties_are_true(tmp_path):
    """A corpus generator's labels are claims; test them. The
    high-entropy fixture shipped with entropy 0.0 through three
    releases because nothing asserted the property its name
    claims (per-byte construction of a fresh Random instance).
    This test exists so a generator bug can never again
    masquerade as a detector miss in a hold-out report."""
    make_fixture_corpus(tmp_path)
    blob = (tmp_path / "fixture_high_entropy.bin").read_bytes()
    assert shannon_entropy(blob) > 7.0
    assert len(set(blob)) > 200


def test_clean_corpus_has_no_fixture_markers(tmp_path):
    from aegis.corpora import make_clean_corpus as mcc
    manifest = mcc(tmp_path)
    for name in manifest:
        blob = (tmp_path / name).read_bytes()
        assert b"AEGIS-SYNTH" not in blob
        assert b"EICAR" not in blob
