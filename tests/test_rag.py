"""Retrieval-layer tests. The licensing ones are the important ones."""
import json

import pytest

from ncsa.frameworks.models import Framework, License
from ncsa.rag.corpus import Document, _clean_title
from ncsa.rag.guard import LicenseViolation, assert_exportable, redact_for_export
from ncsa.rag.index import HybridIndex
from ncsa.rag.probe import Probe, MappingProposal, _literalise, probes_from_packs


def _doc(fw, lic, text="the quick brown fox jumps", cid="1.1"):
    return Document(doc_id=f"{fw.value}:{cid}", framework=fw, control_id=cid,
                    text=text, license=lic, source_document="Doc v1",
                    title="A Title")


# --------------------------------------------------------------- licensing
def test_export_refuses_copyrighted_text():
    docs = [_doc(Framework.CIS, License.IDENTIFIER_ONLY)]
    with pytest.raises(LicenseViolation):
        assert_exportable(docs, sink="examples.jsonl")


def test_export_allows_public_domain():
    docs = [_doc(Framework.NIST_800_53, License.PUBLIC_DOMAIN)]
    assert_exportable(docs, sink="examples.jsonl")     # must not raise


def test_redaction_strips_prose_but_keeps_citation():
    out = redact_for_export(_doc(Framework.CIS, License.IDENTIFIER_ONLY))
    assert out["text"] is None and out["title"] is None
    assert out["control_id"] == "1.1"
    assert out["source_document"] == "Doc v1"


def test_proposal_hides_licensed_title_by_default():
    mp = MappingProposal(field="f", framework="cis", control_id="1.2.3",
                         source_document="CIS Cisco IOS v2.1.0", score=0.1,
                         retrieval={}, title="Ensure something")
    assert mp.to_json()["title"] is None                 # travels
    assert mp.to_json(licensed_ok=True)["title"]          # local review
    assert mp.to_json()["citation"] == "CIS Cisco IOS v2.1.0 - 1.2.3"


def test_proposal_starts_unapproved():
    mp = MappingProposal(field="f", framework="cis", control_id="1",
                         source_document="d", score=0.1, retrieval={})
    assert mp.status == "PROPOSED" and mp.approved_by is None


# ------------------------------------------------------------------ probes
def test_literalise_recovers_the_vendor_command():
    assert _literalise(r"^(no )?ip http server\s*$") == "no ip http server"
    assert _literalise(r"^snmp-server community (\S+)") == "snmp-server community"


def test_literalise_leaves_no_stray_escape_letters():
    for rx in (r"^\s*transport input (.+)$", r"^logging host ([\d.]+)",
               r"^ntp server (\S+)"):
        toks = _literalise(rx).split()
        assert "s" not in toks and "d" not in toks and "S" not in toks


def test_probe_query_carries_vendor_syntax():
    p = Probe(field="management.http.enabled", domain="management",
              value_type="bool",
              vendor_syntax=[{"vendor": "cisco", "raw": "no ip http server"}])
    q = p.query_text()
    assert "no ip http server" in q          # the high-precision term
    assert "plaintext" in q                  # the expanded intent


def test_probes_cover_multiple_vendors_per_field():
    ps = {p.field: p for p in probes_from_packs()}
    p = ps["management.http.enabled"]
    assert len({v["vendor"] for v in p.vendor_syntax}) >= 2


def test_probe_never_carries_config_values_by_default():
    """Production data must not reach the index unless explicitly attached."""
    for p in probes_from_packs():
        assert p.observed_values == []


# ------------------------------------------------------------------- index
def test_collapse_merges_same_recommendation_across_benchmarks():
    docs = [
        Document(doc_id=f"cis:1.1.1:{i}", framework=Framework.CIS,
                 control_id="1.1.1", text="ensure system logging remote host",
                 license=License.IDENTIFIER_ONLY,
                 source_document=f"CIS Vendor{i} v1", title="Ensure System Logging")
        for i in range(4)
    ]
    ix = HybridIndex(docs, cache_path="reference/.embed_cache_test.npz")
    hits = ix.search("system logging remote host", k=5)
    assert len(hits) == 1
    assert len(hits[0].also_in) == 3


def test_framework_filter_is_applied_before_ranking():
    docs = [_doc(Framework.CIS, License.IDENTIFIER_ONLY, "logging remote host"),
            _doc(Framework.NIST_800_53, License.PUBLIC_DOMAIN, "logging remote host",
                 cid="AU-4")]
    ix = HybridIndex(docs, cache_path="reference/.embed_cache_test.npz")
    hits = ix.search("logging remote host", frameworks={Framework.NIST_800_53})
    assert hits and all(h.doc.framework is Framework.NIST_800_53 for h in hits)


def test_confidence_floor_returns_nothing_rather_than_a_guess():
    docs = [_doc(Framework.CIS, License.IDENTIFIER_ONLY, "totally unrelated text")]
    ix = HybridIndex(docs, cache_path="reference/.embed_cache_test.npz")
    assert ix.search("logging", min_rrf=0.99) == []


# ------------------------------------------------------------------ corpus
def test_title_dot_leaders_are_stripped():
    assert _clean_title("Ensure System Logging to a Remote Host ....... 41") == \
        "Ensure System Logging to a Remote Host"
    assert _clean_title(None) is None


# ------------------------------------------------------- CCI-derived NIST
from ncsa.frameworks import cci as ccimod
from ncsa.rag.author import _nist_from_cci, _iso_from_crosswalk


def test_cci_index_canonicalised_to_catalogue_spelling():
    """`AC-17 (2)` must become `AC-17.2` or it matches nothing we hold."""
    assert ccimod.canonical("AC-17 (2)") == "AC-17.2"
    assert ccimod.canonical("CM-6 b") == "CM-6"
    assert ccimod.canonical("IA-3 (1)") == "IA-3.1"
    assert ccimod.canonical("not a control") is None


class _FakeDoc:
    def __init__(self, cid, ccis):
        self.control_id, self.meta = cid, {"ccis": ccis}


class _FakeHit:
    def __init__(self, cid, ccis, rrf=0.02):
        self.doc, self.rrf = _FakeDoc(cid, ccis), rrf


def test_nist_derived_from_stig_carries_its_evidence():
    p = Probe(field="snmp.communities", domain="snmp", value_type="list")
    got = _nist_from_cci(p, [_FakeHit("V-223211", ["CCI-001967"])],
                         {"CCI-001967": ["IA-3.1"]}, {"IA-3.1": "Crypto Auth"}, 3)
    assert len(got) == 1
    assert got[0].control_id == "IA-3.1"
    assert got[0].retrieval["via"] == "stig_cci"
    assert got[0].retrieval["from_stig"] == "V-223211"
    assert got[0].retrieval["cci"] == "CCI-001967"


def test_derived_label_never_outranks_its_source():
    p = Probe(field="f", domain="d", value_type="str")
    nist = _nist_from_cci(p, [_FakeHit("V-1", ["C1"], rrf=0.02)],
                          {"C1": ["AU-2"]}, {}, 3)
    assert nist[0].score <= 0.02
    iso = _iso_from_crosswalk(p, "AU-2", nist[0].score, {"AU-2": ["A.8.15"]}, {}, 3)
    assert iso[0].score <= nist[0].score


def test_no_crosswalk_entry_yields_no_label_rather_than_a_guess():
    p = Probe(field="f", domain="d", value_type="str")
    assert _iso_from_crosswalk(p, "AC-12.3", 0.02, {}, {}, 3) == []
    assert _nist_from_cci(p, [_FakeHit("V-1", [])], {}, {}, 3) == []


# ------------------------------------------------- reader plausibility gate
from ncsa.readers.sonicos_exp import NotASonicOsExport, loads, _assert_plausible


def test_reader_refuses_noise_that_decoded_successfully():
    """Encrypted bytes split into pairs must not pass as a parsed device."""
    import os
    noise = os.urandom(4096).decode("latin-1")
    exp = loads(noise, "random.exp")
    with pytest.raises(NotASonicOsExport):
        _assert_plausible(exp, "random.exp")


def test_reader_accepts_a_real_looking_export():
    exp = loads("allowHttpMgmt=off&minPasswordLength=8&cli_loginBanner=hi",
                "good.exp")
    _assert_plausible(exp, "good.exp")      # must not raise
