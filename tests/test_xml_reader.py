"""The structured-input tier.

Accuracy here is a mapping problem, not a parsing problem -- the device already
parsed its own configuration. These tests pin the properties that make that
true, and the two bugs found while building it.
"""
import pytest

from ncsa.pipeline import assess
from ncsa.readers.xml_reader import loads
from ncsa.schema.enums import ResultState

HARD = "samples/juniper/srx-display-xml.xml"
WEAK = "samples/juniper/srx-display-xml-weak.xml"

JUNOS = """<?xml version="1.0"?>
<rpc-reply xmlns:junos="http://xml.juniper.net/junos/21.4R0/junos">
  <configuration>
    <system>
      <host-name>srx-1</host-name>
      <services>
        <telnet/>
        <ssh><protocol-version>v2</protocol-version></ssh>
      </services>
      <syslog>
        <host><name>10.0.0.1</name></host>
        <host><name>10.0.0.2</name></host>
      </syslog>
    </system>
  </configuration>
</rpc-reply>
"""


# ------------------------------------------------------------------- parsing
def test_namespaces_are_stripped_from_tags_and_attributes():
    d = loads(JUNOS)
    assert any(p.endswith("system/host-name") for p in d.paths)
    assert not any("{" in p for p in d.paths)


def test_empty_element_is_a_flag_not_a_missing_value():
    """Junos writes `<telnet/>` to mean telnet is ENABLED. Reading that as
    absent inverts every boolean the vendor expresses this way."""
    d = loads(JUNOS)
    hit = d.get("configuration/system/services/telnet")
    assert hit is not None and hit[0] == "<present>"


def test_repeated_elements_get_distinct_line_numbers():
    """Both syslog hosts once cited the same line, so the evidence for the
    second server pointed at the first. Evidence at the wrong line is worse
    than none -- a reviewer checks it, sees a different value, and stops
    trusting the report."""
    d = loads(JUNOS)
    hits = d.glob("configuration/system/syslog/host/name")
    assert len(hits) == 2
    lines = [ln for _p, _v, ln, _r in hits]
    assert len(set(lines)) == 2, "repeated elements must not share a line"


def test_line_numbers_point_at_the_real_source_line():
    src = JUNOS.splitlines()
    d = loads(JUNOS)
    for _p, val, ln, _raw in d.glob("configuration/system/syslog/host/name"):
        assert val in src[ln - 1], f"line {ln} does not contain {val}"


def test_evidence_carries_the_structural_path():
    """`record_id` exists for non-line formats; an XML export re-serialised
    with different whitespace keeps its path but loses its line numbers."""
    d = loads(JUNOS)
    hit = d.get("configuration/system/services/ssh/protocol-version")
    ev = d.evidence(hit[1], hit[2])
    assert ev.record_id == "configuration/system/services/ssh/protocol-version"
    assert ev.file and ev.line


def test_malformed_xml_is_refused_not_half_parsed():
    with pytest.raises(ValueError):
        loads("<config><unclosed>")


def test_records_are_elements_not_lines():
    """An XML export is often one very long line; counting lines would report
    a 40,000-element config as a single record."""
    one_line = JUNOS.replace("\n", "")
    assert loads(one_line).total_records > 5


# --------------------------------------------------------------- end to end
def _exists(*p):
    import os
    return all(os.path.exists(x) for x in p)


@pytest.mark.skipif(not _exists(HARD), reason="fixture absent")
def test_junos_xml_is_fingerprinted_and_assessed():
    r = assess(HARD)
    assert r.supported
    assert r.identity.platform == "juniper_srx_xml"
    assert r.identity.hostname == "srx-edge-02"
    assert r.identity.version == "21.4R3-S4.9"


@pytest.mark.skipif(not _exists(HARD, WEAK), reason="fixtures absent")
def test_pack_discriminates_rather_than_agreeing_with_its_author():
    """A pack validated only against a config its own author wrote is not
    validated. The negative control is what makes the hardened score mean
    something."""
    good = assess(HARD).coverage()["score_pct"]
    bad = assess(WEAK).coverage()["score_pct"]
    assert good > bad + 30, f"hardened {good}% vs weak {bad}%"


@pytest.mark.skipif(not _exists(HARD, WEAK), reason="fixtures absent")
def test_explicit_permit_all_is_observed_not_reported_as_absent():
    """`<permit-all/>` is a positively observable failure. Mapping only the
    `deny-all` form made an explicitly permissive device report that no
    default policy was configured -- and the braces pack had the same defect
    earlier, where a hardcoded `deny` produced a false PASS."""
    weak = [f for f in assess(WEAK).assessment.findings
            if f.control_id == "NCSA-CLD-004"][0]
    assert weak.state is ResultState.FAIL
    assert weak.observed == "permit"
    assert weak.evidence, "an observed failure must cite its line"

    good = [f for f in assess(HARD).assessment.findings
            if f.control_id == "NCSA-CLD-004"][0]
    assert good.state is ResultState.PASS
    assert good.observed == "deny"


@pytest.mark.skipif(not _exists(WEAK), reason="fixture absent")
def test_weak_config_findings_carry_xml_paths():
    r = assess(WEAK)
    anchored = [f for f in r.failures() if f.evidence and f.evidence[0].record_id]
    assert anchored, "structured findings should cite a structural path"
