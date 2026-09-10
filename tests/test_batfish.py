"""The Batfish adapter.

Batfish is an optional SECOND OPINION, not a parser we depend on and not a way
to support more vendors -- it covers 10 of the 37 vendors in this brief and
excludes SonicWall, the appliance this project was built against.

These tests pin the three properties that make an optional dependency safe:
it degrades, it never speaks with our authority, and it is not handed configs
it cannot read.
"""
import pytest

from ncsa.batfish import SUPPORTED, analyse, cross_check, status, supports
from ncsa.batfish.adapter import BatfishFinding, BatfishReport, CrossCheck


# ------------------------------------------------------------ scope checking
def test_sonicwall_is_declined_rather_than_misparsed():
    """Handing Batfish an unsupported config produces parse errors that look
    like findings."""
    rep = analyse("does-not-matter.exp", "sonicwall_sonicos")
    assert rep.consulted is False
    assert "does not support" in rep.reason
    assert "SonicWall" in rep.reason


def test_the_supported_list_matches_what_batfish_publishes():
    for p in ("cisco_asa", "juniper_srx", "paloalto_panos",
              "fortinet_fortios", "arista_eos"):
        assert supports(p), p
    for p in ("sonicwall_sonicos", "aruba_aoscx", "no_such_platform"):
        assert not supports(p), p


def test_batfish_covers_a_minority_of_the_brief():
    """The assumption this adapter exists to correct: integrating Batfish does
    not make us compatible with most vendors."""
    brief = {"paloalto", "fortinet", "cisco", "checkpoint", "juniper",
             "sophos", "sonicwall", "watchguard", "barracuda", "zscaler",
             "aws", "azure", "gcp", "hillstone", "a10", "arista", "huawei",
             "mikrotik", "ubiquiti", "extreme", "dell", "cumulus"}
    covered = {v for v in brief if any(v in k for k in SUPPORTED.values())}
    assert len(covered) / len(brief) < 0.5


# ------------------------------------------------------------- degradation
def test_absence_is_a_normal_state_not_an_error():
    """A compliance tool that stops working when a container is down is not a
    compliance tool."""
    s = status()
    assert isinstance(s.available, bool)
    assert s.detail, "an unavailable service must say why"


def test_a_report_that_was_not_consulted_is_not_a_clean_result():
    rep = BatfishReport(consulted=False, reason="not running")
    assert rep.summary()["consulted"] is False
    assert not rep.findings
    # The distinction that matters: no findings because we did not ask is NOT
    # the same as no findings because there were none.
    assert rep.reason


def test_cross_check_reports_nothing_when_batfish_was_not_consulted():
    class _H:
        findings = [type("F", (), {"rule": "r1"})()]
    c = cross_check(_H(), BatfishReport(consulted=False))
    assert c.consulted is False
    assert not c.agreed and not c.only_ncsa and not c.only_batfish


# --------------------------------------------------------------- consensus
def test_cross_check_reports_both_directions():
    """Only-NCSA may be our false positive; only-Batfish is our gap. A
    comparison that showed only agreement would measure nothing."""
    class _H:
        findings = [type("F", (), {"rule": "shared"})(),
                    type("F", (), {"rule": "ours-only"})()]
    bf = BatfishReport(consulted=True, findings=[
        BatfishFinding(kind="unused_structure", node="shared", detail=""),
        BatfishFinding(kind="unused_structure", node="theirs-only", detail="")])
    c = cross_check(_H(), bf)
    assert c.agreed == ["shared"]
    assert c.only_ncsa == ["ours-only"]
    assert c.only_batfish == ["theirs-only"]


def test_batfish_findings_are_labelled_with_their_source():
    """Its model and ours disagree about what a 'rule' is in places; adopting
    its answers silently would make our evidence trail wrong."""
    f = BatfishFinding(kind="unused_structure", detail="x")
    assert f.source == "batfish"
    assert f.to_json()["source"] == "batfish"


# ------------------------------------------------------------- integration
@pytest.mark.skipif(not status().available, reason="Batfish not running")
def test_batfish_reads_a_real_cisco_config():
    rep = analyse("samples/cisco/edge-rtr-01.cfg", "cisco_iosxe_router")
    assert rep.consulted, rep.reason
    # Parse warnings are recorded rather than swallowed: a config Batfish could
    # not read makes every answer empty, and an empty answer is not a clean
    # device.
    assert isinstance(rep.parse_warnings, list)


@pytest.mark.skipif(not status().available, reason="Batfish not running")
def test_two_independent_implementations_are_compared_on_one_device():
    from ncsa.graph.hygiene import analyse as hygiene
    from ncsa.pipeline import assess
    r = assess("samples/cisco/edge-rtr-01.cfg")
    bf = analyse("samples/cisco/edge-rtr-01.cfg", "cisco_iosxe_router")
    c = cross_check(hygiene(r.graph) if r.graph else type("H", (), {"findings": []})(), bf)
    assert c.consulted
