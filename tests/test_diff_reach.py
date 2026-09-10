"""Change over time, and reachability.

The two capabilities every comparable product has and NCSA did not:
firewall-orchestrator sells change history, Batfish sells reachability.
"""
import os

import pytest

from ncsa.diff import COVERAGE, IMPROVED, REGRESSED, compare, snapshot
from ncsa.diff.compare import Snapshot, _direction, device_identifiers
from ncsa.graph.model import ObjectGraph, SecurityRule
from ncsa.graph.reach import Query, _addr_in, _svc_matches, ask
from ncsa.pipeline import assess

SW = r"E:\sonicwall config file.txt"
SWH = r"E:\sonicwall-NSA3700-SonicOS7.3-HARDENED.exp"
both = pytest.mark.skipif(not (os.path.exists(SW) and os.path.exists(SWH)),
                          reason="SonicWall samples absent")


class _Id:
    def __init__(self, serial=None, hostname=None, source_file="f.cfg"):
        self.serial, self.hostname, self.source_file = serial, hostname, source_file


def _snap(**kw):
    base = dict(taken_at="t", device_key="k", config_sha256="c",
                analysis_version="v", device_keys=["k"])
    base.update(kw)
    return Snapshot(**base)


# ----------------------------------------------------------- device identity
def test_a_device_exposes_several_identifiers():
    ids = device_identifiers(_Id(serial="ABC", hostname="fw1"))
    assert ids[0] == "serial:ABC" and "host:fw1" in ids


def test_two_exports_match_on_any_shared_strong_identifier():
    """A sanitised export carries the same hostname but a zeroed serial, so
    keying on 'serial, else hostname' made one appliance look like two and the
    change history between them was refused."""
    a = _snap(device_keys=["serial:ABC", "host:fw1"], device_key="serial:ABC")
    b = _snap(device_keys=["host:fw1"], device_key="host:fw1")
    assert compare(a, b).same_device


def test_a_shared_filename_is_not_a_shared_device():
    a = _snap(device_keys=["serial:AAA", "file:cfg.txt"], device_key="serial:AAA")
    b = _snap(device_keys=["serial:BBB", "file:cfg.txt"], device_key="serial:BBB")
    assert not compare(a, b).same_device


# -------------------------------------------------------------- attribution
def test_an_analysis_change_is_never_reported_as_a_device_change():
    """If a pack gained a mapping between runs, findings move while the
    configuration is untouched. Calling that '3 new violations' is a lie the
    operator cannot detect."""
    a = _snap(states={"C1": "PASS"}, analysis_version="v1")
    b = _snap(states={"C1": "FAIL"}, analysis_version="v2")
    rep = compare(a, b)
    assert rep.analysis_changed and not rep.device_changed
    assert rep.control_changes[0].attributable_to == "analysis"
    assert "configuration is IDENTICAL" in rep.explain()


def test_both_changing_makes_deltas_advisory():
    a = _snap(states={"C1": "PASS"}, analysis_version="v1", config_sha256="a")
    b = _snap(states={"C1": "FAIL"}, analysis_version="v2", config_sha256="b")
    rep = compare(a, b)
    assert rep.control_changes[0].attributable_to == "ambiguous"
    assert "ADVISORY" in rep.explain()


def test_unknown_to_pass_is_coverage_not_improvement():
    """The device may be unchanged and our coverage simply grew. Calling it a
    fix credits the tool for work the operator did not do."""
    assert _direction("UNKNOWN", "PASS") == COVERAGE
    assert _direction("FAIL", "PASS") == IMPROVED
    assert _direction("PASS", "FAIL") == REGRESSED


def test_hit_counts_do_not_make_every_rule_look_changed():
    """A counter moves on every packet; a diff reporting 329 changed rules
    because traffic flowed is a diff nobody reads twice."""
    from ncsa.diff.compare import _rule_signature
    a = SecurityRule(id="r", order=1, action="allow", hit_count=0)
    b = SecurityRule(id="r", order=1, action="allow", hit_count=999999)
    assert _rule_signature(a) == _rule_signature(b)


@both
def test_real_hardening_shows_as_improvement_on_the_same_device():
    a = snapshot(assess(SW), taken_at="2026-09-01T09:00:00")
    b = snapshot(assess(SWH), taken_at="2026-09-05T09:00:00")
    rep = compare(a, b)
    assert rep.same_device, rep.notes
    assert rep.device_changed and not rep.analysis_changed
    assert len(rep.by_direction(IMPROVED)) >= 5
    assert not rep.by_direction(REGRESSED)


# -------------------------------------------------------------- reachability
def test_a_query_for_any_is_not_matched_by_a_specific_rule():
    """Asking 'can an arbitrary host reach this' is answered only by rules
    whose own side accepts anything. Treating a query of `any` as matching
    every rule let a deny scoped to a malicious-IP list appear to block all
    inbound traffic -- reporting a wide-open firewall as fully protected."""
    assert not _addr_in("10.0.0.5", "any")
    assert _addr_in("any", "10.0.0.5")
    assert _addr_in("10.0.0.0/8", "10.1.2.3")


def test_service_matching_respects_protocol_and_range():
    assert _svc_matches("tcp/22", "tcp", 22)
    assert not _svc_matches("tcp/22", "udp", 22)
    assert _svc_matches("tcp/20-25", "tcp", 22)
    assert _svc_matches("any", "tcp", 22)


def test_first_match_wins_so_a_deny_below_an_allow_has_no_effect():
    """The product's whole thesis: a config can contain a deny for a host and
    still permit traffic to it."""
    g = ObjectGraph()
    g.add_rule(SecurityRule(id="allow", name="allow-all", order=1,
                            action="allow", source=["any"],
                            destination=["any"], services=["any"]))
    g.add_rule(SecurityRule(id="deny", name="deny-host", order=2, action="deny",
                            source=["any"], destination=["10.0.0.9"],
                            services=["any"]))
    a = ask(g, Query(destination="10.0.0.9", port=443))
    assert a.permitted is True
    assert a.decided_by == "allow-all"


def test_correct_order_produces_the_intended_denial():
    g = ObjectGraph()
    g.add_rule(SecurityRule(id="deny", name="deny-host", order=1, action="deny",
                            source=["any"], destination=["10.0.0.9"],
                            services=["any"]))
    g.add_rule(SecurityRule(id="allow", name="allow-all", order=2,
                            action="allow", source=["any"],
                            destination=["any"], services=["any"]))
    assert ask(g, Query(destination="10.0.0.9", port=443)).permitted is False


def test_no_match_and_no_stated_default_is_undecidable():
    """Assuming default-deny is right on most platforms and wrong on exactly
    the ones where it matters."""
    g = ObjectGraph()
    g.add_rule(SecurityRule(id="r", order=1, action="allow",
                            source=["10.0.0.1"], destination=["10.0.0.2"],
                            services=["tcp/80"]))
    a = ask(g, Query(source="192.168.1.1", destination="8.8.8.8", port=53))
    assert a.permitted is None
    assert "default" in a.reason


def test_an_unevaluable_rule_above_the_answer_is_caveated():
    g = ObjectGraph()
    g.add_rule(SecurityRule(id="broken", name="broken", order=1, action="deny",
                            source=["NoSuchGroup"], destination=["any"],
                            services=["any"]))
    g.add_rule(SecurityRule(id="allow", name="allow-all", order=2,
                            action="allow", source=["any"],
                            destination=["any"], services=["any"]))
    a = ask(g, Query(destination="10.0.0.9", port=443))
    assert a.permitted is True
    assert a.skipped == ["broken"]
    assert "could not be evaluated" in a.explain()


@pytest.mark.skipif(not os.path.exists(SW), reason="sample absent")
def test_real_device_deny_all_is_found_and_named():
    r = assess(SW)
    a = ask(r.graph, Query(destination="any", port=22, source_zone="WAN"))
    assert a.permitted is False
    assert a.decided_by, "a verdict must name the rule that produced it"
