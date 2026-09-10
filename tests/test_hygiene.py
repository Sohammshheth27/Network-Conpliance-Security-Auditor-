"""Rule hygiene: dead, shadowed, redundant, over-broad policy.

The capability every comparable product leads with -- Batfish,
firewall-orchestrator, ManageEngine, AlgoSec -- and the one NCSA had none of
while holding all the data required.

Nothing here is probabilistic. Shadowing is set containment evaluated in policy
order: decidable, explainable, and either right or wrong. That matters because
the finding says "delete this rule".
"""
import os

import pytest

from ncsa.graph.hygiene import ANY, HygieneFinding, _covers, analyse
from ncsa.graph.model import Node, NodeKind, ObjectGraph, SecurityRule
from ncsa.pipeline import assess

SW = r"E:\sonicwall config file.txt"
sw_only = pytest.mark.skipif(not os.path.exists(SW), reason="SonicWall sample absent")


def _graph(rules, nodes=()):
    g = ObjectGraph()
    for n in nodes:
        g.add(n)
    for r in rules:
        g.add_rule(r)
    return g


def _rule(rid, order, action="allow", src=("any",), dst=("any",),
          svc=("any",), enabled=True, hits=None, szone=("lan",), dzone=("wan",)):
    return SecurityRule(id=rid, name=rid, order=order, action=action,
                        enabled=enabled, source=list(src), destination=list(dst),
                        services=list(svc), source_zones=list(szone),
                        destination_zones=list(dzone), hit_count=hits)


# ------------------------------------------------------------- containment
def test_any_covers_everything_and_nothing_covers_any():
    assert _covers({ANY}, {"10.0.0.1"})
    assert not _covers({"10.0.0.1"}, {ANY})
    assert _covers({"10.0.0.1", "10.0.0.2"}, {"10.0.0.1"})


def test_unresolved_never_counts_as_covered():
    """None is not an empty set. An empty set matches nothing; None means we
    could not tell, and conflating them reports that an unreadable rule
    shadows nothing."""
    assert not _covers(None, {"10.0.0.1"})
    assert not _covers({ANY}, None)


# ---------------------------------------------------------------- findings
def test_a_deny_below_an_allow_any_is_shadowed():
    """The real finding from a production appliance: an operator wrote a deny
    rule that has no effect because an allow-any sits above it."""
    g = _graph([_rule("allow-all", 1, "allow"),
                _rule("deny-bad-host", 2, "deny", dst=("10.51.152.9",))])
    rep = analyse(g)
    shadowed = rep.by_kind("shadowed_rule")
    assert len(shadowed) == 1
    assert shadowed[0].rule == "deny-bad-host"
    assert shadowed[0].related == "allow-all"
    assert shadowed[0].severity == "high"


def test_same_action_below_a_broader_rule_is_redundant_not_shadowed():
    g = _graph([_rule("allow-all", 1, "allow"),
                _rule("allow-one", 2, "allow", dst=("10.0.0.1",))])
    rep = analyse(g)
    assert len(rep.by_kind("redundant_rule")) == 1
    assert not rep.by_kind("shadowed_rule"), "same action is redundant, not shadowed"


def rep_kinds(rep):
    out = {}
    for f in rep.findings:
        out[f.kind] = out.get(f.kind, 0) + 1
    return out


def test_order_matters_a_specific_rule_first_is_not_shadowed():
    """Correct policy -- specific before general -- must produce no finding."""
    g = _graph([_rule("deny-one", 1, "deny", dst=("10.0.0.1",)),
                _rule("allow-all", 2, "allow")])
    assert not analyse(g).by_kind("shadowed_rule")


def test_different_zones_are_not_shadowing():
    g = _graph([_rule("a", 1, "allow", szone=("lan",), dzone=("wan",)),
                _rule("b", 2, "deny", szone=("dmz",), dzone=("wan",))])
    assert not analyse(g).by_kind("shadowed_rule")


def test_zero_hit_rule_is_reported_with_the_reset_caveat():
    """A hit counter resets on reboot, so zero hits is evidence of disuse --
    not proof a rule is unnecessary."""
    g = _graph([_rule("dr-failover", 1, hits=0)])
    f = analyse(g).by_kind("unused_rule")
    assert len(f) == 1
    assert "reset" in f[0].detail and "disaster-recovery" in f[0].detail


def test_a_rule_with_no_counter_is_not_called_unused():
    """None is not zero. Most platforms publish no counter at all."""
    assert not analyse(_graph([_rule("x", 1, hits=None)])).by_kind("unused_rule")


def test_any_any_allow_is_flagged_as_over_broad():
    f = analyse(_graph([_rule("wide", 1, "allow")])).by_kind("overly_permissive")
    assert len(f) == 1 and f[0].severity == "high"


def test_disabled_rules_are_never_treated_as_active_policy():
    g = _graph([_rule("off-allow-all", 1, "allow", enabled=False),
                _rule("deny-one", 2, "deny", dst=("10.0.0.1",))])
    rep = analyse(g)
    assert not rep.by_kind("shadowed_rule"), "a disabled rule shadows nothing"
    assert rep.by_kind("disabled_rule")


# ------------------------------------------------------- self-verification
def test_the_device_counter_can_refute_our_own_analysis():
    """A rule the analysis calls unreachable that HAS matched traffic proves
    the containment logic wrong. Reported, not dropped."""
    g = _graph([_rule("allow-all", 1, "allow"),
                _rule("deny-one", 2, "deny", dst=("10.0.0.1",), hits=5000)])
    rep = analyse(g)
    assert not rep.by_kind("shadowed_rule")
    disputed = rep.by_kind("disputed_shadow")
    assert len(disputed) == 1
    assert "5,000" in disputed[0].detail


@sw_only
def test_containment_findings_beat_the_base_rate_of_unused_rules():
    """`zero hits` only corroborates containment if flagged rules are MORE
    likely to be unused than rules generally. On this appliance 85% of enabled
    rules have zero hits, so agreement had to be checked against that base
    rate rather than assumed to be evidence."""
    r = assess(SW)
    rules = [x for x in r.graph.rules if x.hit_count is not None and x.enabled]
    base = sum(1 for x in rules if x.hit_count == 0) / len(rules)
    rep = analyse(r.graph)
    flagged = rep.by_kind("shadowed_rule") + rep.by_kind("redundant_rule")
    assert flagged
    rate = sum(1 for f in flagged if f.hit_count == 0) / len(flagged)
    assert rate > base, f"flagged {rate:.0%} vs base {base:.0%}"


@sw_only
def test_the_device_can_still_refute_us_and_we_say_so():
    """SonicOS auto-sorts rules by specificity, so policy order is not the
    priority field. Rule #13 (any/any/any) covers #18 by set logic while #18
    has 4.1M matches -- impossible if #13 ran first. Those cases must surface
    as disputes, not be quietly dropped or quietly kept."""
    rep = analyse(assess(SW).graph)
    disputed = rep.by_kind("disputed_shadow")
    assert disputed, "the ordering assumption is wrong here; it must show"
    for f in disputed:
        assert f.hit_count and f.hit_count > 0
        assert "wrong" in f.detail


@sw_only
def test_unevaluable_rules_are_reported_not_assumed_clean():
    rep = analyse(assess(SW).graph)
    assert rep.rules_resolved < rep.rules_examined
    assert rep.unevaluable, "rules we could not resolve must be named"
