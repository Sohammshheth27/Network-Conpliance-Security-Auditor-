"""AWS security groups as a policy object graph.

Validated against a real `describe-security-groups` export: three groups, nine
rules, including SSH open to 0.0.0.0/0 and a group-to-group reference. Once
those rules are SecurityRule objects, the same hygiene analyser and
reachability engine that run on an NSA 3700 run on a VPC -- no cloud-specific
analysis code.

The interesting part of this builder is what it refuses to say. A security
group is unordered and allow-only, so shadow analysis must not run; its member
instances are runtime state, so the group resolves to its identifier rather
than to a fabricated CIDR; and group-to-group traffic is evaluated at both
ends, which this model does not capture.
"""
import os

import pytest

from ncsa.graph.hygiene import analyse
from ncsa.graph.reach import Query, ask
from ncsa.pipeline import assess

SAMPLE = "samples/aws/describe-security-groups.json"
sample_only = pytest.mark.skipif(not os.path.exists(SAMPLE),
                                 reason="AWS sample absent")

DEFAULT_SG = "sg-0a1b2c3d4e5f60001"
WEB_SG = "sg-0a1b2c3d4e5f60002"
DB_SG = "sg-0a1b2c3d4e5f60003"


@pytest.fixture(scope="module")
def graph():
    return assess(SAMPLE, redact=False, assessment_id="aws-graph").graph


@sample_only
def test_every_rule_in_the_export_reaches_the_graph(graph):
    assert graph is not None, "security_groups must have a graph builder"
    assert len(graph.rules) == 9, [r.name for r in graph.rules]
    assert len(graph.of_kind_zone()) == 3 if hasattr(graph, "of_kind_zone") else True


@sample_only
def test_a_security_group_cannot_deny(graph):
    """There is no deny form. Every rule is an allow, and the union is the policy."""
    assert {r.action for r in graph.rules} == {"allow"}


@sample_only
def test_the_graph_is_marked_unordered_so_shadow_analysis_cannot_run(graph):
    """Position is meaningless in a security group.

    Rules union together; none can shadow another. A "shadowed rule" finding
    here would describe semantics the platform does not have, which is the
    same trap Windows Firewall sets.
    """
    assert graph.unordered is True
    rep = analyse(graph)
    assert "shadowed_rule" not in rep.summary()["by_kind"]
    assert "redundant_rule" not in rep.summary()["by_kind"]
    assert any("does not evaluate rules in order" in u for u in rep.unevaluable), (
        "the suppression must be stated, not silent")


@sample_only
def test_default_deny_is_observed_here_and_only_here(graph):
    """A security group cannot be configured to default-allow.

    Every other builder leaves this unobserved, because a default policy is
    configurable -- `set security policies default-policy permit-all` is real
    Junos. AWS has no such form, so the claim is safe, and it is what turns
    "we cannot say" into DENIED for unmatched traffic.
    """
    assert graph.default_action == "deny"
    assert graph.default_action_observed is True


@sample_only
def test_ssh_open_to_the_internet_is_found(graph):
    """The finding this export exists to demonstrate."""
    a = ask(graph, Query(source="0.0.0.0/0", destination=WEB_SG, port=22,
                         protocol="tcp", destination_zone=WEB_SG))
    assert a.permitted is True
    assert "tcp/22" in a.decided_by


@sample_only
def test_traffic_no_rule_permits_is_denied_not_undecidable(graph):
    """RDP is nowhere in the export, so the default decides it."""
    a = ask(graph, Query(source="0.0.0.0/0", destination=WEB_SG, port=3389,
                         protocol="tcp", destination_zone=WEB_SG))
    assert a.permitted is False
    assert "default" in a.decided_by.lower()


@sample_only
def test_a_database_port_is_not_open_to_the_internet(graph):
    """5432 is permitted only from a GROUP reference, never from a CIDR.

    If the group reference were mis-read as "any", this would come back
    permitted -- reporting a correctly-segmented database as internet-facing.
    """
    a = ask(graph, Query(source="0.0.0.0/0", destination=DB_SG, port=5432,
                         protocol="tcp", destination_zone=DB_SG))
    assert a.permitted is False


@sample_only
def test_an_ingress_rule_does_not_read_as_an_outbound_exposure(graph):
    """Direction decides which side the remote address sits on.

    Writing both directions the same way makes "this database may call out to
    443" look like "the internet may reach this database".
    """
    ingress = [r for r in graph.rules if "ingress" in r.name]
    egress = [r for r in graph.rules if "egress" in r.name]
    assert ingress and egress
    for r in ingress:
        assert r.destination_zones and not r.source_zones
    for r in egress:
        assert r.source_zones and not r.destination_zones


@sample_only
def test_a_group_reference_is_not_an_empty_set(graph):
    """Its members are runtime state, and the graph must say so.

    An empty group would read as "matches nothing" and silently turn a live
    database path into a clean result.
    """
    rule = next(r for r in graph.rules if "5432" in r.name)
    assert WEB_SG in rule.source, "the group reference must survive as a name"
    node = graph.lookup(WEB_SG)
    assert node is not None, "a referenced group must exist as a node"


@sample_only
def test_a_group_resolves_to_its_identifier_not_a_fabricated_cidr(graph):
    """We do not know which addresses are in a group, and must not invent one."""
    node = graph.lookup(WEB_SG)
    assert node.values == [WEB_SG]
    assert node.attrs.get("value_is_identifier") is True


@sample_only
def test_all_protocols_does_not_become_a_port_range(graph):
    """`IpProtocol: "-1"` carries no ports because it means everything.

    Rendering a range there would invent a bound the rule does not have.
    """
    rule = next(r for r in graph.rules if r.id.startswith(DEFAULT_SG))
    assert rule.services == ["any"]


@sample_only
def test_hit_counts_are_absent_rather_than_zero(graph):
    """describe-security-groups carries no counters.

    Zero would make every rule look dead and turn the VPC into deletion
    candidates.
    """
    assert all(r.hit_count is None for r in graph.rules)


@sample_only
def test_the_wide_open_default_group_is_reported(graph):
    rep = analyse(graph)
    kinds = rep.summary()["by_kind"]
    assert kinds.get("overly_permissive", 0) >= 2
    names = " ".join(f.rule for f in rep.findings)
    assert "default" in names, "the default group's any/any rules must be flagged"
