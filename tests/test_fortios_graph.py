"""FortiOS object graph.

READ THIS BEFORE TRUSTING THIS BUILDER
--------------------------------------
tests/fixtures/fortios_edge.conf is CONSTRUCTED from Fortinet's published CLI
syntax. It is not a captured "show full-configuration" from a real FortiGate.

That makes these tests weaker than test_panos_graph.py, which validates
against a genuine export -- and which found two real bugs precisely because
the config was real. A fixture written alongside its builder agrees with it by
construction: it proves the builder is self-consistent, not that it matches a
real device.

What these tests DO establish is that the FortiOS semantics the builder claims
to handle are actually handled, and that the two dangerous defaults (absent
status, absent action) fall the right way.
"""
import os

import pytest

from ncsa.graph.fortios_builder import build
from ncsa.graph.hygiene import analyse
from ncsa.graph.model import NodeKind
from ncsa.graph.reach import Query, ask
from ncsa.readers.fortinet_block import load

FIX = os.path.join(os.path.dirname(__file__), "fixtures", "fortios_edge.conf")


@pytest.fixture(scope="module")
def graph():
    return build(load(FIX))


def _rule(graph, prefix):
    return next(r for r in graph.rules if r.name.startswith(prefix))


def test_an_absent_status_means_enabled(graph):
    """FortiOS writes "set status disable" only to turn a policy OFF.

    SonicOS is the exact opposite: there an absent enabled flag means off.
    Carrying that assumption across would silently disable a live rulebase and
    report a permissive firewall as harmless.
    """
    assert _rule(graph, "lan-to-wan").enabled is True        # no status line
    assert _rule(graph, "retired-vendor-access").enabled is False


def test_policies_evaluate_in_document_order_not_by_policy_id(graph):
    """policyid identifies a policy; it does not position it.

    FortiOS reorders policies without renumbering, so sorting by id would
    evaluate the rulebase in an order the device does not use.
    """
    assert [r.order for r in graph.rules] == [1, 2, 3, 4, 5, 6]


def test_a_quoted_multi_value_is_split_on_quotes_not_whitespace(graph):
    """"set member "web servers" "db servers"" is two names, not four.

    Splitting on whitespace fabricates two objects and loses both real ones,
    and object names containing spaces are ordinary on a real device.
    """
    grp = graph.lookup("internal-servers")
    assert grp.kind is NodeKind.ADDRESS_GROUP
    assert grp.members == ["web servers", "db servers"]


def test_a_single_quoted_value_is_one_name(graph):
    """The reader strips the quotes when there is exactly one value."""
    assert _rule(graph, "lan-to-wan").source == ["lan-subnet"]


def test_subnet_and_mask_become_a_cidr(graph):
    assert graph.lookup("lan-subnet").values == ["10.10.0.0/24"]
    assert graph.lookup("web servers").values == ["10.20.0.16/28"]


def test_an_iprange_object_keeps_both_ends(graph):
    assert graph.lookup("partner-range").values == \
        ["198.51.100.10-198.51.100.20"]


def test_a_source_port_range_is_not_read_as_the_destination(graph):
    """"set tcp-portrange 1433:1024-65535" is dst 1433, src 1024-65535.

    Folding the source range in would answer a destination-port question with
    the client's port numbers -- and 1024-65535 matches almost everything.
    """
    assert graph.lookup("sql-with-source").values == ["tcp/1433"]


def test_multiple_port_ranges_on_one_line_are_all_read(graph):
    assert set(graph.lookup("app-ports").values) == {"tcp/8000-8100", "tcp/9090"}


def test_a_policy_naming_an_interface_is_scoped_to_the_zone_that_claims_it(graph):
    """srcintf/dstintf accept an interface OR a zone name.

    port2 belongs to zone "trusted"; port1 belongs to no zone and stays
    itself. Inventing a zone for port1 would fabricate a segmentation
    boundary the device does not have.
    """
    assert graph.zones_of_interface == {"port2": "trusted", "port3": "dmz"}
    r = _rule(graph, "lan-to-wan")
    assert r.source_zones == ["trusted"]
    assert r.destination_zones == ["port1"]


def test_the_wan_role_marks_the_untrusted_side(graph):
    """"set role wan" is the device's own statement, not our guess."""
    assert "port1" in graph.untrusted_zones


def test_predefined_services_are_supplied_with_their_provenance(graph):
    """ALL, HTTP and friends are built into FortiOS and never written down.

    ALL is the one that must be supplied: an unresolved service makes a rule
    unevaluable, so a policy permitting every port would be HIDDEN rather than
    reported as over-permissive.
    """
    all_svc = graph.lookup("ALL")
    assert all_svc.values == ["all"]
    assert all_svc.attrs["predefined"] is True
    assert "not read from this configuration" in all_svc.attrs["provenance"]


def test_a_predefined_service_referenced_only_through_a_group_is_supplied(graph):
    """web-services lists HTTP and HTTPS; no rule names them directly.

    Looking only at rules would leave the group's members unresolved and make
    every policy using the group unevaluable.
    """
    assert graph.lookup("web-services").members == ["HTTP", "HTTPS", "TCP-8443"]
    assert graph.lookup("HTTPS").values == ["tcp/443"]


def test_a_negated_policy_is_marked_unevaluable_not_read_literally(graph):
    """"set srcaddr-negate enable" means everything EXCEPT lan-subnet.

    The vendor-neutral rule has no negation, so read literally this policy
    means the precise opposite of what the device does.
    """
    r = _rule(graph, "everything-except-guests")
    assert r.program and "negate-source" in r.program


def test_a_time_limited_policy_is_marked_unevaluable(graph):
    """A policy on a schedule is not in force at an arbitrary moment.

    The configuration does not say when the question is being asked.
    """
    r = _rule(graph, "night-batch-to-db")
    assert r.program and "schedule:after-hours" in r.program


def test_a_permanent_policy_carries_no_such_marker(graph):
    assert _rule(graph, "lan-to-wan").program is None


def test_hit_counts_are_absent_rather_than_zero(graph):
    """FortiOS keeps counters on the device, not in the config file.

    Zero would make every policy look dead and turn a healthy rulebase into
    deletion candidates.
    """
    assert all(r.hit_count is None for r in graph.rules)


def test_the_implicit_default_is_recorded_as_assumed_not_observed(graph):
    assert graph.default_action == "deny"
    assert graph.default_action_observed is False


def test_reachability_permits_what_policy_one_permits(graph):
    a = ask(graph, Query(source="10.10.0.5", destination="8.8.8.8",
                         port=443, protocol="tcp"))
    assert a.permitted is True
    assert a.decided_by.startswith("lan-to-wan")


def test_reachability_resolves_a_service_group_end_to_end(graph):
    """partner -> web servers on 8443, via web-services -> TCP-8443."""
    a = ask(graph, Query(source="198.51.100.15", destination="10.20.0.20",
                         port=8443, protocol="tcp",
                         source_zone="port1", destination_zone="dmz"))
    assert a.permitted is True
    assert a.decided_by.startswith("partners-to-web")


def test_an_unzoned_query_says_the_zone_was_assumed(graph):
    """Every FortiOS policy is interface- or zone-scoped.

    So an unzoned question is decided by whichever scoped policy comes first,
    even one carrying traffic that never crosses that boundary. The verdict is
    still returned, but the assumption is stated rather than hidden.
    """
    a = ask(graph, Query(source="198.51.100.15", destination="10.20.0.20",
                         port=8443, protocol="tcp"))
    assert a.zone_assumed is True
    assert "assumed to apply" in a.explain()


def test_a_zoned_query_carries_no_such_caveat(graph):
    a = ask(graph, Query(source="198.51.100.15", destination="10.20.0.20",
                         port=8443, protocol="tcp",
                         source_zone="port1", destination_zone="dmz"))
    assert a.zone_assumed is False
    assert "assumed to apply" not in a.explain()


def test_interfaces_are_not_reported_as_orphaned_objects(graph):
    """An interface exists whether or not a policy names it.

    Reporting one as a dead object confuses a topology fact with the
    unreferenced-address-object cleanup this finding is about.
    """
    rep = analyse(graph)
    orphan_findings = [f for f in rep.findings if f.kind == "orphaned_objects"]
    for f in orphan_findings:
        assert "port1" not in f.detail
        assert "port2" not in f.detail


def test_hygiene_flags_the_wide_open_policy(graph):
    rep = analyse(graph)
    assert "overly_permissive" in {f.kind for f in rep.findings}


def test_builder_is_marked_unvalidated_against_real_output():
    """Deliberate tripwire.

    Removing this caveat should require having actually checked the builder
    against a captured FortiGate configuration, the way the PAN-OS builder was
    checked against a genuine export.
    """
    import ncsa.graph.fortios_builder as mod
    assert "CONSTRUCTED FIXTURE, NOT CAPTURED DEVICE OUTPUT" in mod.__doc__
