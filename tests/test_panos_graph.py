"""PAN-OS object graph, validated against a REAL running-config export.

This is the strongest evidence any builder in the project has. The fixture is
a genuine PAN-OS export, not something written alongside the builder, and it
found two real bugs the moment it was used:

  * the XML reader mangled every entry name containing a slash, so
    entry[ethernet1/1] parsed as two path segments;
  * the resolver did not recognise an inline IP RANGE as a literal, so a rule
    carrying "10.0.0.0-10.255.255.255" straight in its member list was
    reported as referencing a missing object and became unevaluable.

Neither was reachable from a constructed fixture, because a fixture written
next to the code agrees with the code by construction.
"""
import os

import pytest

from ncsa.graph.hygiene import analyse
from ncsa.graph.model import NodeKind
from ncsa.graph.panos_builder import build
from ncsa.graph.reach import Query, ask
from ncsa.readers.xml_reader import load

FIX = os.path.join(os.path.dirname(__file__), "fixtures",
                   "panos_running_config.xml")


@pytest.fixture(scope="module")
def graph():
    return build(load(FIX))


def test_only_the_security_rulebase_becomes_policy(graph):
    """nat, pbf, qos and captive-portal rules are not security policy.

    They live at sibling paths under the same rulebase element. Counting a NAT
    rule as a security rule would report address translation as permitted
    traffic, and this config contains all four kinds.
    """
    names = [r.name for r in graph.rules]
    assert len(graph.rules) == 4, names
    assert all("secrule" in n for n in names), names
    assert not any("pbf" in n or "qos" in n or "cprule" in n for n in names)


def test_rules_are_ordered_as_the_device_evaluates_them(graph):
    assert [r.order for r in graph.rules] == [1, 2, 3, 4]
    assert graph.rules[0].name.startswith("secrule1")


def test_an_absent_disabled_flag_means_enabled(graph):
    """The opposite of SonicOS, where an absent flag means off.

    Carrying the SonicOS assumption here would disable a live rulebase and
    report a permissive firewall as harmless -- the most dangerous direction
    for this error to run.
    """
    by_name = {r.name.split(" [")[0]: r for r in graph.rules}
    assert by_name["secrule1"].enabled is True     # no <disabled> element
    assert by_name["secrule5"].enabled is False    # <disabled>yes</disabled>


def test_every_member_of_a_group_is_read_not_just_the_first(graph):
    """PAN-OS writes list membership as repeated sibling elements.

    Reading only the first would shrink a group, and every rule using it,
    without saying so.
    """
    grp = graph.lookup("my address group")
    assert grp.kind is NodeKind.ADDRESS_GROUP
    assert set(grp.members) == {"client-2-address", "server-4-address"}


def test_a_comma_separated_port_list_becomes_separate_services(graph):
    """The real config carries "389,646" in one element."""
    assert set(graph.lookup("ldap service").values) == {"tcp/389", "tcp/646"}


def test_source_port_is_not_folded_into_the_destination_service(graph):
    """TCP-55 has port 55 and source-port 23.

    Reading the source port as a service would answer a destination-port
    question with the client's port number.
    """
    assert graph.lookup("TCP-55").values == ["tcp/55"]


def test_an_app_constrained_rule_cannot_decide_a_port_question(graph):
    """App-ID, not the port, is the primary match criterion on PAN-OS.

    secrule2 permits application 4shared on application-default ports. Which
    ports those are is decided by Palo Alto's application database, which we
    do not hold. Reporting it as permitting a port outright would drop the
    constraint doing the actual security work.
    """
    rule = next(r for r in graph.rules if r.name.startswith("secrule2"))
    assert rule.program, "must be marked undecidable for port questions"
    assert "app-id:4shared" in rule.program
    assert "application-default" in rule.program


def test_a_rule_with_no_application_constraint_is_fully_evaluable(graph):
    rule = next(r for r in graph.rules if r.name.startswith("secrule4"))
    assert rule.program is None


def test_predefined_services_are_supplied_with_their_provenance(graph):
    """service-http is referenced by a rule but never written to the config.

    Left unresolved it would make the rule unevaluable. Supplied silently it
    would look like something we read off the device. It is supplied AND
    labelled.
    """
    node = graph.lookup("service-http")
    assert node is not None, "referenced by secrule1 and must resolve"
    assert node.values == ["tcp/80", "tcp/8080"]
    assert node.attrs["predefined"] is True
    assert "not read from this configuration" in node.attrs["provenance"]


def test_the_implicit_default_is_recorded_as_assumed_not_observed(graph):
    """Every PAN-OS firewall ends with an implicit interzone deny.

    We know it from the platform, not from this file, and the flag has to say
    which -- otherwise an assumption is indistinguishable from a reading.
    """
    assert graph.default_action == "deny"
    assert graph.default_action_observed is False


def test_zone_to_interface_mapping_survives_the_slash_in_the_name(graph):
    """entry[ethernet1/1] is escaped as ethernet1%2F1 in the path.

    Unescaping is not cosmetic: rule members and interface lists carry the raw
    name, so a mismatch here silently breaks every zone lookup.
    """
    assert graph.zones_of_interface == {"ethernet1/1": "external"}
    assert "external" in graph.untrusted_zones


def test_an_inline_ip_range_is_a_literal_not_a_missing_object(graph):
    """secrule1 carries "10.0.0.0-10.255.255.255" directly in its member list.

    Treating it as the name of an absent object made the rule unevaluable and
    put a caveat on every answer below it.
    """
    a = ask(graph, Query(source="10.5.5.5", destination="1.1.1.1",
                         port=55, protocol="tcp"))
    assert a.permitted is True
    assert a.decided_by.startswith("secrule1")


def test_a_named_object_resolves_through_a_service_group(graph):
    a = ask(graph, Query(source="3.6.6.7", destination="1.1.1.1",
                         port=389, protocol="tcp"))
    assert a.permitted is True


def test_hygiene_runs_and_flags_the_disabled_rule(graph):
    rep = analyse(graph)
    kinds = {f.kind for f in rep.findings}
    assert "disabled_rule" in kinds


def test_the_app_constrained_rule_is_disclosed_as_unevaluable(graph):
    """It must appear in the caveat rather than being silently skipped."""
    a = ask(graph, Query(source="any", destination="any", port=3389,
                         protocol="tcp"))
    assert a.skipped, "an unevaluable rule above the match must be disclosed"
    assert "caveat" in a.explain()
