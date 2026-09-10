"""Host firewalls: Windows Firewall and iptables.

The capability `firewall_audit` has and NCSA did not. It costs almost nothing
architecturally -- once host rules become SecurityRule objects, hygiene,
reachability and the controls all apply unchanged. That is the payoff of a
vendor-neutral model, and these tests pin the places where host semantics
DIFFER from an appliance and must not be papered over.
"""
import platform

import pytest

from ncsa.graph.hostfw_builder import _norm, _services, build
from ncsa.graph.hygiene import analyse
from ncsa.graph.reach import Query, ask
from ncsa.readers.hostfw import HostFirewall, parse_iptables

windows_only = pytest.mark.skipif(platform.system() != "Windows",
                                  reason="Windows Firewall not present")

IPTABLES = """
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -i lo -j ACCEPT
-A INPUT -p tcp --dport 22 -s 10.0.0.0/8 -j ACCEPT
-A INPUT -p tcp --dport 23 -j DROP
-A OUTPUT -p tcp --dport 443 -j ACCEPT
COMMIT
"""


# ------------------------------------------------------------ service model
def test_a_bare_protocol_is_not_a_resolvable_service():
    """`udp` alone left 402 of 703 real rules unevaluable: the resolver had no
    object by that name. "UDP, any port" is the full range."""
    assert _services("UDP", "Any") == ["udp/1-65535"]
    assert _services("TCP", "3389") == ["tcp/3389"]
    assert _services("Any", "Any") == ["any"]


def test_non_port_protocols_are_named_not_faked():
    """ICMP types and GRE are real but not port-addressable."""
    assert _services("GRE", "Any") == ["proto:gre"]


def test_windows_any_becomes_the_graph_word_any():
    assert _norm("Any") == ["any"] == _norm("")
    assert _norm("10.0.0.1, 10.0.0.2") == ["10.0.0.1", "10.0.0.2"]


# --------------------------------------------------------------- semantics
def test_host_graph_is_marked_unordered():
    """Windows Firewall matches by precedence, not top-to-bottom."""
    fw = HostFirewall(source_file="t", collected_at="t",
                      rules=[{"name": "a", "action": "Allow", "enabled": "True",
                              "direction": "Inbound", "protocol": "TCP",
                              "localPort": "80", "profile": "Public"}],
                      profiles=[])
    assert build(fw).unordered is True


def test_shadow_analysis_does_not_run_on_an_unordered_platform():
    """A 'shadowed rule' finding there describes semantics the device does not
    have -- it would be invented by our assumption, not read from the policy."""
    fw = HostFirewall(
        source_file="t", collected_at="t", profiles=[],
        rules=[{"name": "wide", "action": "Allow", "enabled": "True",
                "direction": "Inbound", "protocol": "Any", "localPort": "Any",
                "remoteAddress": "Any", "localAddress": "Any",
                "profile": "Public"},
               {"name": "narrow", "action": "Block", "enabled": "True",
                "direction": "Inbound", "protocol": "TCP", "localPort": "3389",
                "remoteAddress": "Any", "localAddress": "Any",
                "profile": "Public"}])
    rep = analyse(build(fw))
    assert not rep.by_kind("shadowed_rule")
    assert any("does not evaluate rules in order" in u for u in rep.unevaluable)


def test_inbound_and_outbound_put_remote_on_the_right_side():
    """Getting this backwards makes every outbound rule look like inbound
    exposure."""
    fw = HostFirewall(
        source_file="t", collected_at="t", profiles=[],
        rules=[{"name": "in", "action": "Allow", "enabled": "True",
                "direction": "Inbound", "protocol": "TCP", "localPort": "80",
                "remoteAddress": "1.2.3.4", "localAddress": "10.0.0.1",
                "profile": "Public"},
               {"name": "out", "action": "Allow", "enabled": "True",
                "direction": "Outbound", "protocol": "TCP", "remotePort": "443",
                "remoteAddress": "8.8.8.8", "localAddress": "10.0.0.1",
                "profile": "Public"}])
    g = build(fw)
    inb = [r for r in g.rules if r.id == "in"][0]
    out = [r for r in g.rules if r.id == "out"][0]
    assert inb.source == ["1.2.3.4"] and inb.destination == ["10.0.0.1"]
    assert out.source == ["10.0.0.1"] and out.destination == ["8.8.8.8"]


def test_a_program_scoped_rule_cannot_answer_a_port_question():
    """Modelling a program rule as any/any made every port on a laptop report
    PERMITTED, decided by a printer utility."""
    fw = HostFirewall(
        source_file="t", collected_at="t", profiles=[],
        rules=[{"name": "app", "display": "HP Smart", "action": "Allow",
                "enabled": "True", "direction": "Inbound", "protocol": "Any",
                "localPort": "Any", "remoteAddress": "Any",
                "localAddress": "Any", "profile": "Public",
                "program": r"C:\hp\smart.exe"}])
    a = ask(build(fw), Query(destination="any", port=3389, source_zone="Public"))
    assert a.permitted is None
    assert any("scoped to a program" in s for s in a.skipped)


def test_notconfigured_default_is_not_assumed_to_be_block():
    """Windows blocks inbound by default, but asserting that from data which
    says NotConfigured would be claiming something we did not read."""
    fw = HostFirewall(source_file="t", collected_at="t", rules=[],
                      profiles=[{"name": "Public", "inbound": "NotConfigured",
                                 "outbound": "NotConfigured"}])
    assert build(fw).default_action_observed is False


def test_an_explicit_block_default_is_observed():
    fw = HostFirewall(source_file="t", collected_at="t", rules=[],
                      profiles=[{"name": "Public", "inbound": "Block",
                                 "outbound": "Allow"}])
    g = build(fw)
    assert g.default_action_observed and g.default_action == "deny"


def test_public_profile_is_the_untrusted_zone():
    fw = HostFirewall(source_file="t", collected_at="t", rules=[],
                      profiles=[{"name": "Public", "inbound": "Block"},
                                {"name": "Domain", "inbound": "Block"}])
    assert build(fw).untrusted_zones == {"Public"}


# ---------------------------------------------------------------- iptables
def test_iptables_rules_and_chain_policies_are_read():
    fw = parse_iptables(IPTABLES)
    assert len(fw.rules) == 4
    assert {p["name"] for p in fw.profiles} == {"INPUT", "FORWARD", "OUTPUT"}
    ssh = [r for r in fw.rules if r["localPort"] == "22"][0]
    assert ssh["remoteAddress"] == "10.0.0.0/8" and ssh["action"] == "Accept"


def test_iptables_evidence_carries_the_original_line():
    fw = parse_iptables(IPTABLES)
    g = build(fw)
    r = [x for x in g.rules if "22" in str(x.services)][0]
    assert r.evidence and "--dport 22" in r.evidence[0].raw


# ------------------------------------------------------------- live machine
@windows_only
def test_this_machine_can_be_assessed():
    from ncsa.readers.hostfw import collect
    fw = collect()
    assert fw.rules, "no firewall rules read"
    g = build(fw)
    assert len(g.rules) == len(fw.rules)
    assert g.unordered


@windows_only
def test_evidence_has_no_fake_line_numbers():
    """A live configuration has no file, so most records have no line. `None`
    rather than 0, so a placeholder cannot masquerade as a real position."""
    from ncsa.readers.hostfw import collect
    g = build(collect())
    for r in g.rules[:50]:
        for e in r.evidence:
            assert e.line is None or e.line >= 1
