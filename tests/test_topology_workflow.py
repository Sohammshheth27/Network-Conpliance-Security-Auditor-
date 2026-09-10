"""Multi-device topology, recertification, and log correlation.

The last three capabilities the comparable products had and NCSA did not.
Each is scoped honestly rather than claimed: what these do NOT do is asserted
in tests, because the gap to Batfish is real and a tool that hides it is worse
than one that names it.
"""
import os
from datetime import date, datetime, timedelta

import pytest

from ncsa.graph.model import ObjectGraph, SecurityRule
from ncsa.logs import corroborate, parse, parse_line
from ncsa.pipeline import assess
from ncsa.topology import Fabric, Interface
from ncsa.topology.interfaces import from_indented
from ncsa.workflow import Register, deletion_candidates, review

SW = r"E:\sonicwall config file.txt"
ASA = r"E:\ASA.txt"
have = pytest.mark.skipif(not (os.path.exists(SW) and os.path.exists(ASA)),
                          reason="real samples absent")


# --------------------------------------------------------------- interfaces
def test_interface_network_is_computed_from_address_and_mask():
    i = Interface(name="X0", address="10.0.5.1", netmask="255.255.255.0")
    assert str(i.network) == "10.0.5.0/24"


def test_an_interface_without_an_address_has_no_network():
    assert Interface(name="X9").network is None


class _Doc:
    def __init__(self, text):
        self.lines = text.splitlines()
        self.redacted = False


def test_indented_extractor_reads_address_zone_and_shutdown():
    d = _Doc("interface GigabitEthernet1/1\n nameif inside\n"
             " ip address 192.168.5.12 255.255.255.0\n"
             "interface GigabitEthernet1/2\n shutdown\n no ip address\n")
    ifs = from_indented(d)
    assert len(ifs) == 1                       # the shutdown one has no address
    assert ifs[0].zone == "inside"
    assert str(ifs[0].network) == "192.168.5.0/24"


@pytest.mark.skipif(not os.path.exists(SW), reason="sample absent")
def test_redaction_makes_topology_impossible_and_says_so():
    """Redaction replaces octets with `x`, so an interface address becomes
    unparseable. This returned an empty list, and a device with ten live
    interfaces looked like a device with none."""
    from ncsa.topology.interfaces import RedactedAddressing, extract
    redacted = assess(SW, redact=True)
    with pytest.raises(RedactedAddressing):
        extract(redacted, strict=True)
    assert extract(assess(SW, redact=False))   # ...and works unredacted


# ----------------------------------------------------------------- topology
@have
def test_fabric_infers_a_link_from_a_shared_subnet():
    fab = Fabric()
    fab.add(assess(SW, redact=False))
    fab.add(assess(ASA))
    links = fab.adjacency()
    assert links, "two devices on 192.168.5.0/24 should be linked"
    assert all(l["inferred_from"] == "shared subnet" for l in links)


@have
def test_a_device_with_no_policy_graph_makes_the_path_undecidable():
    """Never 'permitted'. A device we could not model is not a device that
    permits everything."""
    fab = Fabric()
    fab.add(assess(SW, redact=False))
    fab.add(assess(ASA))
    a = fab.can_reach("192.168.5.99", "10.90.213.5", 22)
    assert a.permitted is None
    assert any("no policy graph" in c for c in a.caveats)


def test_no_device_facing_the_traffic_is_not_the_same_as_blocked():
    """The single most dangerous answer a topology tool can give."""
    fab = Fabric()
    a = fab.can_reach("203.0.113.1", "198.51.100.1", 443)
    assert a.permitted is None
    assert "NOT the same as the traffic being blocked" in a.reason


def test_every_path_answer_states_its_inference_limits():
    fab = Fabric()
    a = fab.can_reach("10.0.0.1", "10.0.0.2", 80)
    assert any("routing and NAT are not modelled" in c for c in a.caveats)


# ---------------------------------------------------------- recertification
def _graph_with(n, hits=0):
    g = ObjectGraph()
    for i in range(n):
        g.add_rule(SecurityRule(id=f"r{i}", name=f"rule{i}", order=i,
                                action="allow", hit_count=hits))
    return g


class _DA:
    def __init__(self, graph, host="fw1"):
        from ncsa.pipeline import DeviceIdentity
        self.identity = DeviceIdentity(hostname=host)
        self.graph = graph


def test_a_certification_requires_an_owner():
    """A certification with no owner is a rubber stamp that answers nobody's
    question when the rule is queried two years later."""
    reg = Register(path=None)
    with pytest.raises(ValueError):
        reg.certify("fw1", "r0", owner="")


def test_an_uncertified_rule_is_reported():
    f = review(_DA(_graph_with(2, hits=5)), Register(path=None))
    assert {x.kind for x in f} == {"unowned"}


def test_unused_and_unowned_ranks_above_merely_unowned():
    from ncsa.graph.hygiene import analyse
    da = _DA(_graph_with(2, hits=0))
    f = review(da, Register(path=None), hygiene=analyse(da.graph))
    assert all(x.kind == "stale_and_unowned" for x in f)
    assert all(x.severity == "high" for x in f)


def test_an_expired_certification_is_high_severity():
    reg = Register(path=None)
    reg.certify("fw1", "r0", owner="sohamm", period_days=30,
                when=date.today() - timedelta(days=90))
    f = [x for x in review(_DA(_graph_with(1, hits=5)), reg)
         if x.rule_id == "r0"]
    assert f and f[0].kind == "expired" and f[0].owner == "sohamm"


def test_recertifying_replaces_rather_than_duplicates():
    reg = Register(path=None)
    reg.certify("fw1", "r0", owner="a")
    reg.certify("fw1", "r0", owner="b")
    assert len(reg.entries) == 1 and reg.for_rule("fw1", "r0").owner == "b"


def test_deletion_needs_at_least_two_independent_signals():
    """Any one signal alone is a bad reason to delete a firewall rule."""
    from ncsa.graph.hygiene import analyse
    da = _DA(_graph_with(3, hits=0))
    cands = deletion_candidates(da, analyse(da.graph), Register(path=None))
    assert cands
    assert all(len(c["signals"]) >= 2 for c in cands)
    assert all("not automatic removal" in c["note"] for c in cands)


# ------------------------------------------------------------ log correlation
def test_key_value_syslog_is_parsed():
    ev = parse_line("Sep  1 10:00:01 fw action=allow rule=policy_13 "
                    "src=10.0.0.1 dst=8.8.8.8 dstport=443 proto=tcp", year=2026)
    assert ev.rule_id == "policy_13" and ev.action == "allow"
    assert ev.dst == "8.8.8.8" and ev.port == "443"


def test_unparsed_lines_are_counted_not_discarded():
    s = parse(["complete gibberish with no fields", ""], year=2026)
    assert s.events == 0 and s.unparsed == 1


def test_logs_can_refute_a_zero_counter():
    """A counter reset makes a busy rule look dead. Logs carry timestamps, so
    they decide what the counter cannot."""
    g = ObjectGraph()
    g.add_rule(SecurityRule(id="r1", name="r1", order=1, action="allow",
                            hit_count=0))
    s = parse(["Sep  1 10:00:01 fw action=allow rule=r1 src=1.1.1.1 "
               "dst=2.2.2.2 dstport=443"], year=2026)
    c = corroborate(g, s)[0]
    assert c.verdict == "counter_was_reset"
    assert "would have been wrong" in c.detail


def test_traffic_with_no_log_entries_is_itself_a_finding():
    """An unlogged permit is a gap in the audit trail several frameworks
    require -- so the absence of logs is not treated as the absence of a
    problem."""
    g = ObjectGraph()
    g.add_rule(SecurityRule(id="r1", name="r1", order=1, action="allow",
                            hit_count=99999))
    c = corroborate(g, parse([], year=2026))[0]
    assert c.verdict == "unlogged"


def test_two_sources_agreeing_promotes_a_caveat_to_a_conclusion():
    g = ObjectGraph()
    g.add_rule(SecurityRule(id="r1", name="r1", order=1, action="allow",
                            hit_count=0))
    c = corroborate(g, parse([], year=2026))[0]
    assert c.verdict == "confirmed_unused"
