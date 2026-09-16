"""Blast radius -- what an attacker reaches from a foothold.

Validated against the real NSA 3700, where it finds something genuine: the
wireless zone has an any/any/any allow into the DMZ, so a device on the guest
Wi-Fi can reach SSH, Telnet, RDP, SMB, RPC and SNMP on the DMZ. That is not a
fixture and not a contrived example -- it is rule 217 of a production policy.

THE FAILURE DIRECTION THAT MATTERS
----------------------------------
Every other analysis in this project errs toward reporting less certainty. A
blast radius must err the same way, and the asymmetry is sharper here: a radius
that omits what it could not evaluate reads as a SMALLER radius, which is
precisely the reassurance an attacker would want the defender to have.

So the invariants are:
  * a path resting on an unevaluable rule is reported, marked uncertain;
  * a probe that could not be decided is counted and located by zone, never
    silently treated as blocked;
  * "reachable" is never worded as "exploitable".
"""
import os

import pytest

from ncsa.pipeline import assess
from ncsa.topology.blast import (ADMIN_PORTS, LATERAL_PORTS, BlastRadius,
                                 Step, blast_radius)

SW = r"E:\sonicwall config file.txt"
sw_only = pytest.mark.skipif(not os.path.exists(SW), reason="SonicWall sample absent")


@pytest.fixture(scope="module")
def graph():
    return assess(SW, redact=False, assessment_id="TEST-BLAST").graph


# --------------------------------------------------------- the real finding

@sw_only
def test_the_wireless_zone_reaches_the_dmz_on_this_device(graph):
    """Rule 217 is `WLAN -> DMZ, any/any/any, allow`.

    Verified against the configuration: source any, destination any, service
    any, enabled. If this assertion ever fails, either the device changed or
    the policy walk did -- and both are worth stopping for.
    """
    radius = blast_radius(graph, origin_zone="WLAN")
    dmz = [s for s in radius.reachable if s.to_zone == "DMZ"]
    assert dmz, "the WLAN->DMZ any/any allow must produce reachable paths"

    admin = [s for s in dmz if s.administrative]
    assert admin, "administrative access from wireless into the DMZ is the finding"
    assert any(s.port == 22 for s in admin), "SSH must be among them"

    # The rule that permits it has to be named, or the finding is unactionable.
    assert all(s.decided_by for s in dmz)


@sw_only
def test_the_origin_zone_is_not_reported_as_its_own_blast_radius(graph):
    """Reaching where you already are is not lateral movement."""
    radius = blast_radius(graph, origin_zone="WLAN")
    assert "WLAN" not in radius.zones_considered
    assert all(s.to_zone != "WLAN" for s in radius.reachable)


@sw_only
def test_administrative_paths_are_separated_from_the_rest(graph):
    """An operator triages admin access first.

    Reaching a database matters; reaching SSH means the attacker can become
    the administrator, which is how a foothold becomes control.
    """
    radius = blast_radius(graph, origin_zone="WLAN")
    assert radius.administrative_paths
    for step in radius.administrative_paths:
        assert step.port in ADMIN_PORTS


# ------------------------------------------------------- honesty invariants

@sw_only
def test_undecidable_probes_are_counted_not_silently_blocked(graph):
    """The dangerous direction.

    SonicOS does not state its default policy in the export, so a probe no
    rule matched cannot be decided. Treating those as blocked would shrink the
    reported radius on exactly the zones we know least about.
    """
    radius = blast_radius(graph, origin_zone="WLAN")
    assert radius.undecidable > 0, "expected undecidable probes on this device"

    total = radius.undecidable + radius.blocked + len(radius.reachable)
    expected = len(radius.zones_considered) * len(LATERAL_PORTS)
    assert total == expected, (
        f"probes are being lost: {total} accounted for of {expected} run")


@sw_only
def test_undecidable_probes_are_located_by_zone(graph):
    """A bare total is not actionable.

    "48 undecidable" tells an operator nothing. "Every probe into MGMT was
    undecidable" tells them the policy is unreadable on the zone they would
    most want certainty about.
    """
    radius = blast_radius(graph, origin_zone="WLAN")
    summary = radius.summary()
    assert summary["undecidable_by_zone"], "undecidable must be attributed"
    assert sum(summary["undecidable_by_zone"].values()) == radius.undecidable

    fully = summary["zones_fully_undecidable"]
    assert fully, "expected at least one wholly unreadable zone on this device"
    for zone in fully:
        assert summary["undecidable_by_zone"][zone] == len(LATERAL_PORTS)


@sw_only
def test_the_explanation_states_that_unproven_is_not_absent(graph):
    """Wording is the control here.

    An operator reading "48 undecidable" may assume blocked. The sentence has
    to say otherwise.
    """
    text = blast_radius(graph, origin_zone="WLAN").explain()
    assert "UNPROVEN, not" in text and "absent" in text


@sw_only
def test_reachable_is_never_stated_as_exploitable(graph):
    """Policy permitting a packet is not a vulnerability.

    Claiming otherwise would be the same overreach the compliance side
    refuses: asserting more than the evidence supports.
    """
    text = blast_radius(graph, origin_zone="WLAN").explain()
    assert "reachable is not exploitable" in text.lower()
    assert "listening" in text, "say what reachability does not establish"


def test_a_path_resting_on_an_unevaluable_rule_is_marked_uncertain():
    """A radius that drops what it could not evaluate reads smaller than it is."""
    step = Step(to_zone="DMZ", port=22, protocol="tcp", service="SSH",
                permitted=True, decided_by="rule-1", reason="", uncertain=True)
    radius = BlastRadius(origin="WLAN", origin_address="any",
                         reachable=[step], zones_considered=["DMZ"])
    assert radius.summary()["uncertain_paths"] == 1
    assert "[UNCERTAIN]" in radius.explain()
    assert "may be larger" in radius.explain()


def test_a_policy_with_no_other_zones_says_so_rather_than_returning_empty():
    """An empty result and "nothing to analyse" look identical otherwise."""
    from ncsa.graph.model import ObjectGraph

    radius = blast_radius(ObjectGraph(), origin_zone="WLAN")
    assert radius.reachable == []
    assert radius.notes, "an empty radius must explain itself"
    assert "nothing to move laterally into" in radius.notes[0]


# ----------------------------------------------------------- the probe set

def test_the_probe_set_leads_with_administrative_access():
    """Asking "can anything reach anything" returns a wall of true.

    The port list is chosen so a hit is a sentence someone can act on.
    """
    assert len(LATERAL_PORTS) >= 12
    ports = [p for p, _proto, _svc in LATERAL_PORTS]
    assert 22 in ports and 3389 in ports and 445 in ports
    assert 3306 in ports and 5432 in ports, "data stores matter too"
    for port, proto, service in LATERAL_PORTS:
        assert proto in ("tcp", "udp")
        assert service, f"port {port} has no explanation for a reader"


@sw_only
def test_an_empty_origin_zone_makes_every_path_latent(graph):
    """The NSA 3700 has no access point and no interface in WLAN.

    Rule 217 still permits WLAN -> DMZ, so the paths are real POLICY -- but
    nothing sits in the zone to use them. Presenting them as live would
    overstate the risk on this device; omitting them would hide a rule that
    activates the moment an access point is plugged in. LATENT says both.
    """
    radius = blast_radius(graph, origin_zone="WLAN", origin_members=[])
    assert radius.reachable, "the policy paths themselves must still be shown"
    assert radius.latent
    assert radius.summary()["origin_populated"] is False
    text = radius.explain()
    assert "LATENT" in text and "go live" in text
    assert any("latent" in n for n in radius.notes)


@sw_only
def test_unknown_population_is_not_reported_as_empty(graph):
    """"Could not tell" must never read as "nothing there"."""
    radius = blast_radius(graph, origin_zone="WLAN")
    assert radius.origin_members is None
    assert not radius.latent
    assert radius.summary()["origin_populated"] is None
    assert "LATENT" not in radius.explain()


@sw_only
def test_a_populated_origin_is_reported_live(graph):
    radius = blast_radius(graph, origin_zone="WLAN",
                          origin_members=["interface X9"])
    assert not radius.latent
    assert "LIVE" in radius.explain()


@sw_only
def test_the_api_reports_wlan_as_latent_on_this_device():
    """End to end: the endpoint derives the population from the device."""
    from fastapi.testclient import TestClient

    from ncsa.api.app import app

    client = TestClient(app)
    with open(SW, "rb") as fh:
        aid = client.post("/assess?redact=false",
                          files={"files": ("sw.txt", fh)}).json()[0]["assessment_id"]
    body = client.post(f"/assessment/{aid}/blast-radius?origin_zone=WLAN").json()
    assert body["summary"]["latent"] is True
    assert body["summary"]["origin_populated"] is False

    # LAN has interfaces, so it must not be marked latent.
    lan = client.post(f"/assessment/{aid}/blast-radius?origin_zone=LAN").json()
    assert lan["summary"]["origin_populated"] is True
    assert lan["summary"]["latent"] is False


@sw_only
def test_multi_device_results_are_not_chained_across_inferred_links(graph):
    """Adjacency is inferred from shared subnets.

    Chaining a path across an inferred link would present a guess as a route.
    Per-device results are reported separately, and the caveat travels with
    them.
    """
    from ncsa.topology.blast import fabric_blast_radius
    from ncsa.topology.fabric import Fabric

    da = assess(SW, redact=False, assessment_id="TEST-FABRIC")
    fabric = Fabric()
    fabric.add(da)

    out = fabric_blast_radius(fabric, origin_zone="WLAN")
    assert out["devices"], "expected at least one device walked"
    assert "INFERRED" in out["caveat"]
    assert "guess" in out["caveat"]
