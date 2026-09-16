"""What-if remediation, on the real NSA 3700.

The two properties that matter most are the least visible:

  1. An EMPTY simulation reproduces the stored assessment exactly. If it did
     not, every "after" figure would include an artefact of re-scoring, and
     the delta shown to a user would be partly fiction.
  2. The stored assessment is untouched afterwards. A simulation that leaked
     into the real result would silently rewrite a report.

Then the behaviour: fixes move the score, disabling rule 217 closes the
WLAN -> DMZ paths, and requests that cannot be simulated honestly are refused
with a reason rather than approximated.
"""
import os

import pytest

from ncsa.engine.rules import load_rules
from ncsa.pipeline import assess
from ncsa.whatif import simulate

SW = r"E:\sonicwall config file.txt"
sw_only = pytest.mark.skipif(not os.path.exists(SW), reason="SonicWall sample absent")

WLAN_DMZ = "Default Access Rule [IPv4#217]"
WLAN_WAN = "Default Access Rule [IPv4#216]"


@pytest.fixture(scope="module")
def da():
    return assess(SW, redact=False, assessment_id="TEST-WHATIF")


def _simple_fail(da):
    """A FAIL on a scalar setting with an `equals` control -- a clean fix."""
    rules = {c.id: c for c in load_rules("rules", platform=da.identity.platform)}
    for f in da.assessment.findings:
        c = rules.get(f.control_id)
        if (f.state.value == "FAIL" and c is not None and c.operator == "equals"
                and not c.field.startswith(("exposure.", "firewall."))):
            return f
    pytest.skip("no simple equals-FAIL on this device")


@sw_only
def test_an_empty_simulation_reproduces_the_assessment_exactly(da):
    out = simulate(da)
    assert out["before"] == out["after"]
    assert out["changes"] == []
    assert out["delta"] == {"score_pct": 0.0, "assessed_pct": 0.0}


@sw_only
def test_the_stored_assessment_is_untouched(da):
    cov = dict(da.coverage())
    n_obs = len(da.sbm.observations)
    rules_enabled = [r.enabled for r in da.graph.rules]

    simulate(da, fix_controls=[_simple_fail(da).control_id],
             disable_rules=[WLAN_DMZ])

    assert da.coverage() == cov
    assert (cov["score_pct"], cov["assessed_pct"]) == (36.2, 70.1)
    assert len(da.sbm.observations) == n_obs
    assert [r.enabled for r in da.graph.rules] == rules_enabled


@sw_only
def test_fixing_a_failure_turns_it_to_pass_and_raises_the_score(da):
    f = _simple_fail(da)
    out = simulate(da, fix_controls=[f.control_id])
    assert out["applied"] and out["applied"][0]["control_id"] == f.control_id
    change = next(c for c in out["changes"] if c["control_id"] == f.control_id)
    assert (change["before"], change["after"]) == ("FAIL", "PASS")
    assert change["targeted"] is True
    assert out["delta"]["score_pct"] > 0
    assert out["simulated"] is True and "nothing on the device" in out["label"]


WLAN_DMZ_V6 = "Default Access Rule [IPv6#60]"
WLAN_WAN_V6 = "Default Access Rule [IPv6#59]"


@sw_only
def test_disabling_only_the_ipv4_rules_leaves_the_ipv6_twins_open(da):
    """The trap this device actually contains.

    SonicOS keeps IPv4 and IPv6 policy in separate tables. Rules 216/217 have
    IPv6 twins (59/60) with the same any/any/any allow, so an administrator who
    closes the IPv4 rules has closed nothing -- the same 32 paths stay open
    over IPv6. The simulation must show that, and must say why.
    """
    out = simulate(da, disable_rules=[WLAN_DMZ, WLAN_WAN], origin_zone="WLAN")
    before = out["blast_radius"]["before"]
    after = out["blast_radius"]["after"]
    assert before["paths_open"] > 0
    assert after["paths_open"] == before["paths_open"], (
        "the IPv6 twins still permit the traffic")
    warned = " ".join(out["warnings"])
    assert WLAN_DMZ_V6 in warned and WLAN_WAN_V6 in warned
    assert "same traffic" in warned


@sw_only
def test_disabling_both_address_families_closes_the_wlan_paths(da):
    out = simulate(da, disable_rules=[WLAN_DMZ, WLAN_WAN,
                                      WLAN_DMZ_V6, WLAN_WAN_V6],
                   origin_zone="WLAN")
    before = out["blast_radius"]["before"]
    after = out["blast_radius"]["after"]
    assert before["paths_open"] > 0
    assert after["paths_open"] < before["paths_open"]
    assert after["administrative_paths"] == 0
    assert out["warnings"] == []
    assert {a["rule"] for a in out["applied"]} == {
        WLAN_DMZ, WLAN_WAN, WLAN_DMZ_V6, WLAN_WAN_V6}


@sw_only
def test_an_unknown_control_cannot_be_simulated_into_a_pass(da):
    """UNKNOWN means we could not read it. A simulated PASS would claim we did."""
    unk = next(f for f in da.assessment.findings if f.state.value == "UNKNOWN")
    out = simulate(da, fix_controls=[unk.control_id])
    assert not out["applied"]
    assert "only FAIL and PARTIAL" in out["rejected"][0]["reason"]
    assert out["changes"] == []


@sw_only
def test_a_policy_finding_is_redirected_to_its_rules(da):
    """Overwriting an exposure field would hide the exposure, not fix it."""
    rules = {c.id: c for c in load_rules("rules", platform=da.identity.platform)}
    pol = next((f for f in da.assessment.findings
                if f.state.value in ("FAIL", "PARTIAL")
                and rules[f.control_id].field.startswith(("exposure.", "firewall."))),
               None)
    if pol is None:
        pytest.skip("no policy-derived failure on this device")
    out = simulate(da, fix_controls=[pol.control_id])
    assert not out["applied"]
    r = out["rejected"][0]
    assert "firewall policy" in r["reason"]
    assert "suggest_disable_rules" in r


@sw_only
def test_an_unknown_rule_name_is_refused(da):
    out = simulate(da, disable_rules=["no such rule"])
    assert not out["applied"]
    assert "no rule with this name" in out["rejected"][0]["reason"]


@sw_only
def test_every_result_carries_its_caveats(da):
    out = simulate(da, disable_rules=[WLAN_DMZ])
    joined = " ".join(out["caveats"])
    assert "stops the traffic it permitted" in joined
    assert "still have to produce it on the device" in joined


@sw_only
def test_the_api_endpoint(da):
    from fastapi.testclient import TestClient

    from ncsa.api.app import app

    client = TestClient(app)
    with open(SW, "rb") as fh:
        aid = client.post("/assess?redact=false",
                          files={"files": ("sw.txt", fh)}).json()[0]["assessment_id"]
    body = client.post(f"/assessment/{aid}/what-if",
                       json={"disable_rules": [WLAN_DMZ],
                             "origin_zone": "WLAN"}).json()
    assert body["simulated"] is True
    assert body["blast_radius"]["before"]["latent"] is True
    stored = client.get(f"/assessment/{aid}").json()["coverage"]
    assert (stored["score_pct"], stored["assessed_pct"]) == (36.2, 70.1)
