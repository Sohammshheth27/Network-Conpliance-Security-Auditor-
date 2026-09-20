"""A mapping that matches nothing must not produce a verdict.

On a source that lists every setting it has, a key matching no record is a key
WE named wrongly. Ruling on it either way asserts a fact from silence:

  NCSA-EXT-039  security.ips.enabled   <- uuidIpsObjEnable  (0 records)
      FAILED, claiming IPS is off on a device whose IPS state was never read.
  NCSA-AAA-002  authentication.local_accounts <- adminName* (0 records)
      PASSED `max_count 1`, because zero accounts is at most one.

The second is the worse of the two: a false PASS manufactured from a blind
spot, which is precisely the failure this codebase exists to refuse.

The distinction is a property of the SOURCE, not of the engine. A Cisco
running-config lists only what differs from default, so an absent `ip http
server` line is real evidence the server is off -- and must keep deciding its
control. That is why this is a per-pack flag and not a global rule.
"""
import os

import pytest

SW = r"E:\sonicwall config file.txt"
CISCO = "samples/cisco/edge-rtr-01.cfg"

sw_only = pytest.mark.skipif(not os.path.exists(SW), reason="SonicWall sample absent")
cisco_only = pytest.mark.skipif(not os.path.exists(CISCO), reason="cisco sample absent")

#: Controls whose only mapping matches no record in the reference export.
DEAD = {
    "NCSA-CAT-006": "firewall.acls",            # policyNgName*
    "NCSA-EXT-039": "security.ips.enabled",     # uuidIpsObjEnable
    "NCSA-EXT-040": "security.gav.enabled",     # uuidGavObjEnable
    "NCSA-AAA-002": "authentication.local_accounts",   # adminName*
}


@pytest.fixture(scope="module")
def sw():
    from ncsa.pipeline import assess

    return assess(SW, redact=False, assessment_id="TEST-DEADMAP")


def test_the_export_declares_itself_exhaustive():
    """The flag is what scopes this behaviour to sources that warrant it."""
    from ncsa.pipeline import load_packs

    exp = next(p for p in load_packs()
               if p.platform == "sonicwall_sonicos" and p.reader == "sonicos_exp")
    assert exp.exhaustive is True
    ios = next(p for p in load_packs() if p.platform == "cisco_iosxe_router")
    assert ios.exhaustive is False, "a running-config lists only what differs"


@sw_only
@pytest.mark.parametrize("control_id", sorted(DEAD))
def test_a_dead_mapping_decides_nothing(sw, control_id):
    """Neither FAIL nor PASS: we have no evidence either way."""
    finding = next(f for f in sw.assessment.findings if f.control_id == control_id)
    assert finding.state.value == "UNKNOWN", (
        f"{control_id} ruled {finding.state.value} on a field no record populates")


@sw_only
def test_the_false_pass_is_gone(sw):
    """`max_count 1` passed because a dead mapping returned zero accounts.
    That is the dangerous direction: a control reported as satisfied on a
    device we never read."""
    f = next(x for x in sw.assessment.findings if x.control_id == "NCSA-AAA-002")
    assert f.state.value != "PASS"


@sw_only
def test_a_present_but_empty_record_still_decides(sw):
    """The distinction this rests on. `cli_loginBanner` EXISTS with value ""
    -- the device stating it has no banner, which is provable and a real
    finding. Only a key that is absent entirely is a blind spot."""
    f = next(x for x in sw.assessment.findings if x.control_id == "NCSA-BAN-001")
    assert f.state.value == "FAIL"


@sw_only
def test_a_declared_platform_default_still_decides(sw):
    """`if_absent` is a claim we chose to make, so it survives. Otherwise
    every pack default would silently become UNKNOWN."""
    f = next(x for x in sw.assessment.findings
             if x.control_id == "NCSA-CLD-004")
    assert f.state.value in ("PASS", "UNKNOWN")
    assert f.observed == "deny"


@cisco_only
def test_a_sparse_config_is_unaffected():
    """On IOS an absent line is evidence. If this flag leaked to sparse
    formats, every compliant-by-absence control would turn UNKNOWN and scores
    would collapse across every vendor."""
    from ncsa.pipeline import assess

    da = assess(CISCO, redact=False, assessment_id="TEST-DEADMAP-IOS")
    decided = [f for f in da.assessment.findings
               if f.state.value in ("PASS", "FAIL", "PARTIAL")]
    assert len(decided) > 30, "a sparse config must still decide its controls"
