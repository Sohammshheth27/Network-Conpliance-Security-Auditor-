"""Consensus between independent methods.

The critical property is NOT that consensus is usually reached. It is that
disagreement is still detectable -- a reconciler that only ever returns
CONFIRMED measures nothing while looking like it measures everything.
"""
import pytest

from ncsa.consensus import CONFIRMED, DISPUTED, UNCORROBORATED, reconcile
from ncsa.pipeline import assess
from ncsa.schema.enums import ResultState
from ncsa.universal import UniversalFinding, scan


class _Finding:
    def __init__(self, field, observed, state=ResultState.FAIL):
        self.field, self.observed, self.state = field, observed, state


class _Assessment:
    def __init__(self, findings):
        self.findings = findings


class _DA:
    def __init__(self, findings):
        self.assessment = _Assessment(findings)


def _uf(detector="telnet_enabled", field="management.telnet.enabled", line=1):
    return UniversalFinding(detector=detector, title="t", severity="high",
                            line=line, raw="transport input telnet",
                            matched="telnet", field_hint=field)


# --------------------------------------------------- all three are reachable
def test_agreement_is_confirmed_and_raises_confidence():
    da = _DA([_Finding("management.telnet.enabled", True, ResultState.FAIL)])
    item = reconcile(da, [_uf()]).items[0]
    assert item.verdict == CONFIRMED
    assert item.confidence == 1.0        # above either method alone


def test_contradiction_is_disputed_and_neither_side_is_dropped():
    """The pack says telnet is off; the detector says it saw telnet."""
    da = _DA([_Finding("management.telnet.enabled", False, ResultState.PASS)])
    item = reconcile(da, [_uf()]).items[0]
    assert item.verdict == DISPUTED
    assert item.confidence < 0.8         # below either method alone
    # Both positions must survive into the report.
    assert "telnet" in item.universal_says.lower() or item.universal_says
    assert "management.telnet.enabled" in item.pack_says


def test_no_pack_mapping_is_uncorroborated_and_named_as_a_coverage_gap():
    """The most actionable output: something real, with a line number, that
    the pack cannot see."""
    rep = reconcile(_DA([]), [_uf(line=97)])
    assert rep.items[0].verdict == UNCORROBORATED
    assert rep.coverage_gaps and "L97" in rep.coverage_gaps[0]


def test_undecided_pack_does_not_count_as_contradiction():
    """UNKNOWN is not disagreement -- the pack simply could not tell."""
    da = _DA([_Finding("management.telnet.enabled", None, ResultState.UNKNOWN)])
    assert reconcile(da, [_uf()]).items[0].verdict == UNCORROBORATED


def test_insecure_is_spelled_differently_per_field():
    """`v is False` confirms a password-encryption finding; a NON-EMPTY LIST
    confirms an snmp.communities one. Keying the predicate on the detector
    alone applied the bool test to a list and manufactured a dispute with a
    pack that agreed."""
    da = _DA([_Finding("snmp.communities", ["READONLY"], ResultState.PASS)])
    item = reconcile(da, [_uf("cleartext_credential", "snmp.communities")]).items[0]
    assert item.verdict == CONFIRMED


def test_dispute_rate_is_measured():
    da = _DA([_Finding("management.telnet.enabled", False, ResultState.PASS),
              _Finding("crypto.weak_ciphers", ["des"], ResultState.FAIL)])
    rep = reconcile(da, [_uf(),
                         _uf("weak_crypto", "crypto.weak_ciphers", line=2)])
    assert rep.dispute_rate == 50.0


# ------------------------------------------------------------- on real files
def _consensus_for(path):
    r = assess(path)
    text = open(path, encoding="utf-8", errors="replace").read()
    return reconcile(r, scan(text))


def test_real_asa_findings_are_corroborated_by_two_methods():
    import os
    if not os.path.exists(r"E:\ASA.txt"):
        pytest.skip("ASA sample absent")
    rep = _consensus_for(r"E:\ASA.txt")
    assert rep.items, "no universal findings to reconcile"
    assert len(rep.by_verdict(CONFIRMED)) >= 2


def test_hardened_config_confirms_rather_than_disputes():
    """Disputes on a correctly configured device mean a layer has drifted."""
    rep = _consensus_for("samples/cisco/hardened-per-cisco-guide.cfg")
    assert rep.dispute_rate == 0.0, rep.explain()


def test_consensus_found_a_real_pack_blind_spot():
    """Regression test for the gap consensus itself uncovered: the Cisco pack
    read `ip ssh server algorithm` and nothing else, so `auth md5 ... priv
    3des` on an SNMPv3 user reported crypto.weak_ciphers = [] -- on the
    fixture built to demonstrate correct configuration."""
    r = assess("samples/cisco/hardened-per-cisco-guide.cfg")
    weak = [f for f in r.assessment.findings if f.field == "crypto.weak_ciphers"][0]
    assert weak.observed, "SNMPv3 weak crypto must be visible to the pack"
    assert any("snmpv3" in str(v) for v in weak.observed)
