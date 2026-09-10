"""Fortinet FortiOS pack.

The pack itself is data, so these tests are about the two things data can still
get wrong: mapping to a path that does not exist, and claiming a fact the
configuration does not support.
"""
import os

import pytest

from ncsa.pipeline import assess, load_packs
from ncsa.readers.fortinet_block import load as load_block
from ncsa.readers.pack import load_pack

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "fortios_edge.conf")


@pytest.fixture(scope="module")
def cfg():
    return load_block(FIXTURE)


@pytest.fixture(scope="module")
def pack():
    return load_pack("packs/fortinet.yaml")


@pytest.fixture(scope="module")
def result():
    return assess(FIXTURE, redact=True, assessment_id="fortinet-test")


def test_the_pack_loads_at_all(pack):
    """`load_packs` swallows a malformed pack silently.

    A pack that fails validation is skipped by a bare `except: continue`, so a
    typo does not raise — the vendor simply vanishes and every device of that
    platform reports UNSUPPORTED. This asserts the pack parses, because nothing
    else will tell us.
    """
    assert pack.vendor == "fortinet"
    assert pack.platform == "fortios"
    assert pack.reader == "fortinet_block"
    assert len(pack.mappings) > 40


def test_the_pack_is_registered(pack):
    platforms = {p.platform for p in load_packs()}
    assert "fortios" in platforms


def test_every_mapped_path_exists_in_a_real_config(cfg, pack):
    """No mapping may point at a path the reader never produces.

    A path with a typo is not an error — it silently yields NOT_OBSERVED, which
    is indistinguishable from a device that genuinely lacks the setting. That is
    exactly the failure mode this codebase treats as unacceptable, so it is
    asserted rather than trusted.
    """
    missing = []
    for m in pack.mappings:
        if not m.path:
            continue
        found = cfg.glob(m.path) if "*" in m.path else cfg.get(m.path) is not None
        if not found:
            missing.append(f"{m.field} <- {m.path}")
    assert not missing, "mappings resolving to nothing: " + "; ".join(missing)


def test_fingerprint_selects_this_pack_and_not_sonicwall(result):
    """FortiOS and the SonicWall CLI export share a reader.

    If the fingerprints collided, a FortiGate would be assessed with SonicWall's
    mappings and quietly produce wrong answers.
    """
    assert result.supported is True
    assert result.identity.vendor == "fortinet"
    assert result.identity.os == "FortiOS"
    assert result.identity.hostname == "fgt-edge-01"


def test_absence_from_every_allowlist_is_evidenced_not_assumed(result):
    """Telnet is off because no interface allows it — and we can prove it.

    FortiOS has no global telnet toggle, so "off" is only true if telnet is
    absent from every interface's allow-list. The derivation must therefore
    cite EVERY list it checked. A bare `False` with no evidence would be an
    assumption wearing an observation's clothes.
    """
    telnet = [f for f in result.assessment.findings
              if f.field == "management.telnet.enabled"]
    assert telnet, "no finding for management.telnet.enabled"
    finding = telnet[0]
    assert finding.observed is False
    assert len(finding.evidence) >= 2, (
        "absence must cite every allow-list checked, not a single line")
    assert all("allowaccess" in e.raw for e in finding.evidence)


def test_a_service_that_is_present_cites_only_where_it_appears(result):
    """SSH is allowed on one interface, so the evidence is that one line."""
    ssh = [f for f in result.assessment.findings
           if f.field == "management.ssh.enabled"]
    assert ssh
    assert ssh[0].observed is True
    assert any("ssh" in e.raw for e in ssh[0].evidence)


def test_declared_not_applicable_fields_do_not_become_unknown(result):
    """A FortiGate has no enable-secret and no AUX port.

    Those controls must resolve to NOT_APPLICABLE. Left as UNKNOWN they would
    depress coverage and imply we failed to read something that was never
    there.
    """
    counts = result.counts()
    assert counts["NOT_APPLICABLE"] > 0
    na_fields = {f.field for f in result.assessment.findings
                 if f.state.value == "NOT_APPLICABLE"}
    assert "authentication.enable_secret" in na_fields


def test_coverage_is_reported_with_its_score(result):
    cov = result.coverage()
    assert cov["controls_total"] > 0
    assert cov["controls_decided"] > 0
    # the invariant the whole product rests on
    assert (cov["score_pct"] is None) == (cov["controls_decided"] == 0)
    assert cov["assessed_pct"] <= 100.0
