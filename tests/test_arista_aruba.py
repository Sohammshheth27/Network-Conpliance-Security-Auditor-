"""Arista EOS and HPE Aruba AOS-CX packs.

READ THIS BEFORE TRUSTING THESE PACKS
-------------------------------------
Both fixtures are CONSTRUCTED from published vendor CLI syntax. Neither is
captured output from a real device.

That makes these tests weaker than `test_paloalto.py`, which validates against
a genuine PAN-OS export — and which found a reader bug precisely because the
config was real. A fixture written alongside its pack agrees with it by
construction; it proves the pack is self-consistent, not that it matches a
real switch.

Both packs are therefore version 0.9. They should be re-validated against a
real `show running-config` before anyone relies on their output.

What these tests DO establish:
  * the packs parse and register;
  * their fingerprints select them rather than falling through to another pack;
  * their regexes match the syntax they claim to match;
  * platform-absent settings resolve to NOT_APPLICABLE, not UNKNOWN.
"""
import os
import re

import pytest
import yaml

from ncsa.engine.fingerprint import fingerprint_file
from ncsa.pipeline import assess, load_packs, select_pack
from ncsa.readers.pack import load_pack

FIX = os.path.join(os.path.dirname(__file__), "fixtures")

CASES = [
    ("arista", "arista_eos.cfg", "arista", "arista_eos", "EOS", "sw-core-01"),
    ("aruba", "aruba_aoscx.cfg", "hpe_aruba", "aruba_aoscx", "AOS-CX", "acx-access-01"),
]

#: Settings the fixtures deliberately omit — a hardened switch has no telnet
#: server and usually only one banner. Absence here is correct behaviour, not
#: a broken regex, and listing them keeps the two apart.
ABSENT_BY_DESIGN = {
    "arista": {"banner.motd"},
    "aruba": {"management.telnet.enabled", "banner.login"},
}


@pytest.mark.parametrize("name,fixture,vendor,platform,os_name,host", CASES)
def test_pack_loads_and_registers(name, fixture, vendor, platform, os_name, host):
    pack = load_pack(f"packs/{name}.yaml")
    assert pack.vendor == vendor
    assert pack.platform == platform
    assert pack.reader == "indented"
    assert platform in {p.platform for p in load_packs()}


@pytest.mark.parametrize("name,fixture,vendor,platform,os_name,host", CASES)
def test_the_fingerprint_selects_this_pack_on_platform(
        name, fixture, vendor, platform, os_name, host):
    """Selection must key on PLATFORM, not fall through to the vendor branch.

    The Arista pack originally declared `platform: eos` while the fingerprinter
    emits `arista_eos`. It still worked — but only via `select_pack`'s
    vendor-name fallback, which picks arbitrarily the moment a second pack for
    the same vendor exists. Aruba failed outright for the same reason plus a
    vendor-name mismatch (`aruba` vs `hpe_aruba`) and reported UNSUPPORTED.
    """
    fp = fingerprint_file(os.path.join(FIX, fixture))
    assert fp.platform == platform, "pack platform must match the fingerprinter"
    assert fp.vendor == vendor
    same_platform = [p for p in load_packs() if p.platform == fp.platform]
    assert same_platform, "selection must not depend on the vendor fallback"


@pytest.mark.parametrize("name,fixture,vendor,platform,os_name,host", CASES)
def test_every_regex_matches_except_those_absent_by_design(
        name, fixture, vendor, platform, os_name, host):
    """A regex that matches nothing yields NOT_OBSERVED, which is silent.

    It is indistinguishable from a device that genuinely lacks the setting, so
    it has to be asserted. Two real bugs were caught this way: Arista's SSH MAC
    line is `mac <algorithms>` not `mac hmac <algorithms>`, and Aruba puts the
    VRF *between* the host and the severity — `logging H vrf mgmt severity S` —
    so a regex expecting them adjacent never matches a real switch.
    """
    raw = yaml.safe_load(open(f"packs/{name}.yaml", encoding="utf-8"))
    text = open(os.path.join(FIX, fixture), encoding="utf-8").read()
    missing = {
        m["field"] for m in raw["mappings"]
        if m.get("regex") and not re.search(m["regex"], text, re.M)
    }
    unexpected = missing - ABSENT_BY_DESIGN[name]
    assert not unexpected, f"regexes matching nothing: {sorted(unexpected)}"


@pytest.mark.parametrize("name,fixture,vendor,platform,os_name,host", CASES)
def test_absent_by_design_really_is_absent(
        name, fixture, vendor, platform, os_name, host):
    """Nothing may be excused that the fixture can actually exercise.

    Otherwise ABSENT_BY_DESIGN becomes a place to hide broken regexes.
    """
    raw = yaml.safe_load(open(f"packs/{name}.yaml", encoding="utf-8"))
    text = open(os.path.join(FIX, fixture), encoding="utf-8").read()
    by_field = {m["field"]: m.get("regex") for m in raw["mappings"]}
    wrongly_excused = [
        f for f in ABSENT_BY_DESIGN[name]
        if by_field.get(f) and re.search(by_field[f], text, re.M)
    ]
    assert not wrongly_excused, f"these do match: {wrongly_excused}"


@pytest.mark.parametrize("name,fixture,vendor,platform,os_name,host", CASES)
def test_assessment_is_supported_and_identified(
        name, fixture, vendor, platform, os_name, host):
    result = assess(os.path.join(FIX, fixture), redact=True,
                    assessment_id=f"{name}-test")
    assert result.supported is True, "pack was not selected for this device"
    assert result.identity.vendor == vendor
    assert result.identity.os == os_name
    assert result.identity.hostname == host


@pytest.mark.parametrize("name,fixture,vendor,platform,os_name,host", CASES)
def test_platform_absent_settings_are_not_applicable(
        name, fixture, vendor, platform, os_name, host):
    """Neither platform has an IOS-style enable secret.

    Left as UNKNOWN it would depress coverage and imply we failed to read
    something that was never there.
    """
    result = assess(os.path.join(FIX, fixture), redact=True,
                    assessment_id=f"{name}-na")
    assert result.counts()["NOT_APPLICABLE"] > 0
    na = {f.field for f in result.assessment.findings
          if f.state.value == "NOT_APPLICABLE"}
    assert "authentication.enable_secret" in na


@pytest.mark.parametrize("name,fixture,vendor,platform,os_name,host", CASES)
def test_no_value_is_claimed_without_evidence(
        name, fixture, vendor, platform, os_name, host):
    result = assess(os.path.join(FIX, fixture), redact=True,
                    assessment_id=f"{name}-ev")
    naked = [f.control_id for f in result.assessment.findings
             if f.observed is not None and not f.evidence]
    assert not naked, f"claims a value with no evidence: {naked}"


@pytest.mark.parametrize("name,fixture,vendor,platform,os_name,host", CASES)
def test_pack_is_marked_unvalidated(name, fixture, vendor, platform, os_name, host):
    """Version stays below 1.0 until a real device config validates the pack.

    This is a deliberate tripwire: bumping the version should require having
    actually checked it against captured output.
    """
    raw = yaml.safe_load(open(f"packs/{name}.yaml", encoding="utf-8"))
    assert str(raw["version"]).startswith("0."), (
        "these packs are validated only against constructed fixtures; do not "
        "mark them 1.0 until checked against a real running-config")
