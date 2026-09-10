"""`show` command output via TextFSM / ntc-templates.

This is the tier that answers deliverable 4a. A running configuration does not
contain a serial number, which is why NCSA reported `serial=None` for every
Cisco and Juniper device -- it was looking in the only place the answer could
never be.
"""
import glob
import os

import pytest

from ncsa.pipeline import assess, enrich_identity, DeviceIdentity
from ncsa.readers.show_output import (available_platforms, identity_from,
                                      looks_like_show_output, ntc_platform,
                                      parse, template_dir)

T = "downloads/ntc-templates/tests"
have_templates = pytest.mark.skipif(
    template_dir() is None, reason="ntc-templates not cloned")


def _fixture(platform):
    g = glob.glob(f"{T}/{platform}/show_version/*.raw")
    return g[0] if g else None


# ------------------------------------------------------------------ parsing
@have_templates
def test_templates_are_available_for_many_platforms():
    assert len(available_platforms()) > 20


@have_templates
def test_serial_and_hardware_are_extracted():
    """The fields a config file cannot supply."""
    f = _fixture("cisco_ios")
    if not f:
        pytest.skip("fixture absent")
    ident = identity_from(parse(open(f, encoding="utf-8").read(), "cisco_ios"))
    assert ident["serial"] == "CAT1451S15C"
    assert ident["model"] == "WS-C4948E"


@have_templates
@pytest.mark.parametrize("platform", ["cisco_ios", "cisco_nxos", "cisco_asa",
                                      "juniper_junos", "arista_eos"])
def test_identity_fields_survive_vendor_spelling_differences(platform):
    """Arista writes MODEL/IMAGE, Junos writes JUNOS_VERSION, NX-OS writes
    PLATFORM/OS. Assuming one spelling returned None on four vendors of five
    while the parse itself succeeded."""
    f = _fixture(platform)
    if not f:
        pytest.skip(f"no {platform} fixture")
    ident = identity_from(parse(open(f, encoding="utf-8").read(), platform))
    assert ident.get("model"), f"{platform}: no model extracted"
    assert ident.get("version"), f"{platform}: no version extracted"


@have_templates
def test_missing_template_returns_empty_not_an_exception():
    """An unsupported platform is a coverage gap to report, not a crash."""
    assert parse("anything at all", "no_such_vendor") == []


def test_show_output_is_distinguished_from_a_config():
    assert looks_like_show_output(
        "Cisco IOS Software, Version 12.2\nrouter1 uptime is 2 years")
    # A config must never be mistaken for show output -- it would be handed to
    # a template and silently produce nothing.
    assert not looks_like_show_output("version 17.9\nhostname edge-rtr-01")
    assert not looks_like_show_output("set system host-name srx-1")


def test_platform_aliasing():
    assert ntc_platform("cisco_iosxe_router") == "cisco_ios"
    assert ntc_platform("juniper_srx_xml") == "juniper_junos"


# -------------------------------------------------------------- enrichment
@have_templates
def test_config_values_win_over_show_output():
    """The config is the artifact being audited and the one findings cite."""
    ident = DeviceIdentity(platform="cisco_iosxe_router", version="17.9",
                           hostname="edge-rtr-01")
    f = _fixture("cisco_ios")
    if not f:
        pytest.skip("fixture absent")
    enrich_identity(ident, open(f, encoding="utf-8").read())
    assert ident.version == "17.9"          # not the show-version value


@have_templates
def test_mismatched_device_is_refused_not_merged():
    """Several fields disagreeing means two different devices. A serial from
    the wrong box on an audit report is worse than no serial."""
    f = _fixture("cisco_ios")
    if not f:
        pytest.skip("fixture absent")
    r = assess("samples/cisco/edge-rtr-01.cfg", show_output=f)
    assert r.identity.serial is None
    assert any("WARNING" in n and "different devices" in n for n in r.notes)


@have_templates
def test_matching_device_is_enriched():
    f = _fixture("cisco_ios")
    if not f:
        pytest.skip("fixture absent")
    text = open(f, encoding="utf-8").read().replace("router1", "edge-rtr-01")
    r = assess("samples/cisco/edge-rtr-01.cfg", show_output=text)
    assert r.identity.serial == "CAT1451S15C"
    assert r.identity.model == "WS-C4948E"


def test_assess_without_show_output_is_unchanged():
    """The enrichment must be strictly additive."""
    r = assess("samples/cisco/edge-rtr-01.cfg")
    assert r.identity.serial is None       # config genuinely has none
    assert r.identity.version == "17.9"
