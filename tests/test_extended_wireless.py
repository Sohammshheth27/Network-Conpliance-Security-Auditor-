"""Wireless checks.

Two validations, and they are not equal, so they are labelled:

  * REAL DEVICE -- the NSA 3700. The correct answer is "no wireless network
    is live", and the file's unused wireless defaults (WEP keys included) must
    NOT become findings.
  * FIXTURE -- samples/wireless/c9800-wlc-01.cfg, built only from commands in
    Cisco's published Catalyst 9800 guides. It proves the checks behave; it
    does not prove a real controller export parses the same way.

The most important guard is the default-security test: an IOS-XE running
config omits defaults, so a WLAN with no security lines is WPA2/AES/802.1X per
Cisco -- not open. Getting that backwards would invent a high-severity finding
on every enterprise WLAN.
"""
import os
import re
from urllib.parse import unquote_plus

import pytest

from ncsa.extended.wireless import (CHECKS, assess_wireless,
                                    networks_from_cisco)
from ncsa.pipeline import assess
from ncsa.readers.indented import loads

SW = r"E:\sonicwall config file.txt"
WLC = "samples/wireless/c9800-wlc-01.cfg"
sw_only = pytest.mark.skipif(not os.path.exists(SW), reason="SonicWall sample absent")


@pytest.fixture(scope="module")
def wlc():
    da = assess(WLC, redact=False, assessment_id="TEST-WLC")
    return da, assess_wireless(da)


def _find(res, cid, ssid):
    return next(f for f in res.findings
                if f.check_id == cid and f.scope.startswith(ssid + " "))


def _nets(text):
    return {n.ssid: n for n in networks_from_cisco(loads(text, "t.cfg"))}


# ------------------------------------------------------------ real SonicWall

@sw_only
def test_the_nsa3700_has_no_live_wireless_and_says_why():
    da = assess(SW, redact=False, assessment_id="TEST-WL-SW")
    res = assess_wireless(da)
    assert res.present is False
    assert "00:00:00:00:00:00" in res.summary
    assert {f.state for f in res.findings} == {"NOT_APPLICABLE"}
    assert len(res.findings) == len(CHECKS)
    # The N/A must be justified by evidence, not asserted.
    assert all(f.evidence for f in res.findings)
    assert res.findings[0].evidence[0].raw.startswith("sonicPointMac_")


@sw_only
def test_the_evidence_matches_the_raw_file():
    """Re-derived from the export without the reader.

    Every SonicPoint MAC is zero, and no interface sits in the WLAN zone.
    """
    tokens = open(SW, encoding="utf-8", errors="replace").read().split("&")
    macs, zones = [], []
    for t in tokens:
        k, _, v = t.partition("=")
        k, v = unquote_plus(k).strip(), unquote_plus(v).strip()
        if re.match(r"^sonicPointMac_\d+$", k):
            macs.append(v)
        if re.match(r"^interface_Zone_\d+$", k):
            zones.append(v.upper())
    assert macs and all(set(m) == {"0"} for m in macs)
    assert "WLAN" not in zones


@sw_only
def test_unused_wireless_defaults_are_not_reported_as_findings():
    """The file holds WEP keys in an unused SonicPoint profile.

    Reporting "WEP in use" would describe a network that does not exist.
    """
    da = assess(SW, redact=False, assessment_id="TEST-WL-WEP")
    res = assess_wireless(da)
    assert not [f for f in res.findings if f.state in ("FAIL", "PARTIAL")]


@sw_only
def test_the_compliance_result_is_untouched():
    da = assess(SW, redact=False, assessment_id="TEST-WL-ISO")
    cov, consumed = dict(da.coverage()), set(da.document._consumed)
    assess_wireless(da)
    assert da.coverage() == cov
    assert (cov["score_pct"], cov["assessed_pct"]) == (36.2, 70.1)
    assert da.document._consumed == consumed


# ---------------------------------------------------------------- 9800 fixture

def test_the_fixture_is_read_as_cisco_ios_xe(wlc):
    da, res = wlc
    assert da.identity.platform.startswith("cisco_ios")
    assert res.present is True
    assert "fixture" in res.validated_on, "a fixture must be labelled as one"


def test_every_cited_line_is_the_line_in_the_file(wlc):
    _da, res = wlc
    lines = open(WLC, encoding="utf-8").read().splitlines()
    for f in res.findings:
        for e in f.evidence:
            actual = lines[e.line - 1].strip()
            quoted = e.raw.strip().replace("<redacted>", "")
            assert actual.startswith(quoted.split("<")[0].strip()), (
                f"{f.check_id} [{f.scope}] cites line {e.line} as "
                f"{e.raw!r}; the file has {actual!r}")


def test_open_guest_network_fails_and_names_the_captive_portal(wlc):
    _da, res = wlc
    f = _find(res, "NCSA-X-WLAN-001", "Guest-WiFi")
    assert f.state == "FAIL"
    assert "does not encrypt" in f.reason, (
        "a captive portal must not be mistaken for encryption")


def test_guest_isolation_fails_without_peer_blocking(wlc):
    _da, res = wlc
    assert _find(res, "NCSA-X-WLAN-004", "Guest-WiFi").state == "FAIL"
    assert _find(res, "NCSA-X-WLAN-004", "Secure-WPA3").state == "NOT_APPLICABLE"


def test_deprecated_security_is_caught(wlc):
    _da, res = wlc
    f = _find(res, "NCSA-X-WLAN-002", "IoT-Devices")
    assert f.state == "FAIL"
    assert "WPA1" in f.reason and "TKIP" in f.reason


def test_a_cleartext_psk_is_reported_but_never_reproduced(wlc):
    _da, res = wlc
    f = _find(res, "NCSA-X-WLAN-005", "IoT-Devices")
    assert f.state == "FAIL"
    for finding in res.findings:
        for e in finding.evidence:
            assert "fixture-key-not-real" not in e.raw, "the key leaked"


def test_a_shut_down_wlan_is_not_applicable(wlc):
    _da, res = wlc
    old = [f for f in res.findings if f.scope.startswith("Old-Lab ")]
    assert old and {f.state for f in old} == {"NOT_APPLICABLE"}


def test_wpa3_carries_pmf_by_definition(wlc):
    _da, res = wlc
    assert _find(res, "NCSA-X-WLAN-003", "Secure-WPA3").state == "PASS"


# ----------------------------------------------------------- semantics guards

def test_a_wlan_with_no_security_lines_is_wpa2_not_open():
    """Cisco: the default WPA2 policy is AES with 802.1X.

    A running config omits defaults, so reading absence as "open" would
    invent a high-severity finding on every enterprise WLAN.
    """
    n = _nets("wlan CORP 1 CORP\n no shutdown\n")["CORP"]
    assert n.security == "wpa2"
    assert n.security_basis == "platform default"
    assert n.akm == {"dot1x"} and n.ciphers == {"aes"}


def test_a_new_wlan_is_disabled_until_no_shutdown():
    """Cisco: "The configured WLAN is disabled by default." """
    assert _nets("wlan X 1 X\n")["X"].enabled is False


def test_owe_is_encrypted_not_open():
    n = _nets("wlan G 1 G\n no security wpa wpa2\n security wpa wpa3\n"
              " no security wpa akm dot1x\n security wpa akm owe\n"
              " no shutdown\n")["G"]
    assert n.security == "owe"


def test_wpa3_implies_mandatory_pmf():
    """Cisco: "For WPA3, PMF is mandatory." """
    n = _nets("wlan S 1 S\n no security wpa wpa2\n security wpa wpa3\n"
              " security wpa akm sae\n no shutdown\n")["S"]
    assert n.pmf and n.pmf.startswith("mandatory")


def test_a_router_with_no_wlans_serves_no_wireless():
    da = assess("samples/cisco/edge-rtr-01.cfg", redact=False,
                assessment_id="TEST-WL-RTR")
    res = assess_wireless(da)
    assert res.present is False
    assert not res.findings


def test_every_nist_id_cited_exists_in_the_catalogue():
    from ncsa.frameworks.models import Framework
    from ncsa.frameworks.registry import load_all

    cat = load_all().catalogs[Framework.NIST_800_53]
    cited = {i for _t, _s, nist, _w in CHECKS.values() for i in nist}
    missing = sorted(i for i in cited
                     if cat.by_id(re.sub(r"\((\d+)\)", r".\1", i)) is None)
    assert not missing, f"cited NIST ids not in the catalogue: {missing}"
