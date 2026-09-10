"""Vendor-agnostic detectors. The negative cases matter more than the positive.

A detector that fires on every vendor can be WRONG on every vendor, so each
trap that produced a false positive during development is pinned here.
"""
import pytest

from ncsa.universal import scan, summarise


def _dets(text):
    return {f.detector for f in scan(text)}


# ------------------------------------------------------------ true positives
def test_finds_cleartext_credential_with_no_pack():
    f = scan("enable password Marcraft1")
    assert any(x.detector == "cleartext_credential" for x in f)


def test_finds_weak_key_exchange():
    f = scan("ssh key-exchange group dh-group1-sha1")
    assert any(x.detector == "weak_crypto" for x in f)


def test_finds_default_snmp_community():
    assert "default_snmp_community" in _dets("snmp-server community public RO")


def test_finds_any_any_permit():
    assert "any_any_permit" in _dets("access-list 100 permit ip any any")


def test_works_on_a_vendor_grammar_we_have_no_pack_for():
    """A MikroTik-style config: no pack, no signature, still readable facts."""
    mikrotik = "/ip service set telnet disabled=no\n" \
               "/snmp community set [find default=yes] name=public"
    d = _dets(mikrotik)
    assert "default_snmp_community" in d


# ----------------------------------------------------------- false positives
def test_telnet_timeout_is_not_telnet_enabled():
    """The real ASA has `telnet timeout 5` and permits no telnet at all."""
    assert "telnet_enabled" not in _dets("telnet timeout 5")


def test_ip_http_secure_server_is_https_not_cleartext():
    """`secure-server` IS the hardened form; the `s` is in the next word, so
    a lookahead on `https` does not catch it."""
    assert "cleartext_http_mgmt" not in _dets("ip http secure-server")
    assert "cleartext_http_mgmt" in _dets("ip http server")


def test_negation_is_honoured():
    """`no ip http server` contains the insecure token and means the opposite.

    Turning hardened devices into failing ones is the most expensive false
    positive available.
    """
    assert "cleartext_http_mgmt" not in _dets("no ip http server")
    assert "telnet_enabled" not in _dets("set telnet disable")
    assert "telnet_enabled" not in _dets("delete system services telnet")


def test_hashed_password_is_not_a_cleartext_finding():
    for line in ("enable secret 5 $1$mERr$xyz123abc",
                 "username admin password 7 070C285F4D06 encrypted",
                 "set authentication-key $9$abcdefgHIJKLM"):
        assert "cleartext_credential" not in _dets(line), line


def test_description_does_not_trip_the_des_cipher_rule():
    """`des` inside `description` is not a cipher."""
    assert "weak_crypto" not in _dets("description DES-MOINES-UPLINK cipher")


def test_comments_are_ignored():
    assert scan("! telnet is disabled on this device") == []
    assert scan("# snmp community public was removed") == []


def test_one_line_yields_one_finding():
    """`snmp-server community public` trips two detectors; reporting it twice
    inflates a device's problem count with a detail about our implementation."""
    f = scan("snmp-server community public RO")
    assert len({x.line for x in f}) == len(f)


# ------------------------------------------------------------- discrimination
def test_hardened_config_scores_better_than_vulnerable_one():
    import os
    h = "samples/cisco/hardened-per-cisco-guide.cfg"
    v = "samples/cisco/edge-rtr-01.cfg"
    if not (os.path.exists(h) and os.path.exists(v)):
        pytest.skip("samples absent")
    nh = len(scan(open(h, encoding="utf-8").read()))
    nv = len(scan(open(v, encoding="utf-8").read()))
    assert nh < nv, "the universal layer must discriminate, not just fire"


def test_findings_always_cite_a_line():
    """Positive evidence only: a universal detector may never report an
    absence, because absence needs a grammar we do not have."""
    f = scan("enable password Marcraft1\nssh key-exchange group dh-group1-sha1")
    assert f and all(x.line > 0 and x.raw for x in f)


def test_confidence_is_below_a_parsed_observation():
    f = scan("enable password Marcraft1")
    assert all(x.confidence < 1.0 for x in f)


def test_ipsec_transform_sets_are_read():
    """`esp-des esp-md5-hmac` is weak IPsec; the hyphen prefix hid it."""
    assert "weak_crypto" in _dets(
        "crypto ipsec transform-set OLD esp-des esp-md5-hmac")
    # ...and a strong transform set must stay clean.
    assert "weak_crypto" not in _dets(
        "crypto ipsec transform-set NEW esp-aes-256 esp-sha256-hmac")
