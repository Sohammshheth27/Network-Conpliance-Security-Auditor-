"""Redaction hides secrets and addresses. It must never change a verdict."""
from functools import lru_cache
import ipaddress
import os

import pytest

from ncsa.pipeline import assess
from ncsa.readers.sonicos_exp import _redact_value

SW = r"E:\sonicwall config file.txt"


@lru_cache(maxsize=None)
def _sw(redact=False, frameworks=None):
    """One SonicWall assessment per distinct input for the whole file: each
    run of this 2.7 MB export costs ~40 s, and these tests only read it."""
    return assess(SW, redact=redact, assessment_id="TEST-SW",
                  frameworks=list(frameworks) if frameworks else None)


@pytest.mark.parametrize("key,val", [
    ("encUsernamePassword", "on"), ("encUsernamePassword", "off"),
    ("sshSecretEnabled", "1"), ("tokenAuthEnable", "false"),
])
def test_a_switch_is_never_redacted(key, val):
    assert _redact_value(key, val) == val


@pytest.mark.parametrize("key,val", [
    ("encPassword", "$5$rounds=5000$abcdefgh"),
    ("userIV", "0a1b2c3d4e5f60718293a4b5c6d7e8f9"),
    ("sharedKey_3", "hunter2-shared"),
    ("adminPasswordHash", "5f4dcc3b5aa765d61d8327deb882cf99"),
])
def test_secrets_are_still_redacted(key, val):
    assert _redact_value(key, val) == "<REDACTED>"


def test_an_address_becomes_a_valid_pseudonym():
    """Not `10.168.10.x`. That was not an address, and everything that parsed
    addressing broke on it -- see `_pseudonym`. The /24 is hashed into 10/8 and
    the host octet carries across."""
    out = _redact_value("iface_lan_ip", "192.168.10.1")
    assert out == "10.38.159.1"
    assert ipaddress.ip_address(out).is_private
    assert "192.168" not in out


def test_one_real_subnet_stays_one_pseudonymous_subnet():
    """Prefix-preserving, or the map lies. Hashing the whole address would put
    two interfaces that really share a subnet on unrelated /24s, and the
    topology would show them as separate networks."""
    a = _redact_value("addrObjIp1_1", "192.168.5.1")
    b = _redact_value("addrObjIp1_2", "192.168.5.20")
    assert a.rsplit(".", 1)[0] == b.rsplit(".", 1)[0]
    assert (a.rsplit(".", 1)[1], b.rsplit(".", 1)[1]) == ("1", "20")
    # A different real subnet must land somewhere else.
    c = _redact_value("addrObjIp1_3", "172.16.9.1")
    assert c.rsplit(".", 1)[0] != a.rsplit(".", 1)[0]


@pytest.mark.parametrize("mask", ["255.255.255.0", "255.255.254.0",
                                  "255.255.255.255", "0.0.0.0"])
def test_a_netmask_is_never_touched(mask):
    """A netmask is not sensitive, and masking it destroyed the subnet
    arithmetic `Interface.network` depends on."""
    assert _redact_value("addrObjSubnetMask_1", mask) == mask


@pytest.mark.skipif(not os.path.exists(SW), reason="SonicWall sample absent")
def test_redacted_sonicwall_equals_unredacted():
    raw = _sw(False)
    red = _sw(True)
    # 41.3 / 68.7 since 20 Sep, deliberately. Four controls rested on mappings
    # that match none of the 92,635 records, so the engine ruled on silence:
    # two FAILs asserting a violation it had no evidence for, and -- worse --
    # `max_count 1` on local accounts PASSING because a dead `adminName*`
    # returned zero accounts. They are UNKNOWN now, which is why coverage FELL
    # while the score rose: four controls left the decided set.
    #
    # This assertion is the point. A score must never move quietly, and it
    # caught this move the moment the pack was flagged `exhaustive`.
    assert (red.coverage()["score_pct"], red.coverage()["assessed_pct"]) == (41.3, 68.7)
    assert red.coverage() == raw.coverage()
    states = lambda da: {f.control_id: f.state.value for f in da.assessment.findings}
    assert states(red) == states(raw)
    assert states(red)["NCSA-PLT-002"] == "FAIL"
