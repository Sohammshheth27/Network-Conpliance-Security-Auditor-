"""Redaction hides secrets and addresses. It must never change a verdict."""
from functools import lru_cache
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


def test_addresses_are_still_masked():
    assert _redact_value("iface_lan_ip", "192.168.10.1") == "10.168.10.x"


@pytest.mark.skipif(not os.path.exists(SW), reason="SonicWall sample absent")
def test_redacted_sonicwall_equals_unredacted():
    raw = _sw(False)
    red = _sw(True)
    assert (red.coverage()["score_pct"], red.coverage()["assessed_pct"]) == (40.0, 74.6)
    assert red.coverage() == raw.coverage()
    states = lambda da: {f.control_id: f.state.value for f in da.assessment.findings}
    assert states(red) == states(raw)
    assert states(red)["NCSA-PLT-002"] == "FAIL"
