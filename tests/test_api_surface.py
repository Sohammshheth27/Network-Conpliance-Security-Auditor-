"""The management REST API as an audited attack surface, and the gate on it.

An enabled management API is remote administrative access by another name. On
the reference NSA 3700 its 22 settings were parsed on every run and mapped to
nothing: basic auth, MD5 digest, a 1024-bit key, CORS policy. Nothing asked a
question about any of them.

These tests cover two things that have to be true together:

  1. the settings are read and evaluated when the API is ON;
  2. they resolve to NOT_APPLICABLE -- citing the disabling setting -- when it
     is OFF.

The second without the first would be a permanently silent control, which is
indistinguishable from not having written it. That is what
`test_the_gate_is_conditional_not_a_permanent_off_switch` exists to prevent.
"""
import os

import pytest

from ncsa.engine.control import Control
from ncsa.engine.evaluate import evaluate_all
from ncsa.engine.rules import load_rules
from ncsa.pipeline import assess
from ncsa.schema.enums import ResultState
from ncsa.schema.evidence import EvidenceRef
from ncsa.schema.observation import Observation
from ncsa.schema.sbm import SecurityBaselineModel

SW = r"E:\sonicwall config file.txt"
sw_only = pytest.mark.skipif(not os.path.exists(SW), reason="SonicWall sample absent")

API_FIELDS = [
    "platform.api.basic_auth",
    "platform.api.digest_md5",
    "platform.api.pubkey_bits",
    "platform.api.cors",
    "platform.api.session_security",
    "platform.api.logging",
]


@pytest.fixture(scope="module")
def controls():
    return load_rules("rules")


def test_every_api_control_is_gated_on_the_api_being_enabled(controls):
    """A control about a disabled surface must not be able to fail.

    Without the gate, a device with the API switched off collects six findings
    about an interface it does not expose -- which is the same mistake as
    reporting the TLS version of disabled HTTPS management.
    """
    gated = {c.field: c for c in controls if c.field in API_FIELDS}
    assert len(gated) == len(API_FIELDS), "an API control is missing"
    for field, c in gated.items():
        reqs = c.requires or []
        assert any(r.get("field") == "platform.api.enabled" and r.get("equals") is True
                   for r in reqs), f"{field} is not gated on platform.api.enabled"
        assert all(r.get("because") for r in reqs), (
            f"{field}: a suppressed control must say why")


def _sbm() -> SecurityBaselineModel:
    """A bare SBM. The identity fields are required by the model itself."""
    return SecurityBaselineModel(assessment_id="test", source_file="synthetic",
                                 source_sha256="0" * 64)


def _obs(value, field):
    """An observation with evidence.

    Evidence is a required argument, not a convenience: the model does not let
    a value be recorded without a line to back it, which is the same rule the
    findings obey.
    """
    return Observation.observed(
        value,
        [EvidenceRef(file="synthetic", line=1, raw=f"{field}={value}")],
        field_path=field)


def _evaluate(sbm, controls, wanted):
    """Evaluate only the named controls, and index the findings by field."""
    picked = [c for c in controls if c.field in wanted]
    assessment = evaluate_all(picked, sbm, device="synthetic",
                              platform="sonicwall_sonicos")
    return {f.field: f for f in assessment.findings}


def test_the_gate_is_conditional_not_a_permanent_off_switch(controls):
    """With the API ENABLED the same controls must produce real verdicts.

    A gate that suppressed unconditionally would pass every other test here
    while auditing nothing at all.
    """
    sbm = _sbm()
    sbm.set("platform.api.enabled", _obs(True, "platform.api.enabled"))
    sbm.set("platform.api.basic_auth", _obs(True, "platform.api.basic_auth"))
    sbm.set("platform.api.pubkey_bits", _obs(1024, "platform.api.pubkey_bits"))
    sbm.set("platform.api.cors", _obs(True, "platform.api.cors"))

    got = _evaluate(sbm, controls,
                    {"platform.api.basic_auth", "platform.api.pubkey_bits", "platform.api.cors"})

    # Basic auth on a live API is a real finding, not a suppressed one.
    assert got["platform.api.basic_auth"].state is ResultState.FAIL
    # 1024 bits is below the 2048 minimum.
    assert got["platform.api.pubkey_bits"].state is ResultState.FAIL
    assert got["platform.api.cors"].state is ResultState.FAIL


def test_the_gate_fires_when_the_api_is_disabled(controls):
    sbm = _sbm()
    sbm.set("platform.api.enabled", _obs(False, "platform.api.enabled"))
    sbm.set("platform.api.basic_auth", _obs(True, "platform.api.basic_auth"))

    got = _evaluate(sbm, controls, {"platform.api.basic_auth"})
    f = got["platform.api.basic_auth"]
    assert f.state is ResultState.NOT_APPLICABLE
    assert "disabled" in f.reason.lower()


def test_an_unmapped_gate_field_does_not_suppress_the_control(controls):
    """The precondition may suppress only on an OBSERVED value.

    If `platform.api.enabled` is simply not mapped for a platform, that is a
    gap in OUR coverage. Reading it as "the API is off" would manufacture a
    false negative out of our own blind spot -- strictly worse than the false
    positive the gate exists to remove.
    """
    sbm = _sbm()
    # api.enabled deliberately never set.
    sbm.set("platform.api.basic_auth", _obs(True, "platform.api.basic_auth"))

    got = _evaluate(sbm, controls, {"platform.api.basic_auth"})
    assert got["platform.api.basic_auth"].state is ResultState.FAIL, (
        "an unmapped gate must not silently disable the control")


@sw_only
def test_the_real_device_reports_the_api_surface_as_not_applicable():
    """The reference NSA 3700 has `sonicOsApi_enable = off`."""
    r = assess(SW, redact=False, assessment_id="api-surface")
    by_field = {f.field: f for f in r.assessment.findings}
    for field in API_FIELDS:
        f = by_field[field]
        assert f.state is ResultState.NOT_APPLICABLE, f"{field} was {f.state}"
        # The disabling setting itself must be the evidence, so a reader can
        # check the suppression rather than take it on trust.
        assert f.evidence, f"{field}: a suppressed control must cite the reason"
        assert "sonicOsApi_enable" in f.evidence[0].raw


@sw_only
def test_stored_credentials_are_audited_and_this_device_fails():
    """`encUsernamePassword = off` -- a leaked backup exposes credentials.

    Not gated: stored-credential protection matters whether or not any
    management interface is enabled.
    """
    r = assess(SW, redact=False, assessment_id="stored-creds")
    f = next(x for x in r.assessment.findings
             if x.field == "platform.stored_credentials_encrypted")
    assert f.state is ResultState.FAIL
    assert "encUsernamePassword" in f.evidence[0].raw
