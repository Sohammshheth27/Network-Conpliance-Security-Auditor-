"""The hardened-configuration emitter.

The emitter writes into a file an operator may import onto a production
firewall, so its refusals matter more than its changes. Every test here pins a
way it could confidently do the wrong thing.
"""
import os
from dataclasses import dataclass

import pytest

from ncsa.engine.emit import _bool_like, _target, emit_sonicos, verify

SW = r"E:\sonicwall config file.txt"
sw_only = pytest.mark.skipif(not os.path.exists(SW), reason="SonicWall sample absent")


@dataclass
class _Control:
    field: str
    operator: str
    expected: object


@dataclass
class _Mapping:
    path: str = "k"
    value: dict = None
    const: object = None


# ------------------------------------------------------------ value spelling
@pytest.mark.parametrize("current,want,expected", [
    ("off", True, "on"), ("on", False, "off"),
    ("0", True, "1"), ("1", False, "0"),
    ("disable", True, "enable"), ("false", True, "true"),
])
def test_the_devices_own_spelling_is_copied(current, want, expected):
    """Which word a key wants is READ from the key, never assumed. The export
    uses `0`/`off` and `1`/`on` for different settings; writing the wrong one
    is writing a value the device does not recognise."""
    assert _bool_like(current, want) == expected


def test_a_value_that_is_not_boolean_shaped_has_no_spelling():
    assert _bool_like("10.90.213.9", True) is None
    assert _bool_like("", True) is None


# ------------------------------------------------------------- the type guard
def test_a_boolean_control_over_a_string_record_is_refused():
    """THE GUARD. An earlier version wrote `syslogServerName=on` -- a boolean
    word into a server ADDRESS field -- because the control says `equals True`
    and the record was empty. That is an invented value, and it would have put
    nonsense into a production firewall."""
    control = _Control("logging.remote_syslog", "equals", True)
    value, reason = _target(control, "", _Mapping(value={}))
    assert value is None
    assert "does not contain" in reason


def test_a_boolean_control_over_a_declared_bool_record_is_written():
    """The pack declaring `as: bool` is what makes an empty record writable."""
    control = _Control("management.https.enabled", "equals", True)
    value, _ = _target(control, "", _Mapping(value={"as": "bool"}))
    assert value == "on"


def test_a_policy_operator_is_never_a_single_record_change():
    """`max_count 0` on "admin ports open to the internet" is satisfied by
    editing firewall rules. There is no record to write, and pretending there
    is would produce a file that claims to fix an exposure it has not."""
    for op in ("max_count", "contains_none", "not_in"):
        value, reason = _target(_Control("f", op, 0), "x", _Mapping())
        assert value is None
        assert "policy" in reason


def test_a_bound_already_met_is_not_rewritten():
    assert _target(_Control("f", "lte", 120), "60", _Mapping())[0] is None
    assert _target(_Control("f", "gte", 15), "20", _Mapping())[0] is None


def test_a_bound_is_corrected_to_the_limit():
    assert _target(_Control("f", "lte", 120), "300", _Mapping())[0] == "120"
    assert _target(_Control("f", "gte", 15), "1", _Mapping())[0] == "15"


def test_a_value_specific_to_the_organisation_is_refused():
    """`is_set` on a syslog host needs an address the configuration does not
    hold. A banner is different: its text is generic."""
    value, reason = _target(_Control("logging.servers", "is_set", None), "", _Mapping())
    assert value is None and "not derivable" in reason


# ------------------------------------------------------- against the device
@pytest.fixture(scope="module")
def emitted():
    from ncsa.engine.rules import load_rules
    from ncsa.pipeline import assess, load_packs, select_pack

    da = assess(SW, redact=False, assessment_id="TEST-EMIT")
    controls = {c.id: c for c in load_rules("rules", platform=da.identity.platform)}
    pack = select_pack(load_packs(), da.fingerprint)
    return da, emit_sonicos(da, SW, controls_by_id=controls, pack=pack)


@sw_only
def test_only_cited_records_change(emitted):
    """MINIMAL DIFF. A setting that passes has nothing to correct, so the file
    must differ only where a finding proved it wrong."""
    from ncsa.readers.sonicos_exp import loads

    da, em = emitted
    before = loads(open(SW, encoding="utf-8", errors="replace").read())
    after = loads(em.text)
    assert before.total_records == after.total_records
    differing = {k for k in before.values
                 if k in after.values and before.values[k][0] != after.values[k][0]}
    assert differing == {c.key for c in em.changes}
    assert not (set(before.values) ^ set(after.values)), "no record added or removed"


@sw_only
def test_nothing_unreadable_is_touched(emitted):
    """UNKNOWN is never changed: the setting was never read, so a change is
    unverifiable and cannot be rolled back meaningfully."""
    da, em = emitted
    changed = {c.control_id for c in em.changes}
    for f in da.assessment.findings:
        if f.state.value in ("UNKNOWN", "PASS", "NOT_APPLICABLE"):
            assert f.control_id not in changed


@sw_only
def test_a_dead_mapping_never_produces_a_change(emitted):
    """`uuidIpsObjEnable` matches none of the 92,635 records, so the engine has
    no evidence IPS is off, and a "fix" would toggle a security service on a
    device whose state was never read.

    This used to be caught HERE, as an emitter refusal. It is now caught a
    layer earlier: the pack declares itself `exhaustive`, so a mapping that
    matches nothing leaves its field unset and the control reports UNKNOWN.
    The emitter only ever considers FAIL, so these never reach it at all --
    a better place to stop it, and the reason this no longer looks for a
    refusal.
    """
    da, em = emitted
    changed = {c.control_id for c in em.changes}
    for cid in ("NCSA-EXT-039", "NCSA-EXT-040", "NCSA-CAT-006"):
        finding = next(f for f in da.assessment.findings if f.control_id == cid)
        assert finding.state.value == "UNKNOWN", (
            f"{cid} rules {finding.state.value} on a field no record populates")
        assert cid not in changed


@sw_only
def test_every_refusal_states_a_reason(emitted):
    _da, em = emitted
    assert em.refused
    assert all(r.reason.strip() for r in em.refused)


def test_the_exp_envelope_is_the_inverse_of_the_reader():
    """SonicOS ingests base64 of the settings blob. The emitter works on the
    DECODED text, so shipping that text would hand an operator the right
    settings in a form the appliance does not accept."""
    import base64

    from ncsa.engine.emit import as_exp, roundtrip_ok
    from ncsa.readers.sonicos_exp import loads

    text = "shortProdName=NSA+3700&minPasswordLength=15&allowHttpMgmt=off"
    blob = as_exp(text)
    assert base64.b64decode(blob, validate=True).decode("utf-8") == text
    assert roundtrip_ok(text)
    # and our own reader reads the decoded form back
    doc = loads(base64.b64decode(blob).decode("utf-8"), redact=False)
    assert doc.values["minPasswordLength"][0] == "15"


@sw_only
def test_the_emitted_configuration_survives_a_round_trip(emitted):
    """A structural check, and the only import-shaped assurance available
    without the hardware: if our reader cannot read back what we wrote, no
    appliance will either."""
    import base64

    from ncsa.engine.emit import as_exp, roundtrip_ok
    from ncsa.readers.sonicos_exp import loads

    _da, em = emitted
    assert roundtrip_ok(em.text)
    doc = loads(base64.b64decode(as_exp(em.text)).decode("utf-8"), redact=False)
    assert doc.total_records == 92635
    for change in em.changes:
        assert doc.values[change.key][0] == change.after


@sw_only
def test_the_gain_is_measured_not_predicted(emitted):
    """The emitted configuration is run back through the engine, so the number
    reported is the one the tool would give on the corrected device."""
    da, em = emitted
    result = verify(em, da, SW, assessment_id="TEST-EMIT-AFTER")
    assert result["after"]["score_pct"] > result["before"]["score_pct"]
    assert result["score_delta"] == round(
        result["after"]["score_pct"] - result["before"]["score_pct"], 1)
    # Hardening cannot RESOLVE an unknown -- there is nothing on the device to
    # correct for a setting we never read. It can, however, REVEAL one:
    # enabling HTTPS management activates NCSA-HTTPS-001, which was moot while
    # the service was off, and whose `tlsMinVersion` mapping matches no record
    # in this export. So the count may rise; it must never fall.
    assert result["after"]["states"]["UNKNOWN"] >= result["before"]["states"]["UNKNOWN"]
    assert result["after"]["states"]["FAIL"] < result["before"]["states"]["FAIL"]
