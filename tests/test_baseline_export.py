"""The Security Baseline Model as JSON.

The machine-readable counterpart to the PDF report. Where the report is read by
a person, this is consumed by a pipeline -- which makes one property
load-bearing above all others:

    EVERY FIELD CARRIES ITS OBSERVATION STATE.

`management.telnet.enabled: false` is a different fact depending on whether we
READ it off the device, assumed it from a platform default, or never found it.
A consumer that sees only the value will draw conclusions the engine refused to
draw, so the state is mandatory on every entry and the document explains the
states inline rather than assuming the reader has seen the documentation.
"""
import json
import os

import pytest

from ncsa.pipeline import assess
from ncsa.schema.export import STATE_MEANING, baseline

SW = r"E:\sonicwall config file.txt"
sw_only = pytest.mark.skipif(not os.path.exists(SW), reason="SonicWall sample absent")


@pytest.fixture(scope="module")
def sw():
    da = assess(SW, redact=False, assessment_id="TEST-SBM")
    return da, baseline(da, "TEST-SBM")


@sw_only
def test_the_document_is_valid_json(sw):
    _da, d = sw
    round_tripped = json.loads(json.dumps(d, default=str))
    assert round_tripped["device"]["hostname"] == d["device"]["hostname"]


@sw_only
def test_the_device_is_identified(sw):
    da, d = sw
    dev = d["device"]
    assert dev["hostname"] == da.identity.hostname
    assert dev["serial"] == da.identity.serial
    assert dev["model"] == da.identity.model
    assert d["source"]["sha256"] == da.identity.sha256, (
        "the digest ties this document to the exact file assessed")


@sw_only
def test_every_figure_matches_the_engine(sw):
    """The export must never drift from the assessment it claims to describe."""
    da, d = sw
    assert d["coverage"] == da.coverage()
    assert d["source"]["records"] == da.total_records
    assert len(d["findings"]) == sum(da.counts().values())


@sw_only
def test_every_field_carries_an_observation_state(sw):
    """A bare value would be a lie by omission.

    This is the property that separates the export from a config dump: it says
    not just what the value is, but what kind of knowledge it represents.
    """
    _da, d = sw
    fields = d["baseline"]["fields"]
    assert fields, "expected a populated baseline"
    for path, entry in fields.items():
        assert "state" in entry, f"{path} has no observation state"
        assert entry["state"] in STATE_MEANING, (
            f"{path} has unknown state {entry['state']!r}")


@sw_only
def test_the_document_explains_its_own_states(sw):
    """A consumer must not need the documentation to read this correctly."""
    _da, d = sw
    meanings = d["schema"]["observation_states"]
    for state in ("OBSERVED", "DEFAULT_ASSUMED", "NOT_OBSERVED", "UNPARSED"):
        assert state in meanings and len(meanings[state]) > 30
    assert "cannot support a finding" in meanings["DEFAULT_ASSUMED"], (
        "an assumed value must be marked as unable to carry a finding")


@sw_only
def test_an_observed_value_cites_the_setting_it_came_from(sw):
    """Vendor syntax is recorded as EVIDENCE, not as structure.

    That is what lets `management.ssh.timeout` mean the same thing across
    platforms while remaining checkable against this device.
    """
    _da, d = sw
    observed = [(p, e) for p, e in d["baseline"]["fields"].items()
                if e["state"] == "OBSERVED"]
    assert observed, "expected observed fields"
    with_evidence = [(p, e) for p, e in observed if e["evidence"]]
    assert len(with_evidence) > len(observed) // 2, (
        "most observed values should name the configuration setting behind them")

    _path, entry = with_evidence[0]
    ev = entry["evidence"][0]
    assert ev["raw"], "evidence must quote the setting"
    assert ev["line"] is not None or ev["record"], (
        "evidence must be locatable by line or record position")


@sw_only
def test_scoped_instances_are_preserved_not_collapsed(sw):
    """A firewall has many rules, and each is a separate object.

    Collapsing them to one `firewall.rules.action` would discard which rule
    was which -- and the whole point of a per-rule finding is that it names
    the rule.
    """
    _da, d = sw
    scoped = [k for k in d["baseline"]["fields"] if "[" in k]
    assert len(scoped) > 100, "expected per-rule and per-interface instances"
    assert any(k.startswith("firewall.rules[") for k in scoped)


@sw_only
def test_findings_carry_their_framework_references(sw):
    _da, d = sw
    with_refs = [f for f in d["findings"]
                 if f["frameworks"]["nist_800_53"] or f["frameworks"]["iso_27001"]]
    assert with_refs, "findings should carry framework provenance"


def test_an_unassessable_file_exports_no_baseline():
    """A file we could not read must not produce a baseline that looks real."""
    from ncsa.pipeline import DeviceAssessment, DeviceIdentity

    da = DeviceAssessment(
        identity=DeviceIdentity(source_file="encrypted.exp", sha256="a" * 64),
        supported=False, notes=["The backup is encrypted."])
    d = baseline(da, "TEST-REFUSED")
    assert d["assessment"]["supported"] is False
    assert d["baseline"]["fields_populated"] == 0
    assert d["coverage"] is None, (
        "a coverage figure for an unreadable file would be fabricated")
    assert d["assessment"]["notes"], "the refusal must state its reason"


@sw_only
def test_the_pipeline_retains_the_model_it_evaluated(sw):
    """The export must describe the SAME model the findings came from.

    It used to be discarded after evaluation and rebuilt on demand by
    re-parsing the file, which can silently diverge from the parse that
    actually produced the findings.
    """
    da, _d = sw
    assert da.sbm is not None
    assert da.sbm.source_sha256 == da.identity.sha256
