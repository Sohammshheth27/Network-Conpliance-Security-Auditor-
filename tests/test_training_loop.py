"""The training loop, end to end -- deliverable 2 and the 'Dynamic Adaptation'
the problem statement is built around.

Two journeys are proven, and neither involves a code change or a restart:

  * A STRUCTURED vendor the tool has never been taught (SONiC's JSON
    config_db, from a fixture built in the documented shape). It is refused,
    taught four mappings through the approval path, and on re-assessment it
    is assessed -- with real verdicts: two NTP servers PASS, one of two
    required syslog servers PARTIAL, a `public` SNMP community FAIL.
  * A TEXT vendor nothing recognises at all ("AcmeOS"). The first approval
    creates its pack with a signature; its next file is recognised by that
    signature and assessed.

Every test removes the packs it teaches, so the suite leaves no knowledge
behind and never changes another test's result.
"""
from ncsa.paths import resolve_packs_dir
import json
import os
from pathlib import Path

import pytest

from ncsa.engine.fingerprint import fingerprint_file
from ncsa.pipeline import assess
from ncsa.training import apply as training
from ncsa.training import build_queue

SONIC = "samples/sonic/config_db.json"
SW = r"E:\sonicwall config file.txt"


@pytest.fixture
def clean_packs(tmp_path, monkeypatch):
    """Snapshot and restore any learned packs these tests touch."""
    touched = [resolve_packs_dir() / "sonic.learned.yaml", resolve_packs_dir() / "acme_os.learned.yaml"]
    saved = {p: p.read_text(encoding="utf-8") for p in touched if p.exists()}
    for p in touched:
        p.unlink(missing_ok=True)
    monkeypatch.setattr(training, "DECISIONS_PATH", tmp_path / "decisions.jsonl")
    yield
    for p in touched:
        p.unlink(missing_ok=True)
    for p, text in saved.items():
        p.write_text(text, encoding="utf-8")


def _teach(setting, field, platform, kind="value", **new_vendor):
    r = training.approve(setting, field, platform, "test-admin",
                         registry=None, kind=kind, **new_vendor)
    assert r.accepted, f"{setting} -> {field}: {r.reason} {r.detail}"
    return r


def _state(da, cid):
    return next(f for f in da.assessment.findings if f.control_id == cid)


# ------------------------------------------------------------- SONiC (JSON)

def test_an_untaught_vendor_is_refused_with_its_structure_queued(clean_packs):
    da = assess(SONIC, redact=False, assessment_id="TEST-SONIC-0")
    assert da.supported is False
    assert "Training page" in " ".join(da.notes)
    q = {c.name: c for c in build_queue(da)}
    assert q["NTP_SERVER"].kind == "keys"
    assert set(q["NTP_SERVER"].sample_values) == {"0.debian.pool.ntp.org",
                                                   "1.debian.pool.ntp.org"}
    assert "DEVICE_METADATA.*.hostname" in q
    assert "SNMP_COMMUNITY" in q
    assert "_comment" not in q, "comment keys are not settings"


def test_a_new_vendor_cannot_be_taught_without_its_identity(clean_packs):
    r = training.approve("NTP_SERVER", "time.servers", "sonic", "test-admin",
                         registry=None, kind="keys")
    assert not r.accepted
    assert "NEW vendor" in r.reason
    assert not (resolve_packs_dir() / "sonic.learned.yaml").exists(), "a refusal must write nothing"


@pytest.mark.parametrize("platform,reader,sig,expect", [
    ("Bad Name", "json", ["$.X"], "platform id"),
    ("unknown", "json", ["$.X"], "platform id"),
    ("acme_os", "yaml", ["^AcmeOS version"], "file format"),
    ("acme_os", "indented", [], "signature is required"),
    ("acme_os", "indented", ["^ssh"], "too short"),
    ("acme_os", "indented", ["^Acme(OS"], "not a valid regular expression"),
    ("sonic", "json", ["DEVICE_METADATA"], "must be a JSONPath"),
])
def test_new_vendor_details_are_validated(clean_packs, platform, reader, sig, expect):
    r = training.approve("x", "device.hostname", platform, "test-admin", registry=None,
                         vendor="Acme", reader=reader, signature=sig)
    assert not r.accepted and expect in r.reason


def test_a_json_mapping_uses_jsonpath_not_path():
    """The existing writer emitted `path:` for JSON, which the reader ignores."""
    e = training._mapping_entry("SNMP_COMMUNITY", "snmp.communities", "json", kind="keys")
    assert e == {"field": "snmp.communities", "jsonpath": "$.SNMP_COMMUNITY",
                 "value": {"from": "keys"}}
    assert training._jsonpath("MY-TABLE.*.x-y") == "$.'MY-TABLE'.*.'x-y'"


def test_teaching_sonic_makes_it_assessable_with_real_verdicts(clean_packs):
    new = dict(vendor="SONiC", reader="json", signature=["$.DEVICE_METADATA"])
    _teach("DEVICE_METADATA.*.hostname", "device.hostname", "sonic", **new)
    _teach("NTP_SERVER", "time.servers", "sonic", kind="keys")
    _teach("SYSLOG_SERVER", "logging.servers", "sonic", kind="keys")
    _teach("SNMP_COMMUNITY", "snmp.communities", "sonic", kind="keys")

    da = assess(SONIC, redact=False, assessment_id="TEST-SONIC-1")
    assert da.supported is True
    obs = da.sbm.observations
    assert obs["device.hostname"].value == "sonic-lab-01"
    assert sorted(obs["time.servers"].value) == ["0.debian.pool.ntp.org",
                                                 "1.debian.pool.ntp.org"]
    assert _state(da, "NCSA-EXT-027").state.value == "PASS"     # two time sources
    # One of the two required syslog servers is PARTIAL by the engine's own
    # definition of min_count -- genuinely half met, neither pass nor fail.
    assert _state(da, "NCSA-LOG-002").state.value == "PARTIAL"
    assert _state(da, "NCSA-SNMP-002").state.value == "FAIL"    # `public` community
    # Every verdict cites the file it came from.
    assert _state(da, "NCSA-SNMP-002").evidence


def test_a_taught_domain_decides_and_the_rest_stay_unknown(clean_packs):
    """Teaching four settings must not make the device look fully assessed."""
    new = dict(vendor="SONiC", reader="json", signature=["$.DEVICE_METADATA"])
    _teach("NTP_SERVER", "time.servers", "sonic", kind="keys", **new)
    da = assess(SONIC, redact=False, assessment_id="TEST-SONIC-2")
    cov = da.coverage()
    assert cov["controls_decided"] >= 1
    assert cov["controls_undecided"] > cov["controls_decided"]


def test_approved_settings_are_marked_and_rejected_ones_leave(clean_packs):
    new = dict(vendor="SONiC", reader="json", signature=["$.DEVICE_METADATA"])
    _teach("NTP_SERVER", "time.servers", "sonic", kind="keys", **new)
    training.reject("SNMP.*.Location", "sonic", "test-admin", "not security")
    da = assess(SONIC, redact=False, assessment_id="TEST-SONIC-3")
    q = {c.name: c for c in build_queue(da)}
    assert "SNMP.*.Location" not in q
    assert q.get("NTP_SERVER") is None or q["NTP_SERVER"].status == "APPROVED"


def test_learned_summary_counts_what_was_taught(clean_packs):
    new = dict(vendor="SONiC", reader="json", signature=["$.DEVICE_METADATA"])
    _teach("NTP_SERVER", "time.servers", "sonic", kind="keys", **new)
    s = training.learned_summary()
    sonic = next(p for p in s["platforms"] if p["platform"] == "sonic")
    assert sonic["new_vendor"] and sonic["count"] == 1
    assert sonic["mappings"][0]["approved_by"] == "test-admin"


# ------------------------------------------------------------ AcmeOS (text)

ACME = """AcmeOS Firewall Software version 4.2.1
hostname edge-acme-01
ssh idle-timeout 300
ntp server 10.1.1.1
ntp server 10.1.1.2
"""


def test_an_unknown_text_vendor_is_taught_from_scratch(clean_packs, tmp_path):
    cfg = tmp_path / "acme.cfg"
    cfg.write_text(ACME, encoding="utf-8")
    assert fingerprint_file(cfg).platform == "UNKNOWN"

    da = assess(cfg, redact=False, assessment_id="TEST-ACME-0")
    assert da.supported is False
    names = {c.name for c in build_queue(da)}
    assert "ssh idle-timeout" in names

    _teach("ssh idle-timeout", "management.ssh.timeout", "acme_os",
           vendor="Acme", reader="indented",
           signature=[r"^AcmeOS Firewall Software version"])

    # The NEXT file from this vendor is recognised by its taught signature.
    fp = fingerprint_file(cfg)
    assert fp.platform == "acme_os" and "taught signature" in fp.matched[0]

    da2 = assess(cfg, redact=False, assessment_id="TEST-ACME-1")
    assert da2.supported is True
    obs = da2.sbm.observations["management.ssh.timeout"]
    assert obs.value == 300
    assert obs.evidence[0].line == 3, "the learned value must cite its line"


def test_a_taught_signature_never_captures_a_known_vendor(clean_packs, tmp_path):
    """Built-in signatures are consulted first; a taught one only as a fallback."""
    _teach("ssh idle-timeout", "management.ssh.timeout", "acme_os",
           vendor="Acme", reader="indented", signature=[r"^hostname\s+\S+"])
    assert fingerprint_file("samples/cisco/edge-rtr-01.cfg").platform == "cisco_iosxe_router"


# -------------------------------------------------------------------- API

@pytest.fixture
def client():
    from fastapi.testclient import TestClient

    from ncsa.api.app import app
    return TestClient(app)


def _upload(client, path, name):
    with open(path, "rb") as fh:
        return client.post("/assess?redact=false",
                           files={"files": (name, fh)}).json()[0]["assessment_id"]


def test_api_teaches_sonic_and_reassesses(clean_packs, client):
    aid = _upload(client, SONIC, "config_db.json")
    ctx = client.get(f"/assessment/{aid}/training/context").json()
    assert ctx["has_pack"] is False and ctx["platform"] == "sonic"
    assert ctx["suggested_signature"] == ["$.DEVICE_METADATA"]

    body = {"setting_name": "SNMP_COMMUNITY", "field": "snmp.communities",
            "platform": "sonic", "approved_by": "test-admin", "kind": "keys",
            "assessment_id": aid, "vendor": "SONiC", "reader": "json",
            "signature": ["$.DEVICE_METADATA"]}
    r = client.post("/training/approve", json=body).json()
    assert r["accepted"], r

    after = client.post(f"/assessment/{aid}/reassess").json()
    assert after["supported"] is True
    snmp = next(f for f in after["findings"] if f["control_id"] == "NCSA-SNMP-002")
    assert snmp["state"] == "FAIL"


def test_api_refuses_a_signature_that_does_not_match_its_own_file(clean_packs, client):
    aid = _upload(client, SONIC, "config_db.json")
    body = {"setting_name": "NTP_SERVER", "field": "time.servers", "platform": "sonic",
            "approved_by": "test-admin", "kind": "keys", "assessment_id": aid,
            "vendor": "SONiC", "reader": "json", "signature": ["$.NOT_A_TABLE"]}
    r = client.post("/training/approve", json=body).json()
    assert not r["accepted"] and "own file" in r["reason"]
    assert not (resolve_packs_dir() / "sonic.learned.yaml").exists()


def test_api_refuses_a_signature_that_captures_another_vendor(clean_packs, client, tmp_path):
    cfg = tmp_path / "acme.cfg"
    cfg.write_text(ACME, encoding="utf-8")
    aid = _upload(client, cfg, "acme.cfg")
    body = {"setting_name": "ssh idle-timeout", "field": "management.ssh.timeout",
            "platform": "acme_os", "approved_by": "test-admin", "assessment_id": aid,
            "vendor": "Acme", "reader": "indented", "signature": [r"^hostname\s+\S+"]}
    r = client.post("/training/approve", json=body).json()
    assert not r["accepted"] and "too generic" in r["reason"]


def test_api_locks_a_recognised_platform_id(clean_packs, client):
    aid = _upload(client, SONIC, "config_db.json")
    body = {"setting_name": "NTP_SERVER", "field": "time.servers",
            "platform": "my_sonic", "approved_by": "test-admin", "kind": "keys",
            "assessment_id": aid, "vendor": "SONiC", "reader": "json",
            "signature": ["$.DEVICE_METADATA"]}
    r = client.post("/training/approve", json=body).json()
    assert not r["accepted"] and "'sonic'" in r["reason"]


def test_schema_fields_name_the_controls_they_drive(client):
    fields = {f["field"]: f for f in client.get("/schema/fields").json()}
    assert "NCSA-SNMP-002" in fields["snmp.communities"]["controls"]
    assert fields["time.servers"]["type"] == "list"


# ------------------------------------------------------------- isolation

@pytest.mark.skipif(not os.path.exists(SW), reason="SonicWall sample absent")
def test_teaching_another_vendor_leaves_the_sonicwall_untouched(clean_packs):
    new = dict(vendor="SONiC", reader="json", signature=["$.DEVICE_METADATA"])
    _teach("NTP_SERVER", "time.servers", "sonic", kind="keys", **new)
    cov = assess(SW, redact=False, assessment_id="TEST-SW-ISO").coverage()
    assert (cov["score_pct"], cov["assessed_pct"]) == (41.3, 68.7)
