"""Assessments survive a restart (ncsa/api/store.py).

A restart is simulated by building a NEW store over the same data directory:
the in-memory results are gone, exactly as after a process kill.
"""
from pathlib import Path

import pytest

from ncsa.api.store import AssessmentStore
from ncsa.pipeline import assess

RTR = Path("samples/cisco/edge-rtr-01.cfg")


def _store_one(store, aid="abc123def456", redact=True, fws=None):
    dest = store.new_upload_path(RTR.name, aid)
    dest.write_text(RTR.read_text())
    da = assess(dest, redact=redact, assessment_id=aid, frameworks=fws)
    store.put(aid, da, dest, name=RTR.name, redact=redact, frameworks=fws)
    return da


def test_the_upload_keeps_its_real_name(tmp_path):
    s = AssessmentStore(tmp_path)
    p = s.new_upload_path("edge-rtr-01.cfg", "u1")
    assert p.name == "edge-rtr-01.cfg"


def test_an_assessment_survives_a_restart_with_identical_results(tmp_path):
    before = _store_one(AssessmentStore(tmp_path), fws=["stig"])

    after = AssessmentStore(tmp_path)                 # the restart
    assert "abc123def456" in after
    assert after.summaries()[0]["score_pct"] == before.coverage()["score_pct"]
    da, path = after["abc123def456"]                  # rebuilt on access
    assert da.coverage() == before.coverage()
    assert da.frameworks == ["stig"], "the options come back too"
    assert after.meta("abc123def456")["redact"] is True


def test_a_record_whose_file_is_gone_is_a_clean_miss(tmp_path):
    s = AssessmentStore(tmp_path)
    _store_one(s)
    (s.uploads / "abc123def456" / RTR.name).unlink()
    fresh = AssessmentStore(tmp_path)
    with pytest.raises(KeyError):
        fresh["abc123def456"]


def test_the_api_serves_an_assessment_made_before_the_restart(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    from ncsa.api import app as api_app

    s = AssessmentStore(tmp_path)
    monkeypatch.setattr(api_app, "_STORE", s)
    c = TestClient(api_app.app)
    with open(RTR, "rb") as fh:
        aid = c.post("/assess", files={"files": (RTR.name, fh)}).json()[0]["assessment_id"]

    monkeypatch.setattr(api_app, "_STORE", AssessmentStore(tmp_path))   # restart
    assert aid in [a["assessment_id"] for a in c.get("/assessments").json()]
    body = c.get(f"/assessment/{aid}").json()
    assert body["identity"]["source_file"] == RTR.name, "no random prefix"
    assert c.get("/assessment/nope").status_code == 404
