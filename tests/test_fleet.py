"""Fleet view: every device with its framework scores, and a CSV export."""
import csv
import io
from pathlib import Path

from fastapi.testclient import TestClient

from ncsa.api import app as api_app
from ncsa.api.store import AssessmentStore

RTR = Path("samples/cisco/edge-rtr-01.cfg")
ASA = Path("samples/juniper/srx-fw-01.conf")


def _client(tmp_path, monkeypatch):
    monkeypatch.setattr(api_app, "_STORE", AssessmentStore(tmp_path))
    return TestClient(api_app.app)


def test_the_listing_carries_each_devices_framework_scores(tmp_path, monkeypatch):
    c = _client(tmp_path, monkeypatch)
    for p in (RTR, ASA):
        with open(p, "rb") as fh:
            c.post("/assess?redact=false", files={"files": (p.name, fh)})
    rows = c.get("/assessments").json()
    assert len(rows) == 2
    for r in rows:
        assert set(r["frameworks"]) == {"cis", "nist_800_53", "stig", "iso_27001"}
        assert r["platform"] and r["assessed_at"]


def test_the_fleet_csv_matches_the_listing(tmp_path, monkeypatch):
    c = _client(tmp_path, monkeypatch)
    with open(RTR, "rb") as fh:
        aid = c.post("/assess?redact=false", files={"files": (RTR.name, fh)}).json()[0]["assessment_id"]
    r = c.get("/fleet.csv")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/csv")
    rows = list(csv.DictReader(io.StringIO(r.text)))
    assert [x["assessment_id"] for x in rows] == [aid]
    listed = c.get("/assessments").json()[0]
    assert float(rows[0]["score_pct"]) == listed["score_pct"]
    assert float(rows[0]["nist_800_53_score_pct"]) == listed["frameworks"]["nist_800_53"]


def test_an_older_database_gains_the_new_columns(tmp_path):
    import sqlite3

    db = tmp_path / "assessments.db"
    with sqlite3.connect(db) as con:   # the first schema, before fleet scores
        con.execute("CREATE TABLE assessments (aid TEXT PRIMARY KEY, path TEXT NOT NULL,"
                    " name TEXT NOT NULL, redact INTEGER NOT NULL, frameworks TEXT,"
                    " created_at TEXT NOT NULL, device TEXT, vendor TEXT, platform TEXT,"
                    " supported INTEGER, score_pct REAL, assessed_pct REAL)")
        con.execute("INSERT INTO assessments VALUES ('old1','x','x.cfg',1,NULL,"
                    "'2026-09-01T00:00:00+00:00','dev','cisco','p',1,50.0,40.0)")
    rows = AssessmentStore(tmp_path).summaries()
    assert rows[0]["assessment_id"] == "old1" and rows[0]["frameworks"] == {}
