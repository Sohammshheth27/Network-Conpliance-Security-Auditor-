"""Scheduled re-collection and drift alerts (ncsa/collect/monitor.py)."""
import importlib
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from ncsa.api import app as api_app
from ncsa.api.store import AssessmentStore
from ncsa.collect import live

RTR = Path("samples/cisco/edge-rtr-01.cfg")
PASSWORD = "Mon-Pw-9931"


class _Conn:
    def __init__(self, text):
        self.text = text

    def send_command(self, cmd, read_timeout=None):
        return self.text

    def enable(self):
        pass

    def disconnect(self):
        pass


@pytest.fixture
def env(tmp_path, monkeypatch):
    # The sample is deliberately weak (`ip ssh version 1`). The monitored device
    # starts IMPROVED (version 2) and then regresses to the sample as shipped.
    real = RTR.read_text()
    if "ip ssh version 1" not in real:
        pytest.skip("sample lacks `ip ssh version 1`")
    base = real.replace("ip ssh version 1", "ip ssh version 2")
    cmp = importlib.import_module("ncsa.diff.compare")
    hist = tmp_path / "history"
    monkeypatch.setattr(cmp.save, "__defaults__", (hist,))
    monkeypatch.setattr(cmp.history, "__defaults__", (hist,))
    monkeypatch.setattr(api_app, "_STORE", AssessmentStore(tmp_path / "data"))
    monkeypatch.setattr(api_app, "_UPLOADS", api_app._STORE.uploads)
    monkeypatch.setattr(api_app, "_MONITORS", {})
    state = {"text": base, "fail": None}

    def connect(**_):
        if state["fail"]:
            raise state["fail"]
        return _Conn(state["text"])

    monkeypatch.setattr(live, "_netmiko_connect", connect)
    return TestClient(api_app.app), state, tmp_path


def _job(c, **kw):
    body = {"host": "10.0.0.1", "platform": "cisco_iosxe_router", "username": "audit",
            "password": PASSWORD, "interval_minutes": 60, **kw}
    return c.post("/monitor", json=body)


def test_a_job_never_exposes_or_stores_the_password_in_clear(env):
    c, _, tmp = env
    r = _job(c)
    assert r.status_code == 200 and PASSWORD not in r.text
    assert "secret_blob" not in r.json()
    assert PASSWORD not in c.get("/monitor").text
    assert PASSWORD.encode() not in (tmp / "data" / "monitor.db").read_bytes()
    assert _job(c, interval_minutes=5).status_code == 422, "at least 15 minutes"


def test_drift_is_alerted_when_the_device_gets_worse(env):
    c, state, _ = env
    job = _job(c).json()["job_id"]
    first = c.post(f"/monitor/{job}/run").json()
    assert first["status"] == "ok" and first["alerts"] == 0

    state["text"] = RTR.read_text()          # back to `ip ssh version 1`
    second = c.post(f"/monitor/{job}/run").json()
    assert second["status"] == "drift"
    kinds = {a["kind"] for a in c.get("/monitor").json()["alerts"]}
    assert "control_regressed" in kinds and "score_drop" in kinds
    assert any("NCSA-SSH-002" in d for d in second["detail"])


def test_an_unreachable_device_is_an_alert_not_a_crash(env):
    c, state, _ = env
    job = _job(c).json()["job_id"]
    state["fail"] = TimeoutError("timed out")
    r = c.post(f"/monitor/{job}/run").json()
    assert r["status"] == "collection_failed"
    assert c.get("/monitor").json()["alerts"][0]["kind"] == "collection_failed"


def test_jobs_can_be_deleted(env):
    c, _, _ = env
    job = _job(c).json()["job_id"]
    assert c.delete(f"/monitor/{job}").status_code == 200
    assert c.post(f"/monitor/{job}/run").status_code == 404
