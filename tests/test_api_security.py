"""Who may call the API (ncsa/api/app.py, the security middleware).

/collect carries device credentials and every upload is a customer
configuration, so the API no longer answers anyone from anywhere.
"""
import pytest
from fastapi.testclient import TestClient

from ncsa.api.app import app


def test_with_a_token_every_api_call_needs_it(monkeypatch):
    monkeypatch.setenv("NCSA_API_TOKEN", "s3cret-token")
    c = TestClient(app)
    assert c.get("/assessments").status_code == 401
    assert c.get("/assessments", headers={"Authorization": "Bearer wrong"}).status_code == 401
    ok = c.get("/assessments", headers={"Authorization": "Bearer s3cret-token"})
    assert ok.status_code == 200


def test_public_pages_stay_public_with_a_token(monkeypatch):
    monkeypatch.setenv("NCSA_API_TOKEN", "s3cret-token")
    c = TestClient(app)
    assert c.get("/health").status_code == 200
    assert c.get("/").status_code == 200


def test_without_a_token_only_this_machine_is_answered(monkeypatch):
    monkeypatch.delenv("NCSA_API_TOKEN", raising=False)
    try:
        remote = TestClient(app, client=("10.0.0.5", 50000))
    except TypeError:
        pytest.skip("this Starlette TestClient cannot set the client address")
    r = remote.get("/assessments")
    assert r.status_code == 403 and "NCSA_API_TOKEN" in r.text
    local = TestClient(app, client=("127.0.0.1", 50000))
    assert local.get("/assessments").status_code == 200


def test_cors_allows_the_console_origin_only():
    c = TestClient(app)
    pre = {"Access-Control-Request-Method": "GET"}
    good = c.options("/assessments", headers={**pre, "Origin": "http://localhost:5173"})
    evil = c.options("/assessments", headers={**pre, "Origin": "http://evil.example"})
    assert good.headers.get("access-control-allow-origin") == "http://localhost:5173"
    assert "access-control-allow-origin" not in evil.headers
