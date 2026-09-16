"""Tamper-evident reports (ncsa/report/signing.py)."""
from fastapi.testclient import TestClient

from ncsa.report.signing import ReportSigner, verify_offline

PDF = b"%PDF-1.7\n% a report\n1 0 obj << >> endobj\n%%EOF\n"


def test_an_issued_report_verifies_and_an_edited_one_does_not(tmp_path):
    s = ReportSigner(tmp_path)
    meta = s.sign(PDF, aid="a1", framework="stig")
    ok = s.verify(PDF)
    assert ok["verdict"] == "authentic" and ok["assessment_id"] == "a1"
    assert ok["framework"] == "stig"
    edited = PDF.replace(b"a report", b"A report")
    assert s.verify(edited)["verdict"] == "unknown", "one changed byte"
    assert meta["sha256"] == ok["sha256"]


def test_anyone_can_verify_with_the_public_key_alone(tmp_path):
    s = ReportSigner(tmp_path)
    meta = s.sign(PDF, aid="a1")
    assert verify_offline(PDF, meta["signature"], s.public_pem)
    assert not verify_offline(PDF + b" ", meta["signature"], s.public_pem)


def test_the_key_survives_a_restart(tmp_path):
    meta = ReportSigner(tmp_path).sign(PDF, aid="a1")
    again = ReportSigner(tmp_path)               # a new process, same data dir
    assert again.verify(PDF)["verdict"] == "authentic"
    assert verify_offline(PDF, meta["signature"], again.public_pem)


def test_the_api_serves_the_public_key_and_verifies_uploads():
    from ncsa.api import app as api_app

    c = TestClient(api_app.app)
    pem = c.get("/report-signing-key").json()["public_key_pem"]
    assert pem.startswith("-----BEGIN PUBLIC KEY-----")
    meta = api_app._signer().sign(PDF, aid="api-1")
    good = c.post("/verify-report", files={"file": ("r.pdf", PDF)}).json()
    assert good["verdict"] == "authentic" and good["assessment_id"] == "api-1"
    bad = c.post("/verify-report", files={"file": ("r.pdf", PDF + b"x")}).json()
    assert bad["verdict"] == "unknown"
    assert verify_offline(PDF, meta["signature"], pem)
