"""Framework scores over time, and the report scoped to one framework."""
from pathlib import Path

from ncsa.diff.compare import Snapshot, compare, snapshot
from ncsa.pipeline import assess

RTR = Path("samples/cisco/edge-rtr-01.cfg")


def test_a_snapshot_records_each_frameworks_score():
    s = snapshot(assess(str(RTR), redact=False, assessment_id="T-HIST"))
    assert set(s.frameworks) == {"cis", "nist_800_53", "stig", "iso_27001"}
    assert s.to_json()["frameworks"] == s.frameworks


def test_an_old_snapshot_without_framework_scores_still_loads_and_compares():
    new = snapshot(assess(str(RTR), redact=False, assessment_id="T-HIST2"))
    old_json = new.to_json()
    old_json.pop("frameworks")
    old = Snapshot.from_json(old_json)
    rep = compare(old, new)
    assert rep.framework_scores == {}, "a missing score is not a zero"


def test_the_diff_reports_how_each_framework_moved():
    a = snapshot(assess(str(RTR), redact=False, assessment_id="T-HIST3"))
    b = Snapshot.from_json({**a.to_json(),
                            "frameworks": {**a.frameworks, "nist_800_53": 99.9}})
    rep = compare(a, b)
    assert rep.framework_scores["nist_800_53"] == [a.frameworks["nist_800_53"], 99.9]
    assert "nist_800_53 score" in rep.explain()
    assert rep.summary()["frameworks"]["nist_800_53"][1] == 99.9


def _client():
    from fastapi.testclient import TestClient
    from ncsa.api.app import app
    return TestClient(app)


def test_history_and_scoped_report_over_the_api(tmp_path, monkeypatch):
    import importlib

    # `ncsa.diff` re-exports a function named `compare`, which shadows the
    # submodule in `import ncsa.diff.compare as ...`.
    cmp = importlib.import_module("ncsa.diff.compare")

    # `save` and `history` bind their store as a default argument, so the
    # module variable alone is not enough -- redirect both BEFORE any call,
    # or the test reads (and writes) the real change history.
    store = tmp_path / "history"
    monkeypatch.setattr(cmp, "STORE", store)
    monkeypatch.setattr(cmp.save, "__defaults__", (store,))
    monkeypatch.setattr(cmp.history, "__defaults__", (store,))

    c = _client()
    with open(RTR, "rb") as fh:
        aid = c.post("/assess?redact=false", files={"files": (RTR.name, fh)}).json()[0]["assessment_id"]

    assert c.get(f"/assessment/{aid}/history").json() == [], "viewing never records"
    assert c.post(f"/assessment/{aid}/snapshot").status_code == 200
    hist = c.get(f"/assessment/{aid}/history").json()
    assert len(hist) == 1 and "stig" in hist[0]["frameworks"]

    html = c.get(f"/assessment/{aid}/report?format=html&framework=stig").text
    assert "DISA STIG" in " ".join(html.split())
    assert c.get(f"/assessment/{aid}/report?format=html&framework=nope").status_code == 422
