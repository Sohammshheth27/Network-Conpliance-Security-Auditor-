"""Keep tests out of the product's audit trail.

`reference/approved_mappings.jsonl` is hash-chained and committed: it is the
record of who approved which mapping. Tests exercise the approval endpoint, and
before this fixture every run appended `test-admin` / `api-test` approvals to
the real file -- fabricated entries in a log auditors are told to trust.
Each test now gets its own empty log and decisions file.
"""
import os
import shutil

import pytest


@pytest.fixture(scope="session", autouse=True)
def _session_packs(tmp_path_factory):
    """A private copy of packs/ for the whole run.

    Approval tests WRITE `<platform>.learned.yaml`. Against the real packs/
    that meant a test could leave a pack behind (it did: sonic.learned.yaml),
    and two concurrent runs read each other's half-written files as YAML
    errors. The engine resolves the default packs directory through
    NCSA_PACKS_DIR (ncsa/paths.py), so every read and write goes here.
    """
    d = tmp_path_factory.mktemp("packs")
    for f in os.listdir("packs"):
        if f.endswith(".yaml") and not f.endswith(".learned.yaml"):
            shutil.copy2(os.path.join("packs", f), d / f)
    prev = os.environ.get("NCSA_PACKS_DIR")
    os.environ["NCSA_PACKS_DIR"] = str(d)
    yield d
    if prev is None:
        os.environ.pop("NCSA_PACKS_DIR", None)
    else:
        os.environ["NCSA_PACKS_DIR"] = prev


@pytest.fixture(scope="session")
def _session_store(tmp_path_factory):
    """One assessment store per test run, in a temp directory. Session-scoped
    because some tests assess a file once and query it from later tests."""
    from ncsa.api.store import AssessmentStore

    return AssessmentStore(tmp_path_factory.mktemp("ncsa_data"))


@pytest.fixture(autouse=True)
def _isolated_audit_logs(tmp_path, monkeypatch, _session_store):
    from ncsa.api import app as api_app
    from ncsa.training import apply as training_apply

    monkeypatch.setattr(api_app, "APPROVALS_LOG", tmp_path / "approved_mappings.jsonl")
    monkeypatch.setattr(training_apply, "DECISIONS_PATH", tmp_path / "decisions.jsonl")
    # Never write uploaded configs or the assessment database to ./data.
    monkeypatch.setattr(api_app, "_STORE", _session_store)
    monkeypatch.setattr(api_app, "_UPLOADS", _session_store.uploads)
