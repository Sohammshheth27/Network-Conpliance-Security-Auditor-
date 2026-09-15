"""Keep tests out of the product's audit trail.

`reference/approved_mappings.jsonl` is hash-chained and committed: it is the
record of who approved which mapping. Tests exercise the approval endpoint, and
before this fixture every run appended `test-admin` / `api-test` approvals to
the real file -- fabricated entries in a log auditors are told to trust.
Each test now gets its own empty log and decisions file.
"""
import pytest


@pytest.fixture(autouse=True)
def _isolated_audit_logs(tmp_path, monkeypatch):
    from ncsa.api import app as api_app
    from ncsa.training import apply as training_apply

    monkeypatch.setattr(api_app, "APPROVALS_LOG", tmp_path / "approved_mappings.jsonl")
    monkeypatch.setattr(training_apply, "DECISIONS_PATH", tmp_path / "decisions.jsonl")
