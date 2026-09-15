"""Tests must never write the committed audit trail (see conftest.py)."""
from pathlib import Path


def test_the_approval_log_under_test_is_not_the_real_one():
    from ncsa.api import app as api_app
    from ncsa.training import apply as training_apply

    real = Path("reference/approved_mappings.jsonl").resolve()
    assert Path(api_app.APPROVALS_LOG).resolve() != real
    assert Path(training_apply.DECISIONS_PATH).resolve() != \
        Path("reference/training_decisions.jsonl").resolve()
