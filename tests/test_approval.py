"""The approval gate.

An approval is the only way a human decision changes what the tool reports, so
it is the one path where a mistake becomes permanent and invisible. Poisoning
always makes things look BETTER -- a wrong mapping does not crash, it quietly
converts failures into passes forever. These tests pin the four properties
that stop that.
"""
from pathlib import Path

import pytest

from ncsa.training import apply as ap
from ncsa.training.apply import (ApprovalResult, _mapping_entry, approve,
                                 learned_path, revert_learned, write_learned)


@pytest.fixture(autouse=True)
def _clean():
    yield
    for p in Path("packs").glob("*.learned.yaml"):
        p.unlink(missing_ok=True)


# ------------------------------------------------------------ cheap refusals
def test_field_must_be_in_the_schema_whitelist():
    r = approve("someSetting", "not.a.real.field", "cisco_asa", "sohamm")
    assert not r.accepted and "whitelist" in r.reason


def test_an_approval_must_record_who_made_it():
    r = approve("someSetting", "logging.enabled", "cisco_asa", "")
    assert not r.accepted and "who made it" in r.reason


def test_unknown_platform_is_refused():
    r = approve("x", "logging.enabled", "no_such_platform", "sohamm")
    assert not r.accepted and "no pack" in r.reason


# ------------------------------------------------- the generated mapping
def test_line_reader_mapping_captures_the_value_it_coerces():
    """A generated `^console timeout\b` with `as: int` and no capture group
    made the extractor fall back to the whole line and coerce
    "console timeout 0" to an integer -- UNPARSED, on the very setting the
    approval claimed to teach."""
    e = _mapping_entry("console timeout", "management.console.exec_timeout",
                       "indented")
    assert "(" in e["regex"], "a typed field needs a capture group"
    assert e["value"]["group"] == 1
    assert e["value"]["as"] == "int"


def test_bool_field_uses_presence_not_a_capture():
    e = _mapping_entry("service password-encryption",
                       "authentication.password_encryption", "indented")
    assert e["value"] == {"const": True}


def test_path_reader_addresses_by_name():
    e = _mapping_entry("cli_idleTimeout", "management.ssh.timeout",
                       "sonicos_exp")
    assert e["path"] == "cli_idleTimeout" and "regex" not in e


# ---------------------------------------------------- learned pack merging
def test_a_learned_mapping_never_replaces_an_authored_one():
    """A later mapping overwrites an earlier one for the same field, so simply
    appending let an approval silently degrade a hand-written mapping."""
    from ncsa.pipeline import load_packs

    base = next(p for p in load_packs() if p.platform == "cisco_asa")
    authored_kex = [m for m in base.mappings
                    if m.field == "management.ssh.kex"][0].regex

    approve("ssh key-exchange group", "management.ssh.kex", "cisco_asa", "t")
    after = next(p for p in load_packs() if p.platform == "cisco_asa")
    kex = [m for m in after.mappings if m.field == "management.ssh.kex"]
    assert len(kex) == 1, "the authored mapping must survive alone"
    assert kex[0].regex == authored_kex


def test_deleting_the_learned_file_restores_prior_behaviour():
    from ncsa.pipeline import load_packs

    before = len(next(p for p in load_packs()
                      if p.platform == "cisco_asa").mappings)
    approve("logging enable", "logging.enabled", "cisco_asa", "t")
    learned_path("cisco_asa").unlink(missing_ok=True)
    after = len(next(p for p in load_packs()
                     if p.platform == "cisco_asa").mappings)
    assert after == before


# --------------------------------------------------------- the actual gate
def test_a_blocked_approval_leaves_nothing_behind(monkeypatch):
    """Otherwise the gate itself becomes a way to poison the tool: a refused
    approval that still wrote its mapping would apply without being recorded."""
    real = ap.corpus_snapshot
    calls = {"n": 0}

    def fake():
        calls["n"] += 1
        # First call is BEFORE, second is AFTER. Flip a verified FAIL to PASS.
        if calls["n"] == 1:
            return {"cisco-asa-real": {"NCSA-TEL-001": "PASS"}}
        return {"cisco-asa-real": {"NCSA-TEL-001": "FAIL"}}

    monkeypatch.setattr(ap, "corpus_snapshot", fake)
    monkeypatch.setattr(ap, "_verified_expectations",
                        lambda: {"cisco-asa-real": {"NCSA-TEL-001": "PASS"}})

    r = approve("telnet timeout", "management.telnet.enabled", "cisco_asa", "t")
    assert not r.accepted
    assert r.broken == ["cisco-asa-real:NCSA-TEL-001"]
    assert "Nothing was written" in r.reason
    assert not learned_path("cisco_asa").exists(), "the write must be reverted"
    ap.corpus_snapshot = real


def test_a_rising_pass_rate_is_flagged_even_when_nothing_breaks(monkeypatch):
    """Poisoning always makes things look better."""
    calls = {"n": 0}

    def fake():
        calls["n"] += 1
        if calls["n"] == 1:
            return {"c": {"A": "FAIL", "B": "FAIL"}}
        return {"c": {"A": "PASS", "B": "FAIL"}}

    monkeypatch.setattr(ap, "corpus_snapshot", fake)
    monkeypatch.setattr(ap, "_verified_expectations", lambda: {"c": {"B": "FAIL"}})

    r = approve("x", "logging.enabled", "cisco_asa", "t")
    assert r.accepted           # nothing verified broke
    assert r.direction_alert    # ...but it is reported anyway
    assert r.pass_rate_after > r.pass_rate_before


def test_revert_removes_a_file_that_did_not_exist_before():
    learned_path("cisco_asa").unlink(missing_ok=True)
    snap = write_learned("cisco_asa", "x", "logging.enabled", "indented", "t")
    assert learned_path("cisco_asa").exists()
    revert_learned(snap)
    assert not learned_path("cisco_asa").exists()


def test_a_good_approval_actually_changes_parsing():
    """An approval that does not alter what the device reports is theatre --
    and it was: registry entries changed nothing because no reader read them."""
    import hashlib

    from ncsa.pipeline import load_packs
    from ncsa.readers import apply_indented_pack, load_indented

    import os
    if not os.path.exists(r"E:\ASA.txt"):
        pytest.skip("ASA sample absent")

    r = approve("aaa authentication login-history",
                "logging.command_accounting", "cisco_asa", "t")
    assert r.accepted, r.reason
    pack = next(p for p in load_packs() if p.platform == "cisco_asa")
    sbm = apply_indented_pack(load_indented(r"E:\ASA.txt"), pack,
                              assessment_id="t", sha256="x")
    obs = sbm.get("logging.command_accounting")
    assert obs is not None
