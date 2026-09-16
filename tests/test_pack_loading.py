"""A pack that will not load must never fail silently.

Observed for real, and it is the nastiest failure this codebase has produced:

    A pack referenced a derivation the running process did not have. load_pack
    raised. `load_packs` caught the exception and moved on. The SonicWall pack
    was therefore absent, the device was assessed with no pack at all, and the
    report showed 50 UNKNOWN controls instead of 20 -- with no error, no note,
    and nothing anywhere to distinguish it from a device we genuinely could not
    read.

That is the exact confusion the whole product exists to prevent: OUR failure
presented as a fact about the device. A broken pack is a bug in us, and it has
to say so.
"""
import io
import shutil
from pathlib import Path

import pytest

from ncsa.paths import resolve_packs_dir
from ncsa.pipeline import PACK_LOAD_ERRORS, load_packs


def _pack() -> Path:
    """The pack the loader actually reads.

    Tests run against a private copy of packs/ (NCSA_PACKS_DIR, set by
    conftest for the session), so breaking the repo's own file would test
    nothing. Resolved per call: the variable is set after this module loads.
    """
    return Path(resolve_packs_dir("packs")) / "sonicwall_exp.yaml"


@pytest.fixture
def restore_pack(tmp_path):
    """Break the pack, then always put it back."""
    backup = tmp_path / "pack_ok.yaml"
    shutil.copy(_pack(), backup)
    yield backup
    shutil.copy(backup, _pack())
    load_packs()          # leave the module state clean for other tests


def test_a_healthy_packs_directory_reports_no_errors():
    packs = load_packs()
    assert packs, "no packs loaded at all"
    assert PACK_LOAD_ERRORS == [], (
        f"packs failed to load: {PACK_LOAD_ERRORS}")


def test_a_broken_pack_is_reported_rather_than_swallowed(restore_pack):
    before = len(load_packs())

    with io.open(_pack(), "a", encoding="utf-8") as fh:
        fh.write("\n  this is: [not valid yaml at all\n")

    after = len(load_packs())

    assert after == before - 1, "the broken pack should not have loaded"
    assert PACK_LOAD_ERRORS, (
        "a pack that cannot load must be REPORTED -- silently dropping it "
        "gets the device assessed with no pack and no explanation")
    err = PACK_LOAD_ERRORS[0]
    assert err["pack"] == "sonicwall_exp.yaml"
    # The message must be actionable: which file, and what was wrong with it.
    assert "Error" in err["error"] or "error" in err["error"].lower()


def test_the_error_list_is_rebuilt_on_every_call(restore_pack):
    """Stale errors would be as misleading as no errors.

    The list describes the packs directory as it is now, not as it once was.
    """
    with io.open(_pack(), "a", encoding="utf-8") as fh:
        fh.write("\n  broken: [\n")
    load_packs()
    assert PACK_LOAD_ERRORS

    shutil.copy(restore_pack, _pack())
    load_packs()
    assert PACK_LOAD_ERRORS == [], "errors must clear once the pack is fixed"


def test_health_reports_pack_failures(restore_pack):
    """`ok` must go false when a pack is broken.

    A health endpoint that stays green while a platform has silently
    disappeared from the supported list is worse than none.
    """
    from fastapi.testclient import TestClient

    from ncsa.api.app import app
    client = TestClient(app)

    healthy = client.get("/health").json()
    assert healthy["ok"] is True
    assert healthy["pack_load_errors"] == []

    with io.open(_pack(), "a", encoding="utf-8") as fh:
        fh.write("\n  broken: [\n")

    sick = client.get("/health").json()
    assert sick["ok"] is False
    assert sick["pack_load_errors"], "the failure must be named, not implied"
    assert sick["pack_load_errors"][0]["pack"] == "sonicwall_exp.yaml"

    # NOTE the platform list does NOT shrink here, and that is correct:
    # `sonicwall_sonicos` is declared by two packs -- sonicwall.yaml reads the
    # CLI export and sonicwall_exp.yaml reads the .exp backup. Losing one
    # leaves the platform name present while silently removing the ability to
    # read that FORMAT. Which is precisely why the error list has to exist:
    # the platform inventory alone cannot show this failure.
    assert "sonicwall_sonicos" in sick["platforms_parsed"]
