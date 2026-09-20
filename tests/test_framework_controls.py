"""What a cited identifier means -- and what we are allowed to say about it.

"AU-2" tells an operator nothing, so the console resolves identifiers through
/framework-controls. The interesting part is not the lookup, it is the licence:
NIST and DISA STIG are public domain and may carry their published titles, while
CIS and ISO are identifier-only. Their prose sits in the local catalogue -- we
parse it to find the recommendation at all -- and it must never leave this
process in a report, a page or a log.

So these tests assert the boundary, not the plumbing: a public-domain title
comes back, and an identifier-only framework comes back WITHOUT the title that
the catalogue demonstrably holds for the same entry.
"""
import pytest
from fastapi.testclient import TestClient

from ncsa.api.app import app

client = TestClient(app)


def _controls(framework: str, ids: str) -> dict:
    r = client.get(f"/framework-controls?framework={framework}&ids={ids}")
    assert r.status_code == 200, r.text
    return r.json()["controls"]


def test_a_public_domain_control_carries_its_title():
    got = _controls("nist_800_53", "AU-2,AC-4")
    assert got["AU-2"] == "AU-2: Event Logging"
    assert "Information Flow" in (got["AC-4"] or "")


def test_a_stig_rule_carries_its_title():
    got = _controls("disa_stig", "V-239912")
    assert got["V-239912"] and got["V-239912"].startswith("V-239912:")


def test_an_identifier_only_framework_never_returns_its_prose():
    """The catalogue holds the ISO title; the API must not hand it out."""
    from ncsa.frameworks.models import Framework
    from ncsa.frameworks.registry import load_all

    cat = load_all("reference").catalogs[Framework.ISO_27001]
    entry = next((e for e in cat.entries
                  if e.id.startswith("A.") and (e.title or "").strip()), None)
    if entry is None:
        pytest.skip("no titled ISO entry in this catalogue build")

    got = _controls("iso_27001_2022", entry.id)[entry.id]
    assert got and entry.id in got, "the identifier itself must come back"
    assert entry.title not in got, (
        f"ISO prose leaked through the API: {got!r} contains the published "
        f"title {entry.title!r}, which this project may cite by number only")


def test_cis_is_identifier_only_too():
    from ncsa.frameworks.models import Framework
    from ncsa.frameworks.registry import load_all

    cat = load_all("reference").catalogs[Framework.CIS]
    entry = next((e for e in cat.entries if (e.title or "").strip()), None)
    if entry is None:
        pytest.skip("no titled CIS entry in this catalogue build")

    got = _controls("cis", entry.id)[entry.id]
    assert got and entry.id in got
    assert entry.title not in got, "CIS prose must never reach a caller"


def test_an_unknown_id_is_null_rather_than_a_guess():
    got = _controls("nist_800_53", "AU-2,NOT-A-CONTROL")
    assert got["AU-2"], "the real one still resolves"
    assert got["NOT-A-CONTROL"] is None, (
        "an unresolvable id must be reported as unknown so the page shows the "
        "bare identifier instead of inventing a description")


def test_an_unknown_framework_is_refused():
    r = client.get("/framework-controls?framework=nonsense&ids=AU-2")
    assert r.status_code == 422 and "unknown framework" in r.text


def test_no_ids_is_an_empty_answer_not_an_error():
    r = client.get("/framework-controls?framework=nist_800_53&ids=")
    assert r.status_code == 200 and r.json()["controls"] == {}
