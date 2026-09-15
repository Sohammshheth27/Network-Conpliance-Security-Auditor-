"""Known-vulnerability lookup.

Validated on the real NSA 3700 (SonicOS 7.3.0-7012-R8150) against a dated NVD
snapshot. The unit tests pin the three decisions where a CVE matcher does its
damage:

  * BOUNDARY EXCLUSIVITY -- `versionEndExcluding: 7.3.0-7012` means the fix is
    IN 7.3.0-7012. Reading it as inclusive reports a patched device as
    vulnerable.
  * HARDWARE GATING -- most SonicOS records are "version AND model". A TZ-only
    flaw must not be reported against an NSA.
  * THREE-VALUED LOGIC -- "cannot tell" stays UNKNOWN. Folding it into "not
    affected" is the direction in which a vulnerability lookup hurts people.
"""
import json
import os
from pathlib import Path

import pytest

from ncsa.extended import cve as cvemod
from ncsa.extended.cve import (PLATFORM_CPE, assess_cve, compare, match_cve,
                               version_key)
from ncsa.pipeline import assess

SW = r"E:\sonicwall config file.txt"
sw_only = pytest.mark.skipif(not os.path.exists(SW), reason="SonicWall sample absent")
SNAP = Path("reference/cve/nvd-sonicwall_sonicos.json")
snap_only = pytest.mark.skipif(not SNAP.exists(), reason="no CVE snapshot")
TARGET = PLATFORM_CPE["sonicwall_sonicos"]
DEVICE = version_key("7.3.0-7012-R8150")


def _record(bounds: dict, models=("nsa_3700",), cid="CVE-TEST-0001"):
    """A minimal NVD record: OS range AND hardware list."""
    return {"id": cid, "status": "Analyzed", "description": "test",
            "metric": {"base_score": 7.5, "base_severity": "HIGH"},
            "configurations": [{"operator": "AND", "nodes": [
                {"operator": "OR", "cpeMatch": [dict(
                    criteria="cpe:2.3:o:sonicwall:sonicos:*:*:*:*:*:*:*:*",
                    vulnerable=True, **bounds)]},
                {"operator": "OR", "cpeMatch": [
                    {"criteria": f"cpe:2.3:h:sonicwall:{m}:-:*:*:*:*:*:*:*",
                     "vulnerable": False} for m in models]}]}]}


# ------------------------------------------------------------------ versions

def test_the_device_version_parses_to_release_and_build():
    assert DEVICE == ((7, 3, 0), 7012)


@pytest.mark.parametrize("raw,key", [
    ("7.3.0-7012", ((7, 3, 0), 7012)),
    ("7.0.1-5018-r1715", ((7, 0, 1), 5018)),
    ("7.0.1-r1036", ((7, 0, 1), None)),
    ("6.5.4.4-44n", ((6, 5, 4, 4), 44)),
    ("5.9.1.0.", ((5, 9, 1, 0), None)),
    ("*", None),
])
def test_nvd_version_spellings(raw, key):
    assert version_key(raw) == key


def test_comparison_orders_release_then_build():
    assert compare(DEVICE, version_key("7.3.2-7010")) == -1
    assert compare(DEVICE, version_key("7.1.1-7040")) == 1
    assert compare(DEVICE, version_key("7.3.0-7012")) == 0
    # A bound with no build names the whole release.
    assert compare(DEVICE, version_key("7.3.0")) == 0
    # A device with no build cannot be ordered within its own release.
    assert compare(version_key("7.3.0"), version_key("7.3.0-7012")) is None


# ------------------------------------------------------------------ matching

def test_end_excluding_bound_is_exclusive():
    """CVE-2025-40600's real shape: fixed IN 7.3.0-7012."""
    rec = _record({"versionStartIncluding": "7.1.1-7040",
                   "versionEndExcluding": "7.3.0-7012"})
    assert match_cve(rec, TARGET, DEVICE, "nsa_3700")[0] is False
    older = version_key("7.2.0-7000")
    assert match_cve(rec, TARGET, older, "nsa_3700")[0] is True


def test_end_including_bound_is_inclusive():
    rec = _record({"versionEndIncluding": "7.3.0-7012"})
    assert match_cve(rec, TARGET, DEVICE, "nsa_3700")[0] is True


def test_a_tz_only_flaw_is_not_reported_against_an_nsa():
    rec = _record({"versionEndExcluding": "7.3.2-7010"}, models=("tz270", "tz370"))
    assert match_cve(rec, TARGET, DEVICE, "nsa_3700")[0] is False


def test_an_unknown_model_makes_a_hardware_gated_match_undecidable():
    rec = _record({"versionEndExcluding": "7.3.2-7010"})
    verdict, why = match_cve(rec, TARGET, DEVICE, None)
    assert verdict is None
    assert "model" in why


def test_a_record_without_affected_versions_is_undecidable_not_clean():
    rec = {"id": "CVE-TEST-2", "configurations": []}
    assert match_cve(rec, TARGET, DEVICE, "nsa_3700")[0] is None


# ------------------------------------------------------------- real device

@pytest.fixture(scope="module")
def sw():
    da = assess(SW, redact=False, assessment_id="TEST-CVE")
    return da, assess_cve(da)


@sw_only
@snap_only
def test_every_match_names_both_version_and_hardware(sw):
    _da, res = sw
    assert res.present is True
    fails = [f for f in res.findings if f.state == "FAIL"]
    assert fails, "this firmware is below the current fixed releases"
    for item in res.inventory:
        assert "nsa_3700" in item["matched_on"], (
            f"{item['id']} matched without the hardware gate")


@sw_only
@snap_only
def test_the_patched_boundary_record_is_not_reported(sw):
    """CVE-2025-40600 was fixed in exactly this build."""
    _da, res = sw
    data = json.loads(SNAP.read_text(encoding="utf-8"))
    if not any(c["id"] == "CVE-2025-40600" for c in data["cves"]):
        pytest.skip("record not in this snapshot")
    assert "CVE-2025-40600" not in {i["id"] for i in res.inventory}


@sw_only
@snap_only
def test_every_match_is_re_derivable_from_the_snapshot(sw):
    """Independent re-check: each reported CVE matches when re-evaluated."""
    _da, res = sw
    data = {c["id"]: c for c in
            json.loads(SNAP.read_text(encoding="utf-8"))["cves"]}
    for item in res.inventory:
        assert match_cve(data[item["id"]], TARGET, DEVICE, "nsa_3700")[0] is True


@sw_only
@snap_only
def test_failures_cite_the_firmware_version_setting(sw):
    _da, res = sw
    for f in res.findings:
        if f.state == "FAIL":
            assert f.evidence and f.evidence[0].raw.startswith("buildNum=")


@sw_only
@snap_only
def test_the_result_states_its_data_date_and_limits(sw):
    _da, res = sw
    assert "NVD snapshot" in res.summary
    joined = " ".join(res.notes)
    assert "not reflected" in joined
    assert "PSIRT" in joined and "not proof of no vulnerability" in joined


@sw_only
@snap_only
def test_the_compliance_result_is_untouched():
    da = assess(SW, redact=False, assessment_id="TEST-CVE-ISO")
    cov = dict(da.coverage())
    assess_cve(da)
    assert da.coverage() == cov
    assert (cov["score_pct"], cov["assessed_pct"]) == (36.2, 53.4)


# ------------------------------------------------------------ edge handling

@sw_only
def test_kev_membership_is_flagged(tmp_path, sw):
    da, _ = sw
    rec = _record({"versionEndExcluding": "7.3.2-7010"}, cid="CVE-TEST-KEV")
    (tmp_path / "nvd-sonicwall_sonicos.json").write_text(json.dumps(
        {"fetched_at": "2026-09-13T00:00:00+00:00", "total": 1, "cves": [rec]}))
    (tmp_path / "kev.json").write_text(json.dumps(
        {"catalogVersion": "test", "vulnerabilities": [
            {"cveID": "CVE-TEST-KEV", "dateAdded": "2026-01-01",
             "dueDate": "2026-01-22"}]}))
    res = assess_cve(da, snapshot_dir=tmp_path)
    assert res.inventory[0]["known_exploited"] is True
    assert "KNOWN EXPLOITED" in res.findings[0].reason


@sw_only
def test_a_stale_snapshot_says_so_first(tmp_path, sw):
    da, _ = sw
    (tmp_path / "nvd-sonicwall_sonicos.json").write_text(json.dumps(
        {"fetched_at": "2025-01-01T00:00:00+00:00", "total": 0, "cves": []}))
    res = assess_cve(da, snapshot_dir=tmp_path)
    assert "days old" in res.notes[0]


@sw_only
def test_a_missing_snapshot_is_reported_not_treated_as_clean(tmp_path, sw):
    da, _ = sw
    res = assess_cve(da, snapshot_dir=tmp_path)
    assert res.present is None
    assert "tools.fetch_cve" in res.summary


def test_a_device_with_no_stated_version_cannot_be_matched():
    class _Id:
        platform = "sonicwall_sonicos"
        version = None
        model = "NSA 3700"

    class _Da:
        identity = _Id()

    res = assess_cve(_Da())
    assert res.present is None
    assert "does not state its software version" in res.summary


def test_the_lookup_never_touches_the_network():
    """Reproducible and air-gap friendly: the check reads files only."""
    src = Path(cvemod.__file__).read_text(encoding="utf-8")
    for banned in ("urllib", "requests", "http.client", "socket"):
        assert f"import {banned}" not in src and f"from {banned}" not in src
