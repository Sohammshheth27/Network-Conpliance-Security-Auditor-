"""User-selected frameworks (CIS / NIST / STIG / ISO) and the CIS crosswalk.

The contract, in order of importance:

  1. Selecting NOTHING is the assessment exactly as it has always been. The
     SonicWall figures below are the proof -- 40.0% on 74.6% coverage (50 of 67 applicable controls decided).
  2. Selecting a framework scores the device against ONLY the controls that
     framework cites, so "CIS: 71%" is a statement about CIS.
  3. A framework with nothing to evaluate says so. CIS publishes no SonicWall
     benchmark; selecting it must produce an explanation, not a blank report.
  4. Every CIS number on a finding exists in the benchmark it claims, for the
     platform it claims. A wrong CIS number is worse than none: an auditor
     will look it up.
"""
from functools import lru_cache
import os

import pytest
import yaml

from ncsa.engine.rules import CIS_CROSSWALK, cis_benchmark, load_rules
from ncsa.frameworks.selection import (FRAMEWORKS, framework_coverage,
                                       normalise)
from ncsa.pipeline import assess

SW = r"E:\sonicwall config file.txt"
RTR = "samples/cisco/edge-rtr-01.cfg"
sw_only = pytest.mark.skipif(not os.path.exists(SW), reason="SonicWall sample absent")


@lru_cache(maxsize=None)
def _sw(redact=False, frameworks=None):
    """One SonicWall assessment per distinct input for the whole file: each
    run of this 2.7 MB export costs ~40 s, and these tests only read it."""
    return assess(SW, redact=redact, assessment_id="TEST-SW",
                  frameworks=list(frameworks) if frameworks else None)


# ------------------------------------------------------------- selection

def test_nothing_selected_means_all():
    assert normalise(None) is None
    assert normalise([]) is None
    assert normalise(["all"]) is None


def test_selection_is_validated_not_ignored():
    """A typo silently falling back to "all" would mislabel the whole report."""
    with pytest.raises(ValueError, match="unknown framework"):
        normalise(["cys"])
    assert normalise(["CIS", "stig,nist_800_53"]) == ["cis", "stig", "nist_800_53"]


@sw_only
def test_the_default_assessment_is_unchanged():
    cov = _sw(False).coverage()
    assert (cov["score_pct"], cov["assessed_pct"]) == (40.0, 74.6)


@sw_only
def test_selecting_every_framework_matches_the_default():
    """All 88 controls cite NIST 800-53, so NIST alone is the full set."""
    base = _sw(False).coverage()
    nist = _sw(False, ("nist_800_53",)).coverage()
    assert nist == base


@sw_only
def test_cis_on_a_sonicwall_explains_why_it_is_empty():
    da = _sw(False, ("cis",))
    assert da.coverage()["controls_total"] == 0
    notes = " ".join(da.notes)
    assert "CIS publishes no benchmark for this platform" in notes


def test_stig_selection_scores_only_stig_cited_controls():
    da = assess(RTR, redact=False, assessment_id="TEST-FW-STIG", frameworks=["stig"])
    cited = [c for c in load_rules("rules", platform=da.identity.platform)
             if c.frameworks.stig_ids]
    assert cited, "the IOS-XE router has STIG-cited controls"
    assert da.coverage()["controls_total"] == len(cited)
    assert all(f.frameworks.stig_ids for f in da.assessment.findings)


def test_framework_coverage_reports_every_framework():
    da = assess(RTR, redact=False, assessment_id="TEST-FW-COV")
    rows = {r["framework"]: r for r in framework_coverage(da.assessment.findings)}
    assert set(rows) == set(FRAMEWORKS)
    assert rows["nist_800_53"]["controls"] == len(da.assessment.findings)
    for r in rows.values():
        assert r["passed"] <= r["decided"] <= r["controls"]


# ------------------------------------------------ per-framework scoring

def test_a_requirement_is_met_only_when_every_citing_check_passes():
    from ncsa.frameworks.selection import requirement_state as rs

    assert rs(["PASS", "PASS"]) == "MET"
    assert rs(["PASS", "FAIL"]) == "NOT_MET", "one failing test fails it"
    assert rs(["PASS", "PARTIAL"]) == "NOT_MET"
    assert rs(["PASS", "UNKNOWN"]) == "UNDECIDED", "unknown is not a pass"
    assert rs(["UNKNOWN"]) == "UNDECIDED"


def test_each_framework_is_scored_over_its_own_requirements():
    from types import SimpleNamespace as NS

    def f(state, nist, iso):
        return NS(state=NS(value=state),
                  frameworks=NS(nist_800_53=nist, iso_27001=iso,
                                stig_ids=[], cis_ids=[]))

    # Two NIST requirements share one failing check; ISO groups differently.
    findings = [f("PASS", ["AC-2"], ["A.5.15"]),
                f("FAIL", ["AC-2", "AC-17"], ["A.8.20"]),
                f("PASS", ["AU-6"], ["A.8.20"]),
                f("NOT_APPLICABLE", ["SC-8"], ["A.8.24"])]
    rows = {r["framework"]: r for r in framework_coverage(findings)}
    nist, iso = rows["nist_800_53"], rows["iso_27001"]
    # checks: 2 of 3 decided passed, for both frameworks
    assert nist["score_pct"] == iso["score_pct"] == 66.7
    # NIST requirements: AC-2 = 1/2, AC-17 = 0/1, AU-6 = 1/1 -> average 50%
    assert nist["score_method"] == "average"
    assert nist["framework_score_pct"] == 50.0
    assert (nist["requirements_met"], nist["requirements_not_met"]) == (1, 2)
    assert nist["not_met_ids"] == ["AC-17", "AC-2"]
    # ISO: A.5.15 = 1/1, A.8.20 = 1/2 -> 75%; the N/A requirement is excluded
    assert iso["framework_score_pct"] == 75.0 and iso["requirements"] == 2


def test_undecided_checks_are_not_counted_as_passes():
    from ncsa.frameworks.selection import requirement_satisfaction as sat

    assert sat(["PASS", "UNKNOWN"]) == 1.0, "scored on the decided check only"
    assert sat(["PASS", "PARTIAL"]) == 0.5, "partial is not a pass"
    assert sat(["UNKNOWN", "MANUAL_REVIEW"]) is None, "nothing decided, no score"


@sw_only
def test_sonicwall_frameworks_score_differently_and_the_overall_is_unchanged():
    da = _sw(False)
    assert (da.coverage()["score_pct"], da.coverage()["assessed_pct"]) == (40.0, 74.6)
    rows = {r["framework"]: r for r in framework_coverage(da.assessment.findings)}
    for r in rows.values():
        assert r["requirements_met"] <= r["requirements_decided"] <= r["requirements"]
    scores = {k: rows[k]["framework_score_pct"] for k in ("nist_800_53", "iso_27001")}
    assert None not in scores.values()
    assert scores["nist_800_53"] != scores["iso_27001"], scores


# ---------------------------------------------------------------- report

def test_the_report_states_the_selection_and_the_per_framework_result():
    from ncsa.report import build_report

    da = assess(RTR, redact=False, assessment_id="TEST-FW-RPT", frameworks=["stig"])
    html = " ".join(build_report(da, "TEST-FW-RPT").split())
    assert "Frameworks assessed" in html and "DISA STIG" in html
    assert "Result by framework" in html


# ------------------------------------------------------------------ API

def test_the_api_accepts_validates_and_keeps_the_selection():
    from fastapi.testclient import TestClient

    from ncsa.api.app import app

    c = TestClient(app)
    with open(RTR, "rb") as fh:
        body = c.post("/assess?redact=false&frameworks=stig",
                      files={"files": ("r.cfg", fh)}).json()[0]
    assert body["frameworks"] == ["stig"]
    assert len(body["framework_coverage"]) == len(FRAMEWORKS)
    again = c.post(f"/assessment/{body['assessment_id']}/reassess").json()
    assert again["frameworks"] == ["stig"], "a re-assessment keeps the selection"

    with open(RTR, "rb") as fh:
        bad = c.post("/assess?frameworks=cys", files={"files": ("r.cfg", fh)})
    assert bad.status_code == 422


# ------------------------------------------------------- CIS crosswalk

def _crosswalk() -> dict:
    return yaml.safe_load(CIS_CROSSWALK.read_text(encoding="utf-8")) or {}


def test_sonicwall_has_no_cis_benchmark():
    assert cis_benchmark("sonicwall_sonicos") is None


def test_every_crosswalk_entry_names_a_real_control_and_platform():
    cw = _crosswalk()
    controls = {c.id for c in load_rules("rules")}
    benches = cw.get("benchmarks") or {}
    for cid, per in (cw.get("map") or {}).items():
        assert cid in controls, f"crosswalk maps unknown control {cid}"
        for plat in per:
            assert plat in benches, f"{cid}: platform {plat!r} has no benchmark"


def _benchmark_ids(titles: set[str]) -> dict[str, set[str]]:
    """Parse ONLY the cited benchmarks -- the whole catalogue is 89 PDFs --
    and cache the recommendation numbers locally (git-ignored). Parsing ten
    PDFs cost two minutes of every run. The cache key is each PDF's size and
    mtime plus the parser's own mtime, so a new PDF or a parser change
    re-parses; a stale answer is never served."""
    import json
    from pathlib import Path

    import ncsa.frameworks.cis as cis_mod

    root = Path("reference/cis_benchmarks")
    cache_file = Path("reference/.framework_cache_cis_ids.json")
    parser_stamp = Path(cis_mod.__file__).stat().st_mtime_ns
    try:
        cache = json.loads(cache_file.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        cache = {}
    ids: dict[str, set[str]] = {}
    dirty = False
    for p in root.rglob("*.pdf") if root.exists() else []:
        t = p.stem.replace("_", " ")
        if t not in titles:
            continue
        st = p.stat()
        key = f"{p.name}|{st.st_size}|{st.st_mtime_ns}|{parser_stamp}"
        if key not in cache:
            cache[key] = sorted(e.id for e in cis_mod._parse_pdf(p, p.parent.name))
            dirty = True
        ids[t] = set(cache[key])
    if dirty:
        try:
            cache_file.write_text(json.dumps(cache), encoding="utf-8")
        except OSError:
            pass
    return ids


def test_every_cis_number_exists_in_its_benchmark():
    """The check that makes a CIS citation trustworthy."""
    cw = _crosswalk()
    benches = cw.get("benchmarks") or {}
    cited = {benches[p] for per in (cw.get("map") or {}).values() for p in per}
    if not cited:
        pytest.skip("crosswalk cites no benchmark yet")
    ids = _benchmark_ids(cited)
    if not ids:
        pytest.skip("CIS PDFs are not present on this machine (never committed)")
    for bench in cited:
        assert ids.get(bench), f"benchmark {bench!r} is not readable locally"
    for cid, per in (cw.get("map") or {}).items():
        for plat, recs in per.items():
            for r in recs:
                assert str(r) in ids[benches[plat]], (
                    f"{cid} cites CIS {r} for {plat}, which does not exist in "
                    f"{benches[plat]}")


def test_cis_numbers_reach_the_findings():
    da = assess(RTR, redact=False, assessment_id="TEST-CIS-FIND")
    ssh2 = next(f for f in da.assessment.findings if f.control_id == "NCSA-SSH-002")
    per = (_crosswalk().get("map") or {}).get("NCSA-SSH-002", {})
    assert ssh2.frameworks.cis_ids == per.get("cisco_iosxe_router", [])
