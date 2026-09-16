"""Framework-native thresholds (crosswalks/profiles.yaml)."""
from pathlib import Path

import yaml

from ncsa.frameworks.selection import framework_coverage
from ncsa.pipeline import assess

IOS = Path("samples/cisco/edge-rtr-01.cfg")


def _router_with_timeout(tmp_path, minutes):
    text = IOS.read_text()
    import re
    text = re.sub(r"exec-timeout \d+ \d+", f"exec-timeout {minutes} 0", text)
    p = tmp_path / "r.cfg"
    p.write_text(text)
    return assess(str(p), redact=False, assessment_id="T-PROF")


def test_stig_judges_the_idle_timeout_by_its_own_five_minutes(tmp_path):
    da = _router_with_timeout(tmp_path, 8)
    t = next(f for f in da.assessment.findings if f.control_id == "NCSA-TIME-001")
    assert t.state.value == "PASS", "NCSA's own threshold is 10 minutes"
    rows = {r["framework"]: r for r in framework_coverage(da.assessment.findings,
                                                          da.identity.platform)}
    assert "NCSA-TIME-001" in rows["stig"]["profiled_controls"], "STIG says 5"
    assert "NCSA-TIME-001" not in rows["nist_800_53"]["profiled_controls"]
    # the overall score is untouched by any profile
    base = {r["framework"]: r for r in framework_coverage(da.assessment.findings)}
    assert rows["nist_800_53"]["framework_score_pct"] == base["nist_800_53"]["framework_score_pct"]


def test_a_value_within_both_thresholds_is_not_rescored(tmp_path):
    da = _router_with_timeout(tmp_path, 4)
    rows = {r["framework"]: r for r in framework_coverage(da.assessment.findings,
                                                          da.identity.platform)}
    assert rows["stig"]["profiled_controls"] == []


def test_every_profile_names_a_real_control_and_a_cited_platform():
    from ncsa.engine.rules import load_rules

    prof = yaml.safe_load(open("crosswalks/profiles.yaml", encoding="utf-8"))
    ids = {c.id for c in load_rules("rules")}
    for fw, per in prof.items():
        assert fw in {"cis", "stig", "nist_800_53", "iso_27001"}
        for cid, plats in per.items():
            assert cid in ids, cid
            for plat, ov in plats.items():
                assert "expected" in ov, (fw, cid, plat)


def test_profiled_citations_exist_where_the_profile_applies():
    """A threshold-profiled pairing is cited only where the profile exists."""
    cw = yaml.safe_load(open("crosswalks/cis.yaml", encoding="utf-8"))["map"]
    prof = yaml.safe_load(open("crosswalks/profiles.yaml", encoding="utf-8"))["cis"]
    for cid, plats in prof.items():
        for plat in plats:
            assert cw.get(cid, {}).get(plat), f"profile for {cid}/{plat} has no CIS citation"
