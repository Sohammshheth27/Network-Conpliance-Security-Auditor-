"""Framework selection: assess a device against the benchmarks a user chose.

The problem statement asks for evaluation "against user-selected benchmarks
(CIS, NIST, STIGs, ISO)". Every control already carries the identifiers of
each framework that asks for it, so selecting a framework means evaluating the
controls that framework cites -- and computing the score and coverage over
THOSE, so "CIS: 71%" is a statement about CIS and nothing else.

Selecting nothing means every framework, which is the assessment exactly as
it has always been produced. A framework that cites no control on a platform
is reported as such rather than silently producing an empty result: CIS, for
example, publishes no SonicWall benchmark at all.
"""
from __future__ import annotations

#: key -> (display name, FrameworkLabels attribute)
FRAMEWORKS: dict[str, tuple[str, str]] = {
    "cis": ("CIS Benchmarks", "cis_ids"),
    "nist_800_53": ("NIST SP 800-53 Rev 5", "nist_800_53"),
    "stig": ("DISA STIG", "stig_ids"),
    "iso_27001": ("ISO/IEC 27001:2022", "iso_27001"),
}


def normalise(selection) -> list[str] | None:
    """User input -> validated framework keys, or None meaning "all".

    Raises ValueError on an unknown framework rather than ignoring it: a typo
    that silently fell back to "all" would produce a report claiming to be
    about CIS that was about everything.
    """
    if not selection:
        return None
    if isinstance(selection, str):
        selection = [selection]
    out = []
    for s in selection:
        for part in str(s).split(","):
            key = part.strip().lower()
            if not key or key == "all":
                continue
            if key not in FRAMEWORKS:
                raise ValueError(f"unknown framework {part!r}; choose from "
                                 f"{', '.join(FRAMEWORKS)}")
            if key not in out:
                out.append(key)
    return out or None


def cites(control, key: str) -> bool:
    return bool(getattr(control.frameworks, FRAMEWORKS[key][1], None))


def selected(control, keys: list[str]) -> bool:
    return any(cites(control, k) for k in keys)


def requirement_state(states: list[str]) -> str:
    """One framework requirement, judged from the NCSA checks that cite it.

    MET only when EVERY citing check passed. Any FAIL or PARTIAL makes it
    NOT_MET -- a requirement is not half-satisfied because one of its tests
    passed. No failure but an undecided check leaves it UNDECIDED: unknown is
    not a pass, at the requirement level exactly as at the check level.
    """
    if any(s in ("FAIL", "PARTIAL") for s in states):
        return "NOT_MET"
    if states and all(s == "PASS" for s in states):
        return "MET"
    return "UNDECIDED"


def _requirements(findings, attr: str, states: dict | None = None) -> dict[str, list[str]]:
    """Framework requirement id -> states of the checks citing it.

    NOT_APPLICABLE checks are left out: a requirement whose only checks do not
    apply to this platform is not part of this device's assessment. `states`
    carries the framework-profiled state of each finding, when one applies.
    """
    req: dict[str, list[str]] = {}
    for f in findings:
        st = (states or {}).get(id(f), f.state.value)
        if st == "NOT_APPLICABLE":
            continue
        for rid in getattr(f.frameworks, attr, None) or []:
            req.setdefault(str(rid), []).append(st)
    return req


_DECIDED = ("PASS", "FAIL", "PARTIAL")


def requirement_satisfaction(states: list[str]) -> float | None:
    """Share of a requirement's DECIDED checks that passed; None if none decided.

    PARTIAL counts as not passing, exactly as in the overall score. Undecided
    checks are left out rather than counted as passes or failures.
    """
    decided = [s for s in states if s in _DECIDED]
    if not decided:
        return None
    return sum(1 for s in decided if s == "PASS") / len(decided)


#: identity platform (from the fingerprint) -> the key crosswalks use
_PLATFORM_KEY = {"paloalto_panos": "panos", "fortinet_fortios": "fortios",
                 "juniper_srx_xml": "juniper_srx"}


def _profiles() -> dict:
    return _load_profiles()


def _load_profiles_uncached() -> dict:
    from pathlib import Path

    import yaml

    p = Path(__file__).resolve().parents[2] / "crosswalks" / "profiles.yaml"
    return (yaml.safe_load(p.read_text(encoding="utf-8")) or {}) if p.exists() else {}


_PROFILE_CACHE: dict = {}


def _load_profiles() -> dict:
    if "p" not in _PROFILE_CACHE:
        _PROFILE_CACHE["p"] = _load_profiles_uncached()
    return _PROFILE_CACHE["p"]


def _operators() -> dict:
    """control id -> operator, loaded once (Finding does not carry it)."""
    if "ops" not in _PROFILE_CACHE:
        from ..engine.rules import load_rules
        _PROFILE_CACHE["ops"] = {c.id: c.operator for c in load_rules("rules")}
    return _PROFILE_CACHE["ops"]


def _framework_state(f, framework: str, platform: str | None):
    """The finding's state as THIS framework would judge it.

    A decided finding is re-run against the framework's own threshold when a
    profile gives one; anything else keeps its engine state.
    """
    st = f.state.value
    if not platform or st not in _DECIDED:
        return st, False
    key = _PLATFORM_KEY.get(platform, platform)
    ov = ((_profiles().get(framework) or {}).get(f.control_id) or {}).get(key)
    if not ov or "expected" not in ov:
        return st, False
    from ..engine.operators import evaluate as run_operator

    op = _operators().get(f.control_id)
    if not op:
        return st, False
    new = run_operator(op, f.observed, ov["expected"]).value
    return new, new != st


def framework_coverage(findings, platform: str | None = None) -> list[dict]:
    """Per framework: its own score, over its own requirements.

    THE FRAMEWORK SCORE (`framework_score_pct`, method "average"): each of the
    framework's own requirements -- NIST controls such as AC-17(2), ISO/IEC
    27001 Annex A controls such as A.8.20, STIG Vuln IDs -- is scored by the
    share of its decided checks that passed, and the framework's score is the
    average over its requirements. Because each framework groups the checks
    into different requirements, each gets its own number; a requirement with
    three of four checks passing contributes 75%, not zero.

    Reported beside it, so nothing is hidden:

    * `requirements_met` / `requirements_not_met` / undecided -- how many
      requirements are FULLY satisfied (every citing check passed), the view
      an auditor signs off against. `not_met_ids` names the rest.
    * CHECK level (`controls`, `decided`, `passed`, `score_pct`) -- how the
      NCSA checks citing the framework came out. Every check cites NIST, so
      at this level NIST equals the overall score.

    Always reported for every framework, so a reader sees at a glance that a
    platform has, say, 50 CIS-cited controls but no STIG ones.
    """
    out = []
    for key, (name, attr) in FRAMEWORKS.items():
        fs = [f for f in findings if getattr(f.frameworks, attr, None)]
        states, profiled = {}, []
        for f in fs:
            s, changed = _framework_state(f, key, platform)
            states[id(f)] = s
            if changed:
                profiled.append(f.control_id)
        decided = [f for f in fs if states[id(f)] in _DECIDED]
        passed = sum(1 for f in decided if states[id(f)] == "PASS")

        req = _requirements(fs, attr, states)
        shares = [s for s in (requirement_satisfaction(v) for v in req.values())
                  if s is not None]
        states = {rid: requirement_state(v) for rid, v in req.items()}
        met = sum(1 for s in states.values() if s == "MET")
        not_met = sorted(rid for rid, s in states.items() if s == "NOT_MET")
        out.append({
            "framework": key, "name": name, "controls": len(fs),
            "decided": len(decided), "passed": passed,
            "score_pct": round(100 * passed / len(decided), 1) if decided else None,
            "score_method": "average",
            "framework_score_pct": (round(100 * sum(shares) / len(shares), 1)
                                    if shares else None),
            "requirements": len(states),
            "requirements_decided": len(shares),
            "requirements_met": met,
            "requirements_not_met": len(not_met),
            "not_met_ids": not_met,
            # Controls this framework judged by its OWN threshold and reached a
            # different verdict from NCSA's (crosswalks/profiles.yaml).
            "profiled_controls": sorted(profiled),
        })
    return out
