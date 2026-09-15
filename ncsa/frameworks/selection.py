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


def _requirements(findings, attr: str) -> dict[str, list[str]]:
    """Framework requirement id -> states of the checks citing it.

    NOT_APPLICABLE checks are left out: a requirement whose only checks do not
    apply to this platform is not part of this device's assessment.
    """
    req: dict[str, list[str]] = {}
    for f in findings:
        st = f.state.value
        if st == "NOT_APPLICABLE":
            continue
        for rid in getattr(f.frameworks, attr, None) or []:
            req.setdefault(str(rid), []).append(st)
    return req


def framework_coverage(findings) -> list[dict]:
    """Per framework: its own score, over its own requirements.

    Two levels are reported, and they answer different questions:

    * CHECK level (`controls`, `decided`, `passed`, `score_pct`): how the NCSA
      checks citing the framework came out. Every check cites NIST 800-53, so
      at this level NIST equals the overall score.
    * REQUIREMENT level (`requirements*`, `requirement_score_pct`): how the
      FRAMEWORK'S OWN requirements came out -- NIST controls such as AC-17(2),
      ISO/IEC 27001 Annex A controls such as A.8.20, STIG Vuln IDs. This is how
      an auditor of that framework scores it, and it is why the frameworks
      differ: one failing check fails every requirement that cites it, and a
      requirement needing five checks must pass all five.

    Always reported for every framework, so a reader sees at a glance that a
    platform has, say, 50 CIS-cited controls but no STIG ones.
    """
    out = []
    for key, (name, attr) in FRAMEWORKS.items():
        fs = [f for f in findings if getattr(f.frameworks, attr, None)]
        decided = [f for f in fs if f.state.value in ("PASS", "FAIL", "PARTIAL")]
        passed = sum(1 for f in decided if f.state.value == "PASS")

        req = _requirements(findings, attr)
        states = {rid: requirement_state(v) for rid, v in req.items()}
        met = sum(1 for s in states.values() if s == "MET")
        not_met = sorted(rid for rid, s in states.items() if s == "NOT_MET")
        req_decided = met + len(not_met)
        out.append({
            "framework": key, "name": name, "controls": len(fs),
            "decided": len(decided), "passed": passed,
            "score_pct": round(100 * passed / len(decided), 1) if decided else None,
            "requirements": len(states),
            "requirements_decided": req_decided,
            "requirements_met": met,
            "requirements_not_met": len(not_met),
            "requirement_score_pct": (round(100 * met / req_decided, 1)
                                      if req_decided else None),
            "not_met_ids": not_met,
        })
    return out
