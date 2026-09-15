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


def framework_coverage(findings) -> list[dict]:
    """Per framework: how many evaluated controls cite it, and how they came out.

    Always reported for every framework, so a reader sees at a glance that a
    platform has, say, 50 CIS-cited controls but no STIG ones.
    """
    out = []
    for key, (name, attr) in FRAMEWORKS.items():
        fs = [f for f in findings if getattr(f.frameworks, attr, None)]
        decided = [f for f in fs if f.state.value in ("PASS", "FAIL", "PARTIAL")]
        passed = sum(1 for f in decided if f.state.value == "PASS")
        out.append({
            "framework": key, "name": name, "controls": len(fs),
            "decided": len(decided), "passed": passed,
            "score_pct": round(100 * passed / len(decided), 1) if decided else None,
        })
    return out
