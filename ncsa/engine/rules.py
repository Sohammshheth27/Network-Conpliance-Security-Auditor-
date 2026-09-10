"""Load control definitions from YAML.

Plan 6.1: one rulebook, four labels. Rules are data, not code -- the same
principle ComplianceAsCode/OpenSCAP uses (plan 11.4), and the reason a new
framework label never requires a redeploy.

STIG identifiers are stored per platform because Vuln IDs are per-platform by
nature, and v1.4 6.4 established that one control can map to several of them.
"""
from __future__ import annotations

from pathlib import Path

import yaml

from ..schema.enums import Severity
from .control import Control, FrameworkLabels


def load_rule(path: str | Path, *, platform: str | None = None) -> Control:
    p = Path(path)
    with p.open(encoding="utf-8") as fh:
        d = yaml.safe_load(fh)

    fw = d.get("frameworks", {}) or {}
    stig_ids: list[str] = list(fw.get("stig", []) or [])
    by_platform = fw.get("stig_by_platform", {}) or {}
    if platform and platform in by_platform:
        stig_ids += [v for v in by_platform[platform] if v not in stig_ids]

    return Control(
        id=d["id"],
        title=d["title"],
        field=d["field"],
        operator=d["operator"],
        expected=d.get("expected"),
        severity=Severity(d["severity"]),
        tier=d.get("tier", "core"),
        rationale=(d.get("rationale") or "").strip(),
        applies_to=d.get("applies_to", []) or [],
        remediation=d.get("remediation", {}) or {},
        requires=d.get("requires", []) or [],
        frameworks=FrameworkLabels(
            nist_800_53=fw.get("nist_800_53", []) or [],
            iso_27001=fw.get("iso_27001_2022", []) or [],
            stig_ids=stig_ids,
            cis_ids=fw.get("cis", []) or [],
        ),
    )


def load_rules(
    rules_dir: str | Path, *, platform: str | None = None, tiers: list[str] | None = None
) -> list[Control]:
    root = Path(rules_dir)
    controls: list[Control] = []
    for f in sorted(root.rglob("*.yaml")):
        if tiers and f.parent.name not in tiers:
            continue
        controls.append(load_rule(f, platform=platform))
    return controls


def validate_rules(controls: list[Control], registry) -> list[str]:
    """Check every rule against the loaded catalogues and the SBM field list.

    Returns a list of problems. Existence is checked, not meaning -- a Vuln ID
    can exist and still be the wrong rule, which is how the plan came to cite
    V-215807 for SSH version. Semantic fit stays a human review step.
    """
    from ..frameworks.models import Framework
    from ..schema.sbm import FIELD_TYPES, _unscope

    problems: list[str] = []
    nist_ids = {e.id for e in registry.catalogs.get(Framework.NIST_800_53, []).entries} \
        if Framework.NIST_800_53 in registry.catalogs else set()
    stig_ids = {e.id for e in registry.catalogs.get(Framework.DISA_STIG, []).entries} \
        if Framework.DISA_STIG in registry.catalogs else set()

    import re

    def canon(nid: str) -> str:
        m = re.match(r"^([A-Z]{2})-0*(\d+)(?:\s*[.(]0*(\d+)\)?)?$", nid.strip())
        if not m:
            return nid
        fam, num, enh = m.groups()
        return f"{fam}-{int(num)}" + (f".{int(enh)}" if enh else "")

    seen: set[str] = set()
    for c in controls:
        if c.id in seen:
            problems.append(f"{c.id}: duplicate control id")
        seen.add(c.id)

        if _unscope(c.field) not in FIELD_TYPES:
            problems.append(f"{c.id}: field {c.field!r} is not in the SBM whitelist")

        if c.frameworks.is_empty():
            problems.append(f"{c.id}: no framework labels -- it cannot be reported")

        for n in c.frameworks.nist_800_53:
            if nist_ids and canon(n) not in nist_ids:
                problems.append(f"{c.id}: NIST id {n!r} not in the catalogue")
        for v in c.frameworks.stig_ids:
            if stig_ids and v not in stig_ids:
                problems.append(f"{c.id}: STIG id {v!r} not in any loaded STIG")

    return problems
