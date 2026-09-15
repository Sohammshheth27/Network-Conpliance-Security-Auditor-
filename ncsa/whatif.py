"""What-if remediation: apply a fix to a COPY and re-score it.

"If we fix these three things, where does the score land?" is the question a
remediation plan exists to answer, and a one-shot scanner cannot. This one can,
because the device model is retained after assessment: the simulation deep-
copies it, applies the change, and runs the exact evaluator the real assessment
used. Nothing on the device changes, and nothing in the stored assessment does
either.

TWO KINDS OF CHANGE
-------------------
  * fix a control   -- set the field it reads to a value that satisfies it.
  * disable a rule  -- take a firewall rule out of the policy, then recompute
                       every policy fact and the blast radius from the graph.

WHAT IT REFUSES, AND WHY
------------------------
A simulation that flatters is worse than none, so several requests are
declined with a reason rather than approximated:

  * Only FAIL and PARTIAL controls can be "fixed". Turning an UNKNOWN into a
    PASS would claim we know the answer to a question we could not read.
  * Findings computed from the firewall POLICY (exposure.*, per-rule checks)
    are not fixed by overwriting their field -- that would make an exposure
    vanish without changing the rule that causes it. They are simulated by
    disabling the rules named in their evidence, which the refusal suggests.
  * Operators with no single compliant value (not_equals, not_in, matches)
    are declined rather than guessed.

CAVEATS THAT TRAVEL WITH EVERY RESULT
-------------------------------------
Disabling a rule stops the traffic it permitted, and this does not model what
breaks. And the result is a projection: the real change still has to be made
on the device and the device re-assessed before anyone signs off on it.
"""
from __future__ import annotations

import copy

from .schema.evidence import EvidenceRef
from .schema.observation import Observation

#: Fields whose value is COMPUTED from the policy graph. Overwriting them would
#: hide an exposure without touching the rule that creates it.
POLICY_DERIVED = ("exposure.", "firewall.rules", "firewall.default_action")

LABEL = ("SIMULATION -- nothing on the device has changed. These figures are "
         "what the assessment would show if the listed changes were made; the "
         "real change must still be applied and the device re-assessed.")


def _compliant_value(op: str, expected, current):
    """A value that satisfies the operator, or (None, reason) when none exists."""
    if op == "equals":
        return expected, None
    if op == "in":
        return (expected[0] if isinstance(expected, list) and expected
                else expected), None
    if op in ("gte", "lte"):
        return expected, None
    if op == "contains_all":
        return list(expected) if isinstance(expected, list) else [expected], None
    if op == "contains_none":
        forbidden = {str(x).lower() for x in (expected or [])}
        cur = current if isinstance(current, list) else []
        return [x for x in cur if str(x).lower() not in forbidden], None
    if op == "max_count":
        cur = current if isinstance(current, list) else []
        return cur[: int(expected)], None
    if op == "min_count":
        cur = current if isinstance(current, list) else []
        need = max(0, int(expected) - len(cur))
        return cur + [f"<added entry {i + 1}>" for i in range(need)], None
    if op == "is_set":
        return "<configured>", None
    return None, (f"operator {op!r} has no single compliant value, so a fix "
                  "cannot be simulated without guessing one")


def _sim_evidence(source_file: str, path: str, value) -> list[EvidenceRef]:
    return [EvidenceRef(file=source_file or "simulation", line=None,
                        raw=f"[SIMULATED] {path} = {value!r}"[:200],
                        record_id="what-if")]


def _rules_behind(finding, graph) -> list[str]:
    """Rules whose evidence is the evidence this finding cites."""
    if graph is None or not finding.evidence:
        return []
    cited = {(e.record_id, e.line, e.raw) for e in finding.evidence}
    names = []
    for r in graph.rules:
        for e in getattr(r, "evidence", []) or []:
            if (e.record_id, e.line, e.raw) in cited:
                names.append(r.name or r.id)
                break
    return names


def _twins_still_open(graph, disabled_scopes) -> list[str]:
    """Enabled rules that permit exactly what a disabled rule permitted.

    Found on the real NSA 3700: SonicOS keeps IPv4 and IPv6 policy in
    separate tables, and rules 216/217 have IPv6 twins (59/60) with the same
    any/any/any allow. Disabling only the IPv4 rule closes nothing. A
    simulation that stayed silent about that would let an administrator
    believe a change worked when the traffic still flows.
    """
    disabled = [r for r in graph.rules if (r.name or r.id) in disabled_scopes]
    out = []
    for d in disabled:
        for r in graph.rules:
            if (r is d or not r.enabled or r.action != d.action
                    or r.source_zones != d.source_zones
                    or r.destination_zones != d.destination_zones
                    or sorted(r.source) != sorted(d.source)
                    or sorted(r.destination) != sorted(d.destination)
                    or sorted(r.services) != sorted(d.services)):
                continue
            out.append(
                f"{d.name or d.id} was disabled, but {r.name or r.id} permits "
                f"the same traffic ({','.join(d.source_zones)} -> "
                f"{','.join(d.destination_zones)}, same sources, destinations "
                f"and services) and is still enabled -- typically the IPv6 "
                f"twin of an IPv4 rule. The traffic is not closed until both "
                f"are.")
    return out


def simulate(da, *, fix_controls=(), disable_rules=(), origin_zone: str = "",
             origin_members=None, packs_dir="packs", rules_dir="rules") -> dict:
    from .engine.evaluate import evaluate_all
    from .engine.rules import load_rules
    from .graph.bridge import merge
    from .pipeline import DeviceAssessment, load_packs, select_pack
    from .topology.blast import blast_radius

    if da.assessment is None or getattr(da, "sbm", None) is None:
        raise ValueError("this assessment has no retained device model to "
                         "simulate against")

    pack = select_pack(load_packs(packs_dir), da.fingerprint)
    platform = pack.platform if pack else da.identity.platform
    controls = {c.id: c for c in load_rules(rules_dir, platform=platform)}
    before_findings = {f.control_id: f for f in da.assessment.findings}

    sbm = copy.deepcopy(da.sbm)
    graph = copy.deepcopy(da.graph) if da.graph is not None else None
    applied, rejected, warnings = [], [], []
    src = da.identity.source_file

    # ------------------------------------------------------- disable rules
    disabled_scopes = []
    if disable_rules:
        if graph is None:
            rejected.extend({"item": r, "reason": "this platform has no "
                             "policy object graph, so rules cannot be "
                             "simulated"} for r in disable_rules)
        else:
            by_name = {}
            for r in graph.rules:
                for key in (r.name, r.id):
                    if key:
                        by_name.setdefault(str(key).lower(), r)
            for want in disable_rules:
                rule = by_name.get(str(want).lower())
                if rule is None:
                    rejected.append({"item": want, "reason": "no rule with "
                                     "this name or id in the policy"})
                    continue
                if not rule.enabled:
                    rejected.append({"item": want, "reason": "the rule is "
                                     "already disabled"})
                    continue
                rule.enabled = False
                disabled_scopes.append(rule.name or rule.id)
                applied.append({"kind": "disable_rule", "rule": rule.name or rule.id,
                                "action_was": rule.action})
            if disabled_scopes:
                merge(sbm, graph)
                # merge() rewrites every rule it holds, disabled or not. A rule
                # taken out of the policy must not keep failing per-rule
                # controls, so its observations leave the simulated model.
                for scope in disabled_scopes:
                    prefix = f"firewall.rules[{scope}]."
                    for path in [p for p in sbm.observations if p.startswith(prefix)]:
                        del sbm.observations[path]
                warnings.extend(_twins_still_open(graph, disabled_scopes))

    # --------------------------------------------------------- fix controls
    for cid in fix_controls:
        control = controls.get(cid)
        finding = before_findings.get(cid)
        if control is None or finding is None:
            rejected.append({"item": cid, "reason": "no such control in "
                             "this assessment"})
            continue
        state = finding.state.value
        if state not in ("FAIL", "PARTIAL"):
            rejected.append({"item": cid, "reason": f"the control is {state}; "
                             "only FAIL and PARTIAL findings can be simulated "
                             "as fixed"})
            continue
        if control.field.startswith(POLICY_DERIVED):
            rules = _rules_behind(finding, da.graph)
            rejected.append({
                "item": cid,
                "reason": "this finding is computed from the firewall policy; "
                          "overwriting its field would hide the exposure "
                          "without changing the rule that causes it. Simulate "
                          "it by disabling the rules behind it instead.",
                "suggest_disable_rules": rules})
            continue

        op, expected = control.operator, control.expected
        scoped = sbm.scoped_instances(control.field)
        targets = dict(scoped) if scoped else {
            control.field: sbm.observations.get(control.field)}
        paths, why_not = [], None
        for path, obs in targets.items():
            current = obs.value if obs is not None else None
            value, why_not = _compliant_value(op, expected, current)
            if why_not:
                break
            sbm.set(path, Observation.observed(
                value, _sim_evidence(src, path, value), field_path=path))
            paths.append(path)
        if why_not:
            rejected.append({"item": cid, "reason": why_not})
            continue
        applied.append({"kind": "fix_control", "control_id": cid,
                        "field_paths": paths, "operator": op,
                        "expected": expected})

    # -------------------------------------------------------------- rescore
    after = evaluate_all(
        list(controls.values()), sbm, device=da.assessment.device,
        platform=platform,
        not_applicable_domains=getattr(pack, "not_applicable_domains", None),
        not_applicable_fields=getattr(pack, "not_applicable_fields", None))
    after_da = DeviceAssessment(identity=da.identity, assessment=after)

    cov_before, cov_after = da.coverage(), after_da.coverage()
    targeted = {a["control_id"] for a in applied if a["kind"] == "fix_control"}
    changes = []
    for f in after.findings:
        b = before_findings.get(f.control_id)
        if b is not None and b.state != f.state:
            changes.append({"control_id": f.control_id, "title": f.title,
                            "severity": f.severity.value,
                            "before": b.state.value, "after": f.state.value,
                            "targeted": f.control_id in targeted})

    def _delta(k):
        a, b = cov_after.get(k), cov_before.get(k)
        return None if a is None or b is None else round(a - b, 1)

    out = {
        "simulated": True,
        "label": LABEL,
        "applied": applied,
        "rejected": rejected,
        "warnings": warnings,
        "before": cov_before,
        "after": cov_after,
        "delta": {"score_pct": _delta("score_pct"),
                  "assessed_pct": _delta("assessed_pct")},
        "changes": changes,
        "caveats": [
            "Disabling a rule also stops the traffic it permitted. What that "
            "breaks is not modelled here.",
            "A simulated value proves only that the setting WOULD satisfy the "
            "control; the remediation commands still have to produce it on "
            "the device.",
        ],
    }

    if origin_zone and da.graph is not None:
        b = blast_radius(da.graph, origin_zone=origin_zone,
                         origin_members=origin_members)
        a = blast_radius(graph if graph is not None else da.graph,
                         origin_zone=origin_zone, origin_members=origin_members)
        out["blast_radius"] = {"origin_zone": origin_zone,
                               "before": b.summary(), "after": a.summary()}
    return out
