"""The rule engine -- evaluate controls against an SBM.

This layer is the Policy layer of plan 2.2 and must never know vendor syntax.
It reads the SBM and the control set; nothing else.

The important behaviour here is not the comparisons -- it is what happens when
a value is *absent*, because plan 2.3 says most compliance failures are
absences, and getting that wrong is how a compliance tool starts lying.
"""
from __future__ import annotations

from pydantic import BaseModel, Field

from ..schema.enums import ObservationState, ResultState, Severity
from ..schema.sbm import SecurityBaselineModel
from .control import Control, Finding, FrameworkLabels
from .operators import evaluate as run_operator


class Assessment(BaseModel):
    """All findings for one device, plus the honest coverage numbers."""

    assessment_id: str
    device: str
    platform: str | None = None
    findings: list[Finding] = Field(default_factory=list)

    # Plan 10.2 defence 5 -- a later approval must never silently change a
    # past report, so every assessment records the versions it ran against.
    versions: dict[str, str] = Field(default_factory=dict)

    def by_state(self, state: ResultState) -> list[Finding]:
        return [f for f in self.findings if f.state is state]

    def counts(self) -> dict[str, int]:
        out = {s.value: 0 for s in ResultState}
        for f in self.findings:
            out[f.state.value] += 1
        return out

    def score(self) -> float | None:
        """Plan 6.7 -- weighted, with a stated method.

            score = weighted_passed / (weighted_passed + weighted_failed)

        NOT_APPLICABLE / MANUAL_REVIEW / UNKNOWN / ERROR are excluded from the
        denominator and reported separately. Auditors attack undefined scores;
        defining ours costs one sentence.

        PARTIAL counts as half credit -- it is genuinely half-met, and either
        rounding would misstate it.
        """
        passed = failed = 0.0
        for f in self.findings:
            w = f.severity.weight
            if f.state is ResultState.PASS:
                passed += w
            elif f.state is ResultState.FAIL:
                failed += w
            elif f.state is ResultState.PARTIAL:
                passed += w * 0.5
                failed += w * 0.5
        total = passed + failed
        return None if total == 0 else round(100.0 * passed / total, 1)

    def coverage_line(self) -> str:
        c = self.counts()
        scored = c["PASS"] + c["FAIL"] + c["PARTIAL"]
        return (
            f"{len(self.findings)} controls evaluated: "
            f"{c['PASS']} pass, {c['FAIL']} fail, {c['PARTIAL']} partial "
            f"({scored} scored) | {c['NOT_APPLICABLE']} n/a, "
            f"{c['MANUAL_REVIEW']} manual, {c['UNKNOWN']} unknown, {c['ERROR']} error"
        )


def evaluate_control(
    control: Control,
    sbm: SecurityBaselineModel,
    *,
    platform: str | None = None,
    iso_resolver=None,
    not_applicable_domains: dict[str, str] | None = None,
    not_applicable_fields: list[str] | None = None,
) -> Finding:
    """Evaluate one control. Never raises -- failures become ERROR findings."""
    labels = control.frameworks
    if iso_resolver is not None and labels.nist_800_53 and not labels.iso_27001:
        labels = labels.model_copy(
            update={"iso_27001": iso_resolver(labels.nist_800_53)}
        )

    def finding(state: ResultState, reason: str = "", obs=None) -> Finding:
        return Finding(
            control_id=control.id,
            title=control.title,
            state=state,
            severity=control.severity,
            field=control.field,
            observed=(obs.value if obs is not None else None),
            expected=control.expected,
            evidence=(list(obs.evidence) if obs is not None else []),
            frameworks=labels,
            reason=reason,
            confidence=(obs.confidence if obs is not None else 1.0),
        )

    if not control.applicable_to(platform):
        return finding(
            ResultState.NOT_APPLICABLE,
            f"control does not apply to platform {platform!r}",
        )

    # A concept VERIFIED absent from the platform -- not merely unmapped.
    #
    # `not_applicable_fields` may be a bare list or a {field: reason} mapping.
    # The reason form is preferred and is what the pack should carry: an
    # auditor asked to accept an exclusion needs to know WHY, and "verified
    # against the setting inventory" asserts that a check happened without
    # saying what it found.
    if not_applicable_fields and control.field in not_applicable_fields:
        why = (not_applicable_fields.get(control.field)
               if isinstance(not_applicable_fields, dict) else None)
        return finding(
            ResultState.NOT_APPLICABLE,
            f"{control.field} does not exist on platform {platform!r}: {why}"
            if why else
            f"{control.field} does not exist on platform {platform!r} "
            "(verified against the full setting inventory)",
        )

    # A capability the platform genuinely does not have is NOT_APPLICABLE, not
    # UNKNOWN: an AWS security group has no SSH version, and "could not
    # determine" would imply we should have been able to.
    #
    # But that claim must be MADE, not inferred. This used to fall out of
    # `supported_domains` -- a list whose real meaning is "domains this pack
    # models" -- and the two are not the same thing. Measured across 11 real
    # configs, 242 of 269 NOT_APPLICABLE verdicts came from that inference,
    # none of them carrying any justification, and several were plainly false:
    # cisco.yaml declared IOS-XE to have no `l2` capability, on the platform
    # that invented DHCP snooping and dynamic ARP inspection.
    #
    # That direction of error is the dangerous one. UNKNOWN stays in the
    # denominator and depresses assessed coverage; NOT_APPLICABLE is excluded
    # from scoring entirely, so a wrong one silently RAISES the score by
    # removing a hard control from the denominator.
    #
    # So the platform claim now comes only from `not_applicable_domains`, where
    # a pack author states it explicitly and gives a reason. A domain that is
    # merely unmodelled falls through to UNKNOWN, which is what a gap in our
    # own coverage actually is.
    domain = control.field.split(".", 1)[0].split("[", 1)[0]
    if not_applicable_domains and domain in not_applicable_domains:
        return finding(
            ResultState.NOT_APPLICABLE,
            f"platform {platform!r} has no {domain!r} capability: "
            f"{not_applicable_domains[domain]}",
        )

    # A sub-property of a DISABLED feature cannot fail. On a real hardened
    # SonicWall with `snmp_Enable = off` and all eight `snmpStateEnable_N` off,
    # "SNMPv3 authentication must be enabled" reported FAIL -- a finding about
    # a protocol the device does not run. The same shape made "HTTPS
    # management must use TLS 1.2" fail on a device with HTTPS management
    # switched off. Both are the M0-interface mistake again: a setting that is
    # moot is not a setting that is wrong.
    #
    # The precondition is DATA on the rule, so a new one is a YAML edit.
    for req in (control.requires or []):
        rfield = req.get("field")
        if not rfield:
            continue
        robs = sbm.get(rfield)

        # The precondition may suppress a control ONLY on an OBSERVED value.
        #
        # The first version suppressed on `None` too, which meant "we never
        # mapped this field" was read as "the feature is switched off". On the
        # weak Junos XML -- a device with `public` and `private` communities
        # plainly in the file -- `snmp.version` is simply not in that pack, so
        # the SNMPv3 controls silently became NOT_APPLICABLE. A false negative
        # manufactured from a gap in our own coverage is far worse than the
        # false positive it was meant to fix, and it is the same
        # absence-of-evidence mistake as the unconfigured M0 interface.
        if robs is None or robs.state is not ObservationState.OBSERVED:
            continue

        rval = robs.value
        if "equals" in req:
            satisfied = rval == req["equals"]
        elif "not_in" in req:
            satisfied = rval not in req["not_in"]
        else:
            satisfied = bool(rval)
        if not satisfied:
            return finding(
                ResultState.NOT_APPLICABLE,
                req.get("because")
                or f"precondition not met: {rfield} = {rval!r}, so this "
                   "control addresses a capability the device does not use",
                robs)

    obs = sbm.get(control.field)

    # A control names an unscoped field; the parser may have produced several
    # SCOPED instances of it (two vty ranges, three security groups). Evaluate
    # every instance and keep the WORST result.
    #
    # Without this, "management lines must accept SSH only" silently returned
    # UNKNOWN on a device whose vty lines all permitted telnet -- a critical
    # finding lost to a path-shape mismatch rather than to any real ambiguity.
    if obs is None:
        scoped = sbm.scoped_instances(control.field)
        if scoped:
            return _worst_of(control, scoped, finding, labels)

    # --- the absence cases: this is where a naive engine starts lying -------
    if obs is None:
        # The parser never looked at this field at all. We cannot claim the
        # device is compliant, and we cannot prove it is not.
        return finding(
            ResultState.UNKNOWN,
            f"{control.field} was never evaluated by any mapping rule",
        )

    if obs.state is ObservationState.UNPARSED:
        return finding(
            ResultState.UNKNOWN,
            f"{control.field} appeared in the config but could not be interpreted",
            obs,
        )

    if obs.state is ObservationState.NOT_OBSERVED:
        # Absent. Whether that is a FAIL depends on the control: for
        # "telnet must be disabled" absence is compliant; for "a banner must
        # exist" absence IS the violation. The operator decides, with None as
        # the observed value -- we do not shortcut to PASS.
        state = run_operator(control.operator, None, control.expected)
        reason = f"{control.field} not present in configuration"
        if state is ResultState.PASS:
            reason += " (absence satisfies this control)"
        return finding(state, reason, obs)

    # --- we have a value ----------------------------------------------------
    state = run_operator(control.operator, obs.value, control.expected)

    # Plan 7.3 / 6.5: a value we inferred rather than observed cannot carry a
    # FAIL on its own. Downgrade to UNKNOWN so an inference never masquerades
    # as a provable finding.
    if state is ResultState.FAIL and obs.state is ObservationState.DEFAULT_ASSUMED:
        return finding(
            ResultState.UNKNOWN,
            f"{control.field} was assumed from platform defaults, not observed; "
            "cannot prove a violation from an assumption",
            obs,
        )

    reason = ""
    if state is ResultState.PARTIAL:
        reason = f"partially satisfied: observed {obs.value!r}, expected {control.expected!r}"
    elif state is ResultState.ERROR:
        reason = f"operator {control.operator!r} failed on value {obs.value!r}"
    return finding(state, reason, obs)


_SEVERITY_ORDER = {
    ResultState.FAIL: 0,
    ResultState.PARTIAL: 1,
    ResultState.UNKNOWN: 2,
    ResultState.ERROR: 3,
    ResultState.PASS: 4,
    ResultState.NOT_APPLICABLE: 5,
    ResultState.MANUAL_REVIEW: 6,
}


def _worst_of(control, scoped: dict, finding, labels):
    """Evaluate every scoped instance; report the worst outcome.

    "Worst" means most actionable: a single vty line permitting telnet makes
    the device telnet-reachable, so one FAIL among five PASSes is a FAIL.
    """
    results = []
    for path, obs in scoped.items():
        if obs.state is ObservationState.UNPARSED:
            results.append((ResultState.UNKNOWN, path, obs))
            continue
        st = run_operator(control.operator, obs.value, control.expected)
        if st is ResultState.FAIL and obs.state is ObservationState.DEFAULT_ASSUMED:
            st = ResultState.UNKNOWN
        results.append((st, path, obs))

    results.sort(key=lambda r: _SEVERITY_ORDER.get(r[0], 9))
    state, path, obs = results[0]
    same = [p for st, p, _ in results if st is state]
    reason = (
        f"worst of {len(results)} scoped instance(s); {state.value} at "
        + ", ".join(_scope_label(p) for p in same[:3])
    )
    f = finding(state, reason, obs)
    return f


def _scope_label(path: str) -> str:
    import re
    m = re.search(r"\[([^\]]+)\]", path)
    return m.group(1) if m else path


def evaluate_all(
    controls: list[Control],
    sbm: SecurityBaselineModel,
    *,
    device: str,
    platform: str | None = None,
    iso_resolver=None,
    versions: dict[str, str] | None = None,
    not_applicable_domains: dict[str, str] | None = None,
    not_applicable_fields: list[str] | None = None,
) -> Assessment:
    return Assessment(
        assessment_id=sbm.assessment_id,
        device=device,
        platform=platform,
        findings=[
            evaluate_control(
                c, sbm, platform=platform, iso_resolver=iso_resolver,
                not_applicable_domains=not_applicable_domains,
                not_applicable_fields=not_applicable_fields,
            )
            for c in controls
        ],
        versions=versions or {},
    )
