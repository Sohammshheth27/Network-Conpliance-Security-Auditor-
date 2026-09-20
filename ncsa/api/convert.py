"""DeviceAssessment -> the JSON contract.

Kept apart from the route handlers so the conversion is testable without a web
server, and so a UI developer can generate fixtures by calling one function.
"""
from __future__ import annotations

from .schemas import (AssessmentOut, ConsensusOut, CoverageOut, EvidenceOut,
                      FindingOut, FrameworkLabelsOut, IdentityOut,
                      RecordAccountingOut, RemediationOut, RemediationStepOut,
                      RiskOut, TrainingCandidateOut)


def evidence_out(ev) -> EvidenceOut:
    return EvidenceOut(file=getattr(ev, "file", "") or "",
                       line=getattr(ev, "line", None),
                       raw=getattr(ev, "raw", "") or "",
                       record_id=getattr(ev, "record_id", None))


def finding_out(f, risk=None) -> FindingOut:
    fw = f.frameworks
    return FindingOut(
        control_id=f.control_id, title=f.title, state=f.state.value,
        severity=getattr(f.severity, "value", str(f.severity)),
        field=f.field, observed=f.observed, expected=f.expected,
        reason=f.reason or "", confidence=f.confidence,
        evidence=[evidence_out(e) for e in (f.evidence or [])],
        frameworks=FrameworkLabelsOut(
            nist_800_53=list(fw.nist_800_53 or []),
            iso_27001=list(getattr(fw, "iso_27001", []) or []),
            stig_ids=list(getattr(fw, "stig_ids", []) or []),
            cis_ids=list(getattr(fw, "cis_ids", []) or [])),
        risk=(RiskOut(score=round(risk.score, 1), band=risk.band,
                      rationale=list(risk.rationale))
              if risk is not None else None),
        attack=_attack(f.control_id))


def _attack(control_id: str) -> list[dict]:
    # Tags are presentation: they never change a state or a score.
    from ..frameworks.attack import tags_for
    return tags_for(control_id)


def _framework_coverage(da) -> list[dict]:
    from ..frameworks.selection import framework_coverage
    return (framework_coverage(da.assessment.findings, da.identity.platform)
            if da.assessment else [])


def assessment_out(da, assessment_id: str) -> AssessmentOut:
    from ..engine.risk import score_assessment

    cov = da.coverage()
    objects, rels = da.graph_size()
    i = da.identity

    scored = score_assessment(da) if da.assessment else {"findings": [],
                                                         "total_risk": 0.0,
                                                         "worst": None}
    # Risk is attached per finding by control id. Only FAIL/PARTIAL have one;
    # UNKNOWN deliberately carries none.
    risk_by_id = {f.control_id: r for f, r in scored["findings"]}

    findings = []
    if da.assessment is not None:
        for f in da.assessment.findings:
            findings.append(finding_out(f, risk_by_id.get(f.control_id)))

    rec = da.records or {}
    unknown_rec = rec.get("UNKNOWN", 0)
    consensus = None
    if da.consensus is not None:
        consensus = ConsensusOut(**da.consensus.summary())

    return AssessmentOut(
        assessment_id=assessment_id,
        supported=da.supported,
        identity=IdentityOut(
            vendor=i.vendor, platform=i.platform, os=i.os, version=i.version,
            hostname=i.hostname, serial=i.serial, model=i.model,
            source_file=i.source_file, sha256=i.sha256),
        coverage=CoverageOut(**cov),
        records=RecordAccountingOut(
            source_records=da.total_records,
            parsed_records=da.total_records - unknown_rec,
            unreadable_records=unknown_rec,
            mapped_to_schema=rec.get("MAPPED", 0),
            parsed_not_mapped=rec.get("PARSED", 0),
            security_relevant_unmapped=da.training_gap()),
        counts=da.counts(),
        findings=findings,
        frameworks=getattr(da, "frameworks", None),
        framework_coverage=_framework_coverage(da),
        risk_total=scored.get("total_risk", 0.0),
        risk_worst=scored.get("worst"),
        consensus=consensus,
        objects=objects, relationships=rels,
        notes=list(da.notes or []))


def candidate_out(c) -> TrainingCandidateOut:
    return TrainingCandidateOut(
        name=c.name, occurrences=c.occurrences,
        sample_values=list(c.sample_values or []),
        evidence=(EvidenceOut(file=c.platform or "", line=c.evidence_line,
                              raw=c.evidence_raw)
                  if c.evidence_raw else None),
        vendor=c.vendor, platform=c.platform,
        suggested_field=c.suggested_field,
        suggestion_score=round(c.suggestion_score, 3),
        suggested_from=c.suggested_from,
        kind=getattr(c, "kind", "value"),
        status=getattr(c, "status", "PENDING"))


def remediation_out(plan) -> RemediationOut:
    def step(s) -> RemediationStepOut:
        return RemediationStepOut(
            control_id=s.control_id, title=s.title, commands=list(s.commands),
            phase=s.phase, verify=s.verify, risk_band=s.risk_band,
            management_impact=s.management_impact,
            lockout_warning=s.lockout_warning, deferred=s.deferred)

    return RemediationOut(
        platform=plan.platform,
        rollback_command=plan.rollback[0], rollback_note=plan.rollback[1],
        steps=[step(s) for s in plan.steps],
        deferred=[step(s) for s in plan.deferred],
        unavailable=list(plan.unavailable),
        lockout_checked=plan.lockout_checked,
        script=plan.script())
