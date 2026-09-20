"""The JSON contract. This file is the interface other work builds against.

Written before any UI exists, deliberately: if a front end and a back end are
built simultaneously against assumed shapes, neither is wrong and nothing
integrates.

THREE INVARIANTS THE UI MUST NOT UNDO. They are the product's credibility, and
a dashboard can erase them by accident in a way the engine cannot:

 1. `score_pct` is the pass rate over controls we could DECIDE. It is not
    compliance. `assessed_pct` says how much of the APPLICABLE control set
    that was (controls the platform cannot have are excluded), and
    the two must always appear together. A tool that shows 60% without saying
    it assessed 46% of the device is claiming something it did not measure.

 2. UNKNOWN is not a pass and not a fail. It must never render green, and must
    never be folded into the score. It is the honest statement that we could
    not tell -- which is the thing that makes the other numbers trustworthy.

 3. Every finding carries its evidence: file, line, and the raw text. A finding
    without evidence is an assertion; with it, a reviewer can check us. The
    field is not optional in this schema for that reason.
"""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field, SecretStr


class CollectIn(BaseModel):
    """Live collection request (ncsa/collect/live.py).

    Credentials are SecretStr so they never appear in a repr, a log line or a
    validation error. They are used for one SSH session and not stored.
    """
    host: str = Field(description="IP address or DNS name")
    platform: str = Field(description="Selects the SSH driver; the fingerprint "
                                      "still decides which pack applies")
    username: str
    password: SecretStr
    secret: SecretStr | None = Field(default=None, description="Enable secret, Cisco only")
    port: int = 22
    driver: str = Field(default="netmiko", description="netmiko | napalm")
    redact: bool = True
    frameworks: list[str] | None = None


class MonitorIn(CollectIn):
    """A scheduled re-collection job (ncsa/collect/monitor.py). The password
    is stored encrypted and never returned."""
    interval_minutes: int = Field(default=60, description="At least 15")


class EvidenceOut(BaseModel):
    file: str
    line: int | None = None
    raw: str
    record_id: str | None = Field(
        default=None,
        description="Structural path for non-line formats (XPath, JSONPath)")


class FrameworkLabelsOut(BaseModel):
    nist_800_53: list[str] = Field(default_factory=list)
    iso_27001: list[str] = Field(default_factory=list)
    stig_ids: list[str] = Field(default_factory=list)
    cis_ids: list[str] = Field(
        default_factory=list,
        description="CIS recommendation NUMBERS only. CIS prose is "
                    "copyrighted and must never cross this boundary.")


class RiskOut(BaseModel):
    score: float
    band: str = Field(description="CRITICAL | HIGH | MEDIUM | LOW")
    rationale: list[str] = Field(
        default_factory=list,
        description="How the score was reached: severity, exposure, confidence")


class FindingOut(BaseModel):
    control_id: str
    title: str
    state: str = Field(description="PASS|FAIL|PARTIAL|NOT_APPLICABLE|"
                                   "UNKNOWN|MANUAL_REVIEW|ERROR")
    severity: str
    field: str
    observed: Any = None
    expected: Any = None
    reason: str = ""
    confidence: float = 1.0
    evidence: list[EvidenceOut] = Field(default_factory=list)
    frameworks: FrameworkLabelsOut = Field(default_factory=FrameworkLabelsOut)
    risk: RiskOut | None = Field(
        default=None,
        description="Present only for FAIL/PARTIAL. UNKNOWN carries no risk "
                    "score: a number there would imply we knew.")
    attack: list[dict] = Field(
        default_factory=list,
        description="MITRE ATT&CK techniques this control stands in front of, "
                    "resolved against the bundle on disk. Empty for controls "
                    "that prevent no specific technique.")


class IdentityOut(BaseModel):
    vendor: str
    platform: str
    os: str | None = None
    version: str | None = None
    hostname: str | None = None
    serial: str | None = Field(
        default=None,
        description="null when the configuration does not state one. A "
                    "running config usually does not; it comes from `show "
                    "version`. Never substitute a placeholder.")
    model: str | None = None
    source_file: str
    sha256: str


class RecordAccountingOut(BaseModel):
    """Plan 14.1: total == parsed + unknown, and mapped is a subset of parsed."""

    source_records: int
    parsed_records: int
    unreadable_records: int
    mapped_to_schema: int
    parsed_not_mapped: int
    security_relevant_unmapped: int = Field(
        description="Distinct setting NAMES we read but cannot interpret. The "
                    "size of the training queue, and the honest size of the "
                    "gap -- counted in names, not records.")


class CoverageOut(BaseModel):
    controls_total: int
    controls_applicable: int = Field(
        default=0,
        description="Controls that apply to this platform: total minus "
                    "NOT_APPLICABLE (each of which carries its reason).")
    controls_decided: int
    controls_undecided: int
    not_applicable: int
    assessed_pct: float = Field(
        description="Decided controls as a share of the APPLICABLE ones. "
                    "Undecided controls stay in the denominator; controls "
                    "that cannot exist on this platform do not. ALWAYS show "
                    "this next to score_pct.")
    score_pct: float | None = Field(
        default=None,
        description="Pass rate over DECIDED controls only. null when nothing "
                    "could be decided -- never render null as 0%.")


class ConsensusOut(BaseModel):
    total: int = 0
    confirmed: int = 0
    disputed: int = 0
    uncorroborated: int = 0
    dispute_rate_pct: float = 0.0
    pack_coverage_gaps: int = 0


class AssessmentOut(BaseModel):
    assessment_id: str
    supported: bool = Field(
        description="false means no pack exists for this vendor. NOT an "
                    "error: universal findings and the training queue are "
                    "still populated.")
    identity: IdentityOut
    coverage: CoverageOut
    records: RecordAccountingOut
    counts: dict = Field(default_factory=dict)
    findings: list[FindingOut] = Field(default_factory=list)
    risk_total: float = 0.0
    risk_worst: str | None = None
    consensus: ConsensusOut | None = None
    objects: int = 0
    relationships: int = 0
    notes: list[str] = Field(default_factory=list)
    frameworks: list[str] | None = Field(
        default=None,
        description="Frameworks the user selected; null means all of them.")
    framework_coverage: list[dict] = Field(
        default_factory=list,
        description="Per framework: controls citing it, decided, passed, score.")


class TrainingCandidateOut(BaseModel):
    name: str
    occurrences: int
    sample_values: list = Field(default_factory=list)
    evidence: EvidenceOut | None = None
    vendor: str = ""
    platform: str = ""
    suggested_field: str | None = None
    suggestion_score: float = 0.0
    suggested_from: str = ""
    status: str = "PENDING"
    kind: str = Field(default="value",
                      description="value | keys (a table whose keys are the values)")


class ApprovalIn(BaseModel):
    """One human decision. Approvals are hash-chained and regression-gated."""

    setting_name: str
    field: str
    platform: str
    approved_by: str
    value_hint: Any = None
    kind: str = "value"
    #: Set only when teaching a vendor that has no pack yet.
    vendor: str | None = None
    reader: str | None = None
    signature: list[str] = Field(default_factory=list)
    #: The assessment the approval came from, so a new vendor's signature can
    #: be checked against that device's own file before anything is written.
    assessment_id: str | None = None


class ApprovalOut(BaseModel):
    accepted: bool
    reason: str = ""
    registry_version: str = ""
    regression: dict = Field(
        default_factory=dict,
        description="What the golden corpus said. An approval that would flip "
                    "a verified result is BLOCKED and reports which one.")


class RemediationStepOut(BaseModel):
    control_id: str
    title: str
    commands: list[str]
    phase: int = Field(description="10 prepare, 20 enable, 30 harden, "
                                   "40 disable-last")
    verify: str = ""
    risk_band: str = "MEDIUM"
    management_impact: str = "none"
    lockout_warning: str = ""
    deferred: bool = Field(
        default=False,
        description="Held back: would sever the only management path. Render "
                    "these separately -- they are not part of the script.")


class RemediationOut(BaseModel):
    platform: str
    rollback_command: str = ""
    rollback_note: str = ""
    steps: list[RemediationStepOut] = Field(default_factory=list)
    deferred: list[RemediationStepOut] = Field(default_factory=list)
    unavailable: list[str] = Field(
        default_factory=list,
        description="Controls with no remediation written yet. Listed, never "
                    "invented.")
    lockout_checked: bool = Field(
        default=False,
        description="Whether steps were checked against the transports the "
                    "device actually has enabled. FALSE means no step was "
                    "checked, so an empty `lockout_warning` on a step proves "
                    "nothing.")
    script: str = ""


# --------------------------------------------------------------- analysis in
class ReachQueryIn(BaseModel):
    """One reachability question against a single device.

    Either address form or zone form is acceptable; a device that models zones
    but not addresses can still answer, and vice versa. Nothing is defaulted to
    "any" -- an omitted field means the question did not constrain it, which is
    different from asserting it matches everything.
    """

    source: str | None = Field(default=None, description="10.10.0.5 or 10.10.0.0/24")
    destination: str | None = Field(default=None, description="10.20.0.9 or a CIDR")
    port: int | None = Field(default=None, ge=0, le=65535)
    protocol: str | None = Field(default=None, description="tcp / udp / icmp")
    source_zone: str | None = None
    destination_zone: str | None = None


class TopologyIn(BaseModel):
    """Build a fabric from several already-assessed devices.

    `assessment_ids` are ids returned by /assess. Supplying `source` and
    `destination` additionally asks an end-to-end question across the fabric.
    """

    assessment_ids: list[str] = Field(min_length=1)
    source: str | None = None
    destination: str | None = None
    port: int | None = Field(default=None, ge=0, le=65535)
    protocol: str | None = None
