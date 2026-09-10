"""Our controls, and the findings they produce.

Plan 6.1: one rulebook, four labels. We write the check once and attach four
framework labels. NIST is the universal spine; ISO is derived from it via the
official crosswalk; STIG and CIS identifiers are per-platform and therefore live
in the vendor pack, not in the rule.

v1.4 6.4 caveat, learned from the real STIG files: a control does NOT map 1:1
onto a STIG Vuln ID. `ip ssh version 2` lives in the fix text of V-215844 and
four separate rules touch SSH. Hence ``stig_ids`` is a list, and severity is
taken from the framework rather than guessed.
"""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from ..schema.enums import ResultState, Severity
from ..schema.evidence import EvidenceRef
from ..schema.observation import Observation


class FrameworkLabels(BaseModel):
    """What each framework calls this requirement."""

    model_config = {"frozen": True}

    nist_800_53: list[str] = Field(default_factory=list, description="AC-17(2), SC-8(1)")
    iso_27001: list[str] = Field(
        default_factory=list,
        description="Derived from NIST via the OLIR crosswalk -- never hand-written",
    )
    # Per-platform identifiers, resolved from the vendor pack at evaluation time.
    stig_ids: list[str] = Field(default_factory=list, description="V-215844, ...")
    cis_ids: list[str] = Field(default_factory=list, description="1.2.3, ...")

    def is_empty(self) -> bool:
        return not (self.nist_800_53 or self.iso_27001 or self.stig_ids or self.cis_ids)


class Control(BaseModel):
    """One thing we check. Vendor-neutral by construction."""

    model_config = {"frozen": True}

    id: str = Field(description="NCSA-SSH-002")
    title: str
    field: str = Field(description="SBM path, e.g. management.ssh.version")
    operator: str
    expected: Any = None
    severity: Severity
    frameworks: FrameworkLabels = Field(default_factory=FrameworkLabels)

    # Plan 6.5: a control that does not apply to a platform is NOT_APPLICABLE,
    # which is excluded from the score rather than counted as a pass.
    applies_to: list[str] = Field(
        default_factory=list, description="Platform keys; empty means all"
    )
    rationale: str = Field(default="", description="Our own words -- never framework prose")
    tier: str = Field(default="core", description="core | extended | category")

    # Deliverable 4c. Keyed by platform, so the fix for a Cisco router and the
    # fix for an SRX live beside the control they both satisfy -- and adding a
    # vendor stays a YAML edit, not a code change (requirement 5).
    # Each block: {commands: [...], verify: str, phase: int,
    #              management_impact: none|disables_http|disables_telnet|disables_ssh}
    remediation: dict = Field(default_factory=dict)

    # Preconditions. A control whose feature is switched off is NOT_APPLICABLE,
    # not FAIL -- see evaluate_control. Each entry:
    #   {field: snmp.enabled, equals: true, because: "..."}
    #   {field: snmp.version, not_in: [disabled, off]}
    requires: list = Field(default_factory=list)

    def applicable_to(self, platform: str | None) -> bool:
        return not self.applies_to or (platform in self.applies_to)


class Finding(BaseModel):
    """The result of evaluating one control against one device."""

    model_config = {"frozen": True}

    control_id: str
    title: str
    state: ResultState
    severity: Severity
    field: str
    observed: Any = None
    expected: Any = None
    evidence: list[EvidenceRef] = Field(default_factory=list)
    frameworks: FrameworkLabels = Field(default_factory=FrameworkLabels)
    reason: str = Field(
        default="",
        description="Why this state. Plan 14.4 gate 9: every UNKNOWN states a reason.",
    )
    confidence: float = 1.0

    def is_reportable_failure(self) -> bool:
        return self.state in (ResultState.FAIL, ResultState.PARTIAL)
