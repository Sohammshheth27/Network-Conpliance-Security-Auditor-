"""Results of the extended checks: VPN, wireless, known vulnerabilities.

WHY THESE SIT OUTSIDE THE COMPLIANCE SCORE
------------------------------------------
The compliance score is PASS / decided over the 88-control catalogue, and
coverage is decided / 88. Adding a VPN or wireless control to that catalogue
would move every device's score and coverage -- including assessments already
reported and signed off. So the extended checks are reported beside the score,
never inside it, with the same seven result states and the same evidence
discipline. A reader sees both; neither silently changes the other.

THE SAME STATES, THE SAME RULES
-------------------------------
  PASS / FAIL / PARTIAL     decided from a value read off the device
  NOT_APPLICABLE            does not apply, with the reason stated
  UNKNOWN                   could not be decided, with the reason stated
  MANUAL_REVIEW             a person has to judge intent

A value we cannot decode stays UNKNOWN. Guessing what a vendor's private code
means, and then failing a device on the guess, is the one mistake this layer
must not make.
"""
from __future__ import annotations

from dataclasses import dataclass, field

#: Cloud firewall-rule exports. They describe packet filters only: no tunnels,
#: no radios, no customer firmware.
CLOUD_PLATFORMS = frozenset({"aws", "security_groups",
                             "network_security_groups", "gcp_firewall"})

STATES = ("PASS", "FAIL", "PARTIAL", "NOT_APPLICABLE", "UNKNOWN",
          "MANUAL_REVIEW", "ERROR")
SEVERITIES = ("critical", "high", "medium", "low", "info")


@dataclass
class ExtendedFinding:
    """One check, against one object -- a tunnel, a wireless network, a device."""

    check_id: str
    title: str
    domain: str
    state: str
    severity: str
    scope: str
    reason: str
    observed: object = None
    expected: object = None
    evidence: list = field(default_factory=list)       # list[EvidenceRef]
    nist_800_53: list = field(default_factory=list)
    attack: list = field(default_factory=list)          # MITRE ATT&CK ids
    rationale: str = ""

    def __post_init__(self):
        if self.state not in STATES:
            raise ValueError(f"{self.check_id}: unknown state {self.state!r}")
        if self.severity not in SEVERITIES:
            raise ValueError(f"{self.check_id}: unknown severity {self.severity!r}")
        # A failure nobody can locate is not a finding an administrator can act
        # on. The compliance engine enforces the same rule.
        if self.state in ("FAIL", "PARTIAL") and not self.evidence:
            raise ValueError(f"{self.check_id} [{self.scope}]: a {self.state} "
                             "must carry evidence")

    def to_json(self) -> dict:
        return {
            "check_id": self.check_id, "title": self.title,
            "domain": self.domain, "state": self.state,
            "severity": self.severity, "scope": self.scope,
            "reason": self.reason, "observed": self.observed,
            "expected": self.expected, "rationale": self.rationale,
            "nist_800_53": list(self.nist_800_53),
            "attack": list(self.attack),
            "evidence": [{"file": e.file, "line": e.line,
                          "record": e.record_id, "raw": e.raw}
                         for e in self.evidence],
        }


@dataclass
class DomainResult:
    """Everything one extended domain found on one device."""

    domain: str
    #: True / False / None. None means we could not tell -- which is different
    #: from the device having none, and is reported as such.
    present: bool | None
    summary: str
    findings: list = field(default_factory=list)        # list[ExtendedFinding]
    inventory: list = field(default_factory=list)       # plain dicts
    notes: list = field(default_factory=list)
    #: Where this adapter has been validated. "real device" or "fixture" --
    #: the project rule is to say which, every time.
    validated_on: str = ""

    def counts(self) -> dict:
        out = {s: 0 for s in STATES}
        for f in self.findings:
            out[f.state] += 1
        return {k: v for k, v in out.items() if v}

    def to_json(self) -> dict:
        return {"domain": self.domain, "present": self.present,
                "summary": self.summary, "counts": self.counts(),
                "validated_on": self.validated_on,
                "inventory": self.inventory, "notes": self.notes,
                "findings": [f.to_json() for f in self.findings]}


def roll_up(states: list[str]) -> str:
    """Several scoped results into one headline, as the compliance engine does.

    All pass -> PASS; all fail -> FAIL; a mix -> PARTIAL. Anything undecided
    alongside a failure is still a failure somewhere, so FAIL wins over it.
    """
    decided = [s for s in states if s in ("PASS", "FAIL", "PARTIAL")]
    if not decided:
        for s in ("MANUAL_REVIEW", "UNKNOWN", "NOT_APPLICABLE"):
            if s in states:
                return s
        return "UNKNOWN"
    if all(s == "PASS" for s in decided):
        return "PASS"
    if all(s == "FAIL" for s in decided):
        return "FAIL"
    return "PARTIAL"
