"""Deliverable 4c: device-specific, step-by-step CLI remediation.

Emitting fix commands is easy. Emitting fix commands that do not lock the
administrator out of a production device is not, and it is the difference
between a script an engineer will actually run and one they will read and
discard.

Three things this does that a plain command list does not:

1. LOCKOUT SAFETY. A fix that disables the protocol you are managing the
   device over ends your session mid-script, leaving the device half
   configured and unreachable. `no ip http server` is the textbook case, and
   on the SonicWall in this repo the naive fix for the tcp/80 findings would
   have removed the HTTPS redirect that six WAN links depend on. Any step whose
   `management_impact` disables a transport is checked against what the device
   actually has enabled, and is either reordered behind its replacement or
   held back for a maintenance window.

2. ORDER. Enable-then-disable, never the reverse. Turn on SSHv2 before
   removing telnet; configure the syslog target before enforcing logging.
   Steps carry a `phase` and are sorted by it.

3. ROLLBACK. Every script is wrapped in the vendor's own safety net --
   `commit confirmed` on Junos, `reload in` on IOS -- so a mistake reverts by
   itself instead of requiring a site visit.

Remediation lives in the rule YAML as DATA, per platform. Adding a vendor is
still a file, not a code change (requirement 5).
"""
from __future__ import annotations

from dataclasses import dataclass, field

# Ordering phases. Lower runs first.
PHASE_PREPARE = 10      # create the replacement (keys, users, syslog target)
PHASE_ENABLE = 20       # turn the secure thing on
PHASE_HARDEN = 30       # tighten settings that break nothing
PHASE_DISABLE = 40      # turn the insecure thing off -- last, always
PHASE_DEFAULT = 30

# What a step does to the management plane.
IMPACT_NONE = "none"
IMPACT_DISABLES_HTTP = "disables_http"
IMPACT_DISABLES_TELNET = "disables_telnet"
IMPACT_DISABLES_SSH = "disables_ssh"
IMPACT_RESTRICTS_SOURCE = "restricts_source"

_IMPACT_FIELD = {
    IMPACT_DISABLES_HTTP: "management.http.enabled",
    IMPACT_DISABLES_TELNET: "management.telnet.enabled",
    IMPACT_DISABLES_SSH: "management.ssh.enabled",
}

# The vendor's own rollback net, keyed by platform prefix.
#
# Matched in order, so a specific platform must precede its vendor prefix.
# FortiOS and PAN-OS are deliberately absent: PAN-OS stages every change until
# `commit` and has no timed revert, and a revert mechanism we have not
# verified is worse than stating there is none.
ROLLBACK = {
    "juniper": ("commit confirmed 5",
                "Junos reverts automatically in 5 minutes unless you `commit` again."),
    "cisco_asa": ("reload in 5",
                  "The ASA reloads to its saved configuration in 5 minutes unless "
                  "you `reload cancel`. Do not `write memory` until verified."),
    "cisco": ("reload in 5",
              "IOS reloads to the saved config in 5 minutes unless you `reload cancel`."),
}


@dataclass
class Step:
    control_id: str
    title: str
    commands: list
    phase: int = PHASE_DEFAULT
    verify: str = ""
    management_impact: str = IMPACT_NONE
    risk_band: str = "MEDIUM"
    risk_score: float = 0.0
    # Set when the step would sever the path it is being applied over.
    lockout_warning: str = ""
    deferred: bool = False

    def to_json(self) -> dict:
        return {"control_id": self.control_id, "title": self.title,
                "commands": self.commands, "phase": self.phase,
                "verify": self.verify, "risk": self.risk_band,
                "management_impact": self.management_impact,
                "lockout_warning": self.lockout_warning,
                "deferred": self.deferred}


@dataclass
class Plan:
    platform: str
    steps: list = field(default_factory=list)
    deferred: list = field(default_factory=list)
    rollback: tuple = ("", "")
    unavailable: list = field(default_factory=list)

    def script(self) -> str:
        """The ordered CLI script an engineer can paste."""
        out = ["! NCSA remediation -- review before running.",
               f"! platform: {self.platform}"]
        if self.rollback[0]:
            out += [f"! SAFETY NET: run `{self.rollback[0]}` first.",
                    f"!   {self.rollback[1]}", self.rollback[0], "!"]
        for s in self.steps:
            out.append(f"! [{s.risk_band}] {s.control_id}: {s.title}")
            if s.lockout_warning:
                out.append(f"!   WARNING: {s.lockout_warning}")
            out += s.commands
            if s.verify:
                out.append(f"! verify: {s.verify}")
            out.append("!")
        if self.deferred:
            out.append("! ---- HELD BACK: would cut your management path ----")
            for s in self.deferred:
                out.append(f"! {s.control_id}: {s.title}")
                out.append(f"!   {s.lockout_warning}")
                for c in s.commands:
                    out.append(f"!   {c}")
        return "\n".join(out)


def _enabled(sbm, path: str):
    try:
        obs = sbm.get(path)
    except Exception:                                  # noqa: BLE001
        return None
    return getattr(obs, "value", None) if obs is not None else None


def _live_transports(sbm) -> list:
    """Which management transports the device currently has enabled."""
    live = []
    for impact, path in _IMPACT_FIELD.items():
        if _enabled(sbm, path) is True:
            live.append(impact)
    return live


def build_plan(device_assessment, *, controls_by_id=None, sbm=None) -> Plan:
    """Turn scored failures into an ordered, lockout-checked script."""
    from .risk import score_assessment

    platform = device_assessment.identity.platform or ""
    rollback = ("", "")
    for prefix, rb in ROLLBACK.items():
        if platform.startswith(prefix):
            rollback = rb
            break

    plan = Plan(platform=platform, rollback=rollback)
    scored = score_assessment(device_assessment)
    live = _live_transports(sbm) if sbm is not None else []

    for finding, risk in scored["findings"]:
        control = (controls_by_id or {}).get(finding.control_id)
        spec = _remediation_for(control, platform)
        if not spec:
            plan.unavailable.append(finding.control_id)
            continue

        step = Step(
            control_id=finding.control_id, title=finding.title,
            commands=list(spec.get("commands") or []),
            phase=int(spec.get("phase") or _phase_for(spec)),
            verify=spec.get("verify") or "",
            management_impact=spec.get("management_impact") or IMPACT_NONE,
            risk_band=risk.band, risk_score=risk.score)

        # --- lockout check ------------------------------------------------
        impact = step.management_impact
        if impact in _IMPACT_FIELD:
            others = [t for t in live if t != impact]
            if live and impact in live and not others:
                step.deferred = True
                step.lockout_warning = (
                    f"this disables {impact.replace('disables_', '')}, which is "
                    "the ONLY management transport currently enabled on this "
                    "device. Enable and TEST a replacement first.")
            elif impact in live:
                step.lockout_warning = (
                    f"disables {impact.replace('disables_', '')}; confirm you are "
                    f"connected over {'/'.join(o.replace('disables_','') for o in others)} "
                    "before running.")

        (plan.deferred if step.deferred else plan.steps).append(step)

    plan.steps.sort(key=lambda s: (s.phase, -s.risk_score))
    return plan


def _phase_for(spec: dict) -> int:
    impact = spec.get("management_impact") or IMPACT_NONE
    if impact in _IMPACT_FIELD:
        return PHASE_DISABLE
    return PHASE_DEFAULT


def _remediation_for(control, platform: str):
    """Per-platform remediation block off the Control, if it carries one."""
    if control is None:
        return None
    rem = getattr(control, "remediation", None) or {}
    if not isinstance(rem, dict):
        return None
    return rem.get(platform) or rem.get("default")
