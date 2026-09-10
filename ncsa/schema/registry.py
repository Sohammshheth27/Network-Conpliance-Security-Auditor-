"""Field registry -- reconciles the declared SBM against what can actually be produced.

THE PROBLEM THIS SOLVES
-----------------------
The SBM declared 91 fields. The packs could populate 43. Controls read 26. The
corpus covered 20. Nothing reconciled those numbers, so three separate metrics
were computed against a field space half of which was unreachable:

  * plan 14.2 control coverage divided by a fictional denominator
  * guardrail 3 handed the model an enum containing fields no reader can emit,
    inviting it to pick one (and it does -- it never abstains by preference)
  * three controls read fields no pack writes, so they returned UNKNOWN on every
    vendor, forever, and looked like parser gaps rather than dead wiring

STATUS IS DERIVED, NOT DECLARED
-------------------------------
A second hand-maintained list would drift from the packs within a week. Instead
``reconcile()`` reads the packs and the rules at load time and computes status.
The only thing a human maintains is the ROADMAP set below -- fields we have
deliberately not implemented, which must be justified rather than merely absent.
"""
from __future__ import annotations

from enum import Enum
from pathlib import Path

from pydantic import BaseModel, Field

from .sbm import FIELD_TYPES

PACKS_DIR = Path(r"E:\NCSA\packs")
RULES_DIR = Path(r"E:\NCSA\rules")


class FieldStatus(str, Enum):
    ACTIVE = "ACTIVE"        # at least one pack can populate it
    ORPHAN = "ORPHAN"        # a control reads it, no pack writes it -- BROKEN
    UNUSED = "UNUSED"        # a pack writes it, no control reads it -- collected, unchecked
    ROADMAP = "ROADMAP"      # declared deliberately, not yet implemented
    DEAD = "DEAD"            # nothing writes it, nothing reads it, not on the roadmap


# Fields we have deliberately NOT implemented, each with the reason. A field
# here is a decision; a field that falls through to DEAD is an oversight.
ROADMAP: dict[str, str] = {
    "crypto.ipsec_proposals":       "VPN configuration -- out of MVP scope (plan 6.6 extended tier)",
    "routing.bgp_auth":             "RTR STIG territory -- plan 6.3 puts routing out of MVP scope",
    "routing.ospf_auth":            "RTR STIG territory -- plan 6.3 puts routing out of MVP scope",
    "firewall.nat_rules":           "NAT modelling explicitly deferred by plan 15.4",
    "platform.api.enabled":         "needs the vendor API, not the config file (plan 4.2)",
    "services.unused_enabled":      "requires a per-platform service inventory we do not have",
    "security.cfs.enabled":         "SonicWall content filtering -- not in our sanitised export",
    "authentication.mfa.admin_required": "not present in any demo-vendor config we hold",
    "management.https.cert_source": "certificate provenance needs the appliance API",
    "cloud.security_groups.is_default": "derivable, but no control needs it yet",
    "authorization.privilege_levels": "Cisco privilege levels -- extended tier",
    "device.serial":                "plan 16.4: serials come from `show version`, not running-config",
}


class FieldSpec(BaseModel):
    name: str
    type: str
    status: FieldStatus
    written_by: list[str] = Field(default_factory=list)
    read_by: list[str] = Field(default_factory=list)
    note: str = ""


class FieldRegistry(BaseModel):
    fields: dict[str, FieldSpec] = Field(default_factory=dict)

    # ------------------------------------------------------------------ views
    def active(self) -> list[str]:
        """Fields a reader can actually produce. THIS is the LLM enum and the
        denominator for coverage -- not the full declared list."""
        return sorted(f.name for f in self.fields.values()
                      if f.status in (FieldStatus.ACTIVE, FieldStatus.UNUSED))

    def orphans(self) -> list[FieldSpec]:
        return [f for f in self.fields.values() if f.status is FieldStatus.ORPHAN]

    def dead(self) -> list[FieldSpec]:
        return [f for f in self.fields.values() if f.status is FieldStatus.DEAD]

    def counts(self) -> dict[str, int]:
        out = {s.value: 0 for s in FieldStatus}
        for f in self.fields.values():
            out[f.status.value] += 1
        return out

    def report(self) -> str:
        c = self.counts()
        lines = ["SBM FIELD RECONCILIATION", ""]
        lines.append(f"  declared            {len(self.fields)}")
        lines.append(f"  ACTIVE   (pack writes, control reads)   {c['ACTIVE']}")
        lines.append(f"  UNUSED   (pack writes, no control)      {c['UNUSED']}")
        lines.append(f"  ORPHAN   (control reads, no pack)       {c['ORPHAN']}   <- broken")
        lines.append(f"  ROADMAP  (deliberately deferred)        {c['ROADMAP']}")
        lines.append(f"  DEAD     (unreferenced, unjustified)    {c['DEAD']}   <- remove or justify")
        lines.append("")
        lines.append(f"  usable field space (LLM enum, coverage denominator): {len(self.active())}")
        if self.orphans():
            lines.append("")
            lines.append("  ORPHANS -- these controls can only ever return UNKNOWN:")
            for f in self.orphans():
                lines.append(f"    {f.name:<34} read by {', '.join(f.read_by)}")
        if self.dead():
            lines.append("")
            lines.append("  DEAD -- declared but unreachable and unjustified:")
            for f in self.dead():
                lines.append(f"    {f.name}")
        return "\n".join(lines)


def reconcile(packs_dir: Path = PACKS_DIR, rules_dir: Path = RULES_DIR) -> FieldRegistry:
    import yaml

    written: dict[str, list[str]] = {}
    for p in sorted(packs_dir.glob("*.yaml")):
        d = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        for m in (d.get("mappings") or []) + (d.get("derivations") or []):
            written.setdefault(m["field"], []).append(p.stem)

    # The graph bridge is a writer too. Counting only YAML packs marked every
    # bridge-populated field DEAD -- a defect in the metric, not the schema.
    from ..graph import bridge as _bridge
    import inspect
    bridge_src = inspect.getsource(_bridge)
    for name in FIELD_TYPES:
        if f'"{name}"' in bridge_src or f"firewall.rules[{{scope}}]" in bridge_src and name.startswith("firewall.rules."):
            written.setdefault(name, []).append("graph-bridge")
    for leaf in ("id", "action", "source", "destination", "service",
                 "position", "direction", "log"):
        written.setdefault(f"firewall.rules.{leaf}", []).append("graph-bridge")
    for extra in ("firewall.zones", "interfaces.zone", "firewall.rules_unevaluable"):
        written.setdefault(extra, []).append("graph-bridge")

    read: dict[str, list[str]] = {}
    for p in sorted(rules_dir.rglob("*.yaml")):
        d = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        read.setdefault(d["field"], []).append(d["id"])

    reg = FieldRegistry()
    for name, ftype in FIELD_TYPES.items():
        w, r = written.get(name, []), read.get(name, [])
        if w and r:
            status = FieldStatus.ACTIVE
        elif w:
            status = FieldStatus.UNUSED
        elif r:
            status = FieldStatus.ORPHAN
        elif name in ROADMAP:
            status = FieldStatus.ROADMAP
        else:
            status = FieldStatus.DEAD
        reg.fields[name] = FieldSpec(
            name=name, type=ftype, status=status,
            written_by=w, read_by=r, note=ROADMAP.get(name, ""),
        )
    return reg


def assert_no_orphans(reg: FieldRegistry) -> None:
    """Fail loudly. A control that can never fire is worse than a missing one:
    it occupies a row in the coverage matrix and reports UNKNOWN forever."""
    orphans = reg.orphans()
    if orphans:
        detail = "; ".join(f"{o.name} (read by {', '.join(o.read_by)})" for o in orphans)
        raise ValueError(f"{len(orphans)} orphaned control field(s): {detail}")
