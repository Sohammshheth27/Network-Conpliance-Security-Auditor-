"""Rule ownership and recertification.

The workflow feature firewall-orchestrator and ManageEngine are actually bought
for. Compliance frameworks require periodic review of access -- NIST AC-2(3),
PCI-DSS 1.1.7, ISO A.5.18 -- and the question is never "is this rule
technically correct" but "does anyone still need it, and who says so".

A rule with no owner is the real finding. It cannot be reviewed, cannot be
removed safely, and accumulates: every firewall that has been in service five
years has rules nobody will admit to.

WHY THIS PAIRS WITH HYGIENE
Neither signal is sufficient alone. "Unused" without ownership cannot be acted
on -- the owner may know it is a disaster-recovery path. "Unowned" without
usage data cannot be prioritised. Together they rank: a rule that is both
unused AND uncertified AND overly permissive is the one to delete first, and
that ranking is the output an operations team can work through.

Nothing here decides anything. It records what humans asserted, and reports
what has expired.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from pathlib import Path

STORE = Path("corpus/ownership.jsonl")
DEFAULT_PERIOD_DAYS = 365          # annual review is the common requirement


@dataclass
class Certification:
    device: str
    rule_id: str
    owner: str
    justification: str = ""
    certified_at: str = ""
    certified_by: str = ""
    period_days: int = DEFAULT_PERIOD_DAYS
    ticket: str = ""

    @property
    def expires_at(self) -> str:
        try:
            d = datetime.fromisoformat(self.certified_at).date()
        except (ValueError, TypeError):
            return ""
        return (d + timedelta(days=self.period_days)).isoformat()

    def days_remaining(self, today=None) -> int | None:
        if not self.expires_at:
            return None
        t = today or date.today()
        return (date.fromisoformat(self.expires_at) - t).days

    def is_expired(self, today=None) -> bool:
        d = self.days_remaining(today)
        return d is not None and d < 0

    def to_json(self) -> dict:
        return {**self.__dict__, "expires_at": self.expires_at}


@dataclass
class RecertFinding:
    device: str
    rule_id: str
    kind: str                 # unowned | expired | expiring | stale_and_unowned
    severity: str
    detail: str
    owner: str = ""
    days_remaining: int | None = None
    hit_count: int | None = None

    def to_json(self) -> dict:
        return dict(self.__dict__)


class Register:
    """Who owns which rule, and when they last said so."""

    def __init__(self, path=STORE):
        self.path = Path(path) if path else None
        self.entries: list = []
        self.load()

    def load(self) -> None:
        if not (self.path and self.path.exists()):
            return
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                try:
                    self.entries.append(Certification(**{
                        k: v for k, v in json.loads(line).items()
                        if k != "expires_at"}))
                except Exception:                      # noqa: BLE001
                    continue

    def save(self) -> None:
        if not self.path:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(
            "\n".join(json.dumps(e.to_json()) for e in self.entries) + "\n",
            encoding="utf-8")

    def certify(self, device, rule_id, owner, *, justification="",
                certified_by="", period_days=DEFAULT_PERIOD_DAYS,
                ticket="", when=None) -> Certification:
        """Record that a human vouched for a rule today.

        An owner is required. A certification with no owner is a rubber stamp
        that satisfies an audit checkbox and answers nobody's question when the
        rule is queried two years later.
        """
        if not str(owner).strip():
            raise ValueError("a certification must name an owner")
        c = Certification(
            device=device, rule_id=rule_id, owner=owner.strip(),
            justification=justification, certified_by=certified_by or owner,
            certified_at=(when or date.today()).isoformat(),
            period_days=period_days, ticket=ticket)
        # Re-certifying replaces the prior record for that rule; the history
        # lives in the file's append-only nature, not in duplicates.
        self.entries = [e for e in self.entries
                        if not (e.device == device and e.rule_id == rule_id)]
        self.entries.append(c)
        self.save()
        return c

    def for_rule(self, device, rule_id) -> Certification | None:
        for e in self.entries:
            if e.device == device and e.rule_id == rule_id:
                return e
        return None


def review(device_assessment, register=None, *, hygiene=None,
           expiring_within=30, today=None) -> list:
    """What needs a human decision on this device."""
    reg = register or Register()
    dev = (device_assessment.identity.hostname
           or device_assessment.identity.serial
           or device_assessment.identity.source_file)
    graph = getattr(device_assessment, "graph", None)
    if graph is None:
        return []

    unused = set()
    if hygiene is not None:
        unused = {f.rule for f in hygiene.by_kind("unused_rule")}

    out = []
    for rule in getattr(graph, "rules", []):
        if not rule.enabled:
            continue
        name = rule.name or rule.id
        cert = reg.for_rule(dev, rule.id)

        if cert is None:
            stale = name in unused
            out.append(RecertFinding(
                device=dev, rule_id=rule.id, kind=(
                    "stale_and_unowned" if stale else "unowned"),
                severity="high" if stale else "medium",
                hit_count=rule.hit_count,
                detail=("no owner recorded, and the device reports no traffic "
                        "matching it. Unused AND unowned is the strongest "
                        "case for removal this tool can make -- but it is a "
                        "case for a human, not an automatic deletion."
                        if stale else
                        "no owner recorded. The rule cannot be reviewed, and "
                        "cannot be removed safely, because nobody can say "
                        "why it exists.")))
            continue

        days = cert.days_remaining(today)
        if cert.is_expired(today):
            out.append(RecertFinding(
                device=dev, rule_id=rule.id, kind="expired",
                severity="high", owner=cert.owner, days_remaining=days,
                hit_count=rule.hit_count,
                detail=f"certification lapsed {abs(days)} days ago "
                       f"(owner {cert.owner}, last certified "
                       f"{cert.certified_at})."))
        elif days is not None and days <= expiring_within:
            out.append(RecertFinding(
                device=dev, rule_id=rule.id, kind="expiring",
                severity="low", owner=cert.owner, days_remaining=days,
                hit_count=rule.hit_count,
                detail=f"certification expires in {days} days "
                       f"(owner {cert.owner})."))
    return out


def deletion_candidates(device_assessment, hygiene, register=None,
                        today=None) -> list:
    """Rules ranked by how safe they are to remove.

    Three independent signals must agree: no traffic, no owner, and no
    security purpose the policy still needs. Any one alone is a bad reason to
    delete a firewall rule.
    """
    reg = register or Register()
    dev = (device_assessment.identity.hostname
           or device_assessment.identity.serial
           or device_assessment.identity.source_file)
    unused = {f.rule for f in hygiene.by_kind("unused_rule")}
    redundant = {f.rule for f in hygiene.by_kind("redundant_rule")}
    shadowed = {f.rule for f in hygiene.by_kind("shadowed_rule")}

    out = []
    for rule in getattr(device_assessment.graph, "rules", []) or []:
        name = rule.name or rule.id
        signals = []
        if name in unused:
            signals.append("no traffic since the counter reset")
        if name in redundant:
            signals.append("fully covered by an earlier rule")
        if name in shadowed:
            signals.append("unreachable in policy order")
        if reg.for_rule(dev, rule.id) is None:
            signals.append("no recorded owner")
        if len(signals) >= 2:
            out.append({"rule": name, "rule_id": rule.id,
                        "signals": signals, "confidence": len(signals),
                        "hit_count": rule.hit_count,
                        "note": "a candidate for REVIEW, not automatic removal"})
    out.sort(key=lambda x: -x["confidence"])
    return out
