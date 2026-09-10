"""Rule hygiene: dead, shadowed, redundant and over-broad policy.

THE GAP THIS CLOSES. Every comparable product -- Batfish, firewall-orchestrator,
ManageEngine, AlgoSec -- leads with this analysis, and NCSA did none of it while
sitting on all the data required. One real appliance in this repo carries 329
rules, ordering for all of them, and a per-rule packet counter; 227 enabled
rules on it have never matched a single packet.

None of this is machine learning and none of it should be. Shadowing is set
containment over resolved address and service sets, evaluated in policy order.
It is decidable, explainable, and either right or wrong -- which is what an
auditor needs from a finding that says "delete this rule".

WHAT IS DELIBERATELY NOT CLAIMED
A hit counter resets when the device reboots or when an operator clears it. A
rule with zero hits is therefore evidence of DISUSE SINCE THE COUNTER RESET,
not proof the rule is unnecessary -- a disaster-recovery rule may be correctly
unused for years. Findings say so, and carry the counter, so a reviewer can
weigh it against uptime rather than trust a label.

And containment is only decidable when BOTH rules resolved completely. A rule
referencing a group whose membership the export omits is UNEVALUABLE, never
"not shadowed": reporting a clean bill of health for policy we could not read
is the failure this project has caught six times.

EVALUATION ORDER IS A PLATFORM PROPERTY, NOT A FIELD
Containment analysis assumes the policy is evaluated in the order given. That
assumption is FALSE on SonicOS, which auto-sorts access rules by specificity
within a zone pair, so a broad rule with a lower priority number does not
necessarily precede a narrow one. The device's own counters exposed this: rule
#13 (any/any/any, priority 14) covers rule #18 by pure set logic, and #18 has
4,150,371 matches -- impossible if #13 were truly evaluated first.

Those cases are reported as `disputed_shadow` rather than dropped, because they
say something true and useful: on this platform a containment finding is
ADVISORY. The corroboration is what makes that visible. Measured on a real
appliance, 31 of 31 containment findings had zero hits against an 85% base rate
(p < 0.01), so the signal is real -- but the four disputes are the honest edge
of it, and hiding them would have hidden the ordering bug too.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .resolve import Resolver

ANY = "*"          # the universal set, kept explicit rather than implied


@dataclass
class HygieneFinding:
    kind: str
    rule: str
    detail: str
    severity: str = "medium"
    related: str = ""
    evidence: list = field(default_factory=list)
    hit_count: int | None = None

    def to_json(self) -> dict:
        return {"kind": self.kind, "rule": self.rule, "detail": self.detail,
                "severity": self.severity, "related": self.related,
                "hit_count": self.hit_count}


@dataclass
class HygieneReport:
    findings: list = field(default_factory=list)
    unevaluable: list = field(default_factory=list)
    rules_examined: int = 0
    rules_resolved: int = 0

    def by_kind(self, kind: str) -> list:
        return [f for f in self.findings if f.kind == kind]

    def summary(self) -> dict:
        kinds: dict = {}
        for f in self.findings:
            kinds[f.kind] = kinds.get(f.kind, 0) + 1
        return {"rules_examined": self.rules_examined,
                "rules_fully_resolved": self.rules_resolved,
                "unevaluable": len(self.unevaluable),
                "findings": len(self.findings), "by_kind": kinds}


def _resolved_set(resolutions) -> set | None:
    """The value set a rule side covers, or None if it could not be resolved.

    None is not an empty set. An empty set means "matches nothing"; None means
    "we could not tell", and conflating them is how a tool reports that an
    unreadable rule shadows nothing.
    """
    out: set = set()
    for r in resolutions:
        if not r.ok:
            return None
        for v in r.values:
            if v in ("0.0.0.0/0", "::/0", "any", "all"):
                return {ANY}
            out.add(v)
    return out or {ANY}


def _covers(a: set | None, b: set | None) -> bool:
    """Does set a cover set b?"""
    if a is None or b is None:
        return False
    return ANY in a or b <= a


def _family(rule) -> str:
    """IPv4 or IPv6. Separate policy tables; they never shadow each other."""
    ident = f"{rule.id} {rule.name}".lower()
    return "v6" if ("v6" in ident or "ipv6" in ident) else "v4"


def _zone_set(zones) -> set:
    return {z.lower() for z in zones} if zones else {ANY}


def _zones_cover(a, b) -> bool:
    za, zb = _zone_set(a), _zone_set(b)
    return ANY in za or zb <= za


def analyse(graph, resolver=None, *, max_pairs=20000) -> HygieneReport:
    """Full hygiene pass over a policy."""
    r = resolver or Resolver(graph)
    rep = HygieneReport()
    rules = sorted(graph.rules, key=lambda x: (x.order, x.id))
    rep.rules_examined = len(rules)

    # Resolve every rule once. Doing it inside the O(n^2) comparison would
    # re-resolve the same object thousands of times.
    resolved = {}
    for rule in rules:
        res = r.resolve_rule(rule)
        src = _resolved_set(res["src"])
        dst = _resolved_set(res["dst"])
        svc = _resolved_set(res["svc"])
        if None in (src, dst, svc):
            bad = [x.name for x in res["src"] + res["dst"] + res["svc"]
                   if not x.ok]
            rep.unevaluable.append(
                f"{rule.name or rule.id}: unresolved {', '.join(bad[:3])}")
            continue
        resolved[rule.id] = (src, dst, svc)
    rep.rules_resolved = len(resolved)

    # ---------------------------------------------------- dead / unused ----
    for rule in rules:
        if rule.hit_count is None or not rule.enabled:
            continue
        if rule.hit_count == 0:
            rep.findings.append(HygieneFinding(
                kind="unused_rule", rule=rule.name or rule.id,
                severity="low", hit_count=0,
                detail="enabled but has matched no traffic since the counter "
                       "last reset. Counters reset on reboot, so confirm "
                       "against device uptime before removing -- a "
                       "disaster-recovery rule may be correctly unused.",
                evidence=list(rule.evidence)))

    # -------------------------------------------------- disabled clutter ---
    for rule in rules:
        if not rule.enabled:
            rep.findings.append(HygieneFinding(
                kind="disabled_rule", rule=rule.name or rule.id,
                severity="low",
                detail="disabled rule left in the policy. Harmless to traffic, "
                       "but it obscures review and tends to get re-enabled "
                       "without re-approval.",
                evidence=list(rule.evidence)))

    # ------------------------------------------------- overly permissive ---
    for rule in rules:
        if rule.id not in resolved or not rule.enabled:
            continue
        if rule.action.lower() not in ("allow", "accept", "permit"):
            continue
        src, dst, svc = resolved[rule.id]
        wide = [n for n, s in (("source", src), ("destination", dst),
                               ("service", svc)) if ANY in s]
        if len(wide) >= 2:
            rep.findings.append(HygieneFinding(
                kind="overly_permissive", rule=rule.name or rule.id,
                severity="high" if len(wide) == 3 else "medium",
                hit_count=rule.hit_count,
                detail=f"permits any {' and any '.join(wide)}. A rule this "
                       "broad cannot be reviewed meaningfully and defeats the "
                       "purpose of the ones below it.",
                evidence=list(rule.evidence)))

    # ------------------------------------------- shadowed and redundant ----
    # Skipped entirely on platforms with no positional evaluation. Windows
    # Firewall matches by precedence -- a block rule beats an allow rule
    # wherever it sits -- so "this rule is shadowed by the one above it"
    # describes semantics the device does not have, and would be a finding
    # invented by our own assumption rather than read from the policy.
    if getattr(graph, "unordered", False):
        rep.unevaluable.append(
            "shadow and redundancy analysis skipped: this platform does not "
            "evaluate rules in order, so containment implies nothing")
        pairs = 0
    else:
        pairs = 0
    for i, later in enumerate(rules if not getattr(graph, 'unordered', False) else []):
        if later.id not in resolved or not later.enabled:
            continue
        lsrc, ldst, lsvc = resolved[later.id]
        for earlier in rules[:i]:
            pairs += 1
            if pairs > max_pairs:
                rep.unevaluable.append(
                    f"comparison budget reached after {max_pairs} pairs; "
                    "shadow analysis is incomplete for this policy")
                break
            if earlier.id not in resolved or not earlier.enabled:
                continue
            # An IPv4 rule and an IPv6 rule are in SEPARATE policy tables and
            # cannot shadow one another. Comparing across families called a
            # rule with 2,308,325 matches unreachable -- the device's own
            # counter refuted the claim, which is how this was found.
            if _family(earlier) != _family(later):
                continue
            esrc, edst, esvc = resolved[earlier.id]
            if not (_covers(esrc, lsrc) and _covers(edst, ldst)
                    and _covers(esvc, lsvc)
                    and _zones_cover(earlier.source_zones, later.source_zones)
                    and _zones_cover(earlier.destination_zones,
                                     later.destination_zones)):
                continue

            same_action = earlier.action.lower() == later.action.lower()
            if same_action:
                rep.findings.append(HygieneFinding(
                    kind="redundant_rule", rule=later.name or later.id,
                    related=earlier.name or earlier.id, severity="low",
                    hit_count=later.hit_count,
                    detail=f"fully covered by an earlier rule with the same "
                           f"action ({earlier.action}); it can never change "
                           "the outcome.",
                    evidence=list(later.evidence)))
            else:
                rep.findings.append(HygieneFinding(
                    kind="shadowed_rule", rule=later.name or later.id,
                    related=earlier.name or earlier.id, severity="high",
                    hit_count=later.hit_count,
                    detail=f"never reached: an earlier rule matches the same "
                           f"traffic and {earlier.action}s it. The intent "
                           "expressed here is not in effect.",
                    evidence=list(later.evidence)))
            break          # first shadower is the one worth reporting
        else:
            continue
        if pairs > max_pairs:
            break

    # ------------------------------------- corroborate against the device --
    # Set containment and the appliance's own packet counter are INDEPENDENT
    # signals about the same question, and they can disagree in only one
    # direction that matters: a rule the analysis calls unreachable but which
    # has matched traffic is proof the containment logic is wrong, because a
    # rule that matched packets is by definition reachable.
    #
    # This is the strongest validation available here, and neither comparable
    # approach has both halves -- Batfish computes containment without hit
    # counters, and the appliance reports counters without containment.
    by_name = {(x.name or x.id): x for x in rules}
    for f in rep.findings:
        if f.kind not in ("shadowed_rule", "redundant_rule"):
            continue
        rule = by_name.get(f.rule)
        if rule is None or rule.hit_count is None:
            continue
        f.hit_count = rule.hit_count
        if rule.hit_count == 0:
            f.detail += (" The device's own packet counter agrees: this rule "
                         "has never matched.")
        else:
            # Do not quietly keep a finding the device contradicts.
            f.kind = "disputed_shadow"
            f.severity = "low"
            f.detail = (f"analysis called this rule unreachable, but the "
                        f"device counted {rule.hit_count:,} matches. The "
                        "containment result is wrong -- reported rather than "
                        "dropped, because it points at a bug in our own "
                        "analysis.")

    # ------------------------------------------------- orphaned objects ----
    referenced: set = set()
    for rule in rules:
        referenced.update(rule.source)
        referenced.update(rule.destination)
        referenced.update(rule.services)
        # A rule scopes itself to zones and interfaces too. Counting only the
        # address and service sides reported an interface named in every
        # policy as an unreferenced object.
        referenced.update(rule.source_zones)
        referenced.update(rule.destination_zones)
    for node in graph.nodes.values():
        referenced.update(node.members or [])

    # Zones and interfaces are not policy objects. They exist whether or not a
    # rule names them, so an unreferenced one is a topology fact rather than
    # the dead-object cleanup problem this finding is about.
    orphans = [n.name for n in graph.nodes.values()
               if n.name not in referenced
               and getattr(n.kind, "value", str(n.kind))
               not in ("zone", "interface")]
    if orphans:
        rep.findings.append(HygieneFinding(
            kind="orphaned_objects", rule=f"{len(orphans)} objects",
            severity="low",
            detail="defined but referenced by no rule and no group: "
                   + ", ".join(sorted(orphans)[:8])
                   + (" ..." if len(orphans) > 8 else "")
                   + ". Dead objects accumulate and make review harder; they "
                     "are also how a deleted rule leaves a live address "
                     "object behind.",
            related=f"{len(orphans)}"))
    return rep
