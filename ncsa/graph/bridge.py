"""Graph -> SBM bridge. This is what kills the dual system.

Before this module there were two parallel analyses of the same file:

    pack  -> SBM  -> rule engine -> findings -> report      (scalar settings)
    graph -> facts -> (nowhere)                             (policy analysis)

The graph produced the best finding the system makes -- "rdp/3389 from internet
to 10.10.10.10/32", resolved through named objects -- and it could not reach a
report, because nothing wrote it into the SBM. Meanwhile the SBM declared
firewall.rules.* fields that no pack could populate, so they sat DEAD.

One pass, one model: the graph's rules and computed facts become Observations
like everything else, and the existing rule engine evaluates them with no new
code and no vendor knowledge.

UNCERTAINTY IS PRESERVED, NOT FLATTENED
---------------------------------------
A fact computed over an unresolved reference is recorded UNPARSED, which the
engine turns into UNKNOWN. Recording it as a clean empty list would let a typo
in a group name satisfy "no admin ports exposed" -- a false PASS manufactured
from a broken config. That is plan 10.5's worst case, and section 9 of the
parser architecture doc says the same thing: UNRESOLVED_REFERENCE means the
finding may be incomplete.
"""
from __future__ import annotations

from ..schema.enums import RecordState
from ..schema.observation import Observation
from ..schema.sbm import SecurityBaselineModel
from .facts import (admin_mgmt_public_exposure, policy_broad_any_any,
                    sensitive_service_exposed, unresolved_references)
from .model import NodeKind, ObjectGraph
from .resolve import Resolver

# fact -> SBM field. Each is a normal field a normal control can read.
FACT_FIELDS = {
    "exposure.admin_ports_open_to_internet": admin_mgmt_public_exposure,
    "exposure.any_any_rules": policy_broad_any_any,
    "exposure.unrestricted_ingress": sensitive_service_exposed,
}


def merge(sbm: SecurityBaselineModel, graph: ObjectGraph, cfg=None) -> SecurityBaselineModel:
    """Write the graph's rules and facts into an existing SBM."""
    resolver = Resolver(graph)

    # ---------------------------------------------------------------- rules
    for rule in graph.rules:
        scope = rule.name or rule.id
        res = resolver.resolve_rule(rule)
        ev = list(rule.evidence)

        def put(leaf: str, value, evidence=ev):
            path = f"firewall.rules[{scope}].{leaf}"
            sbm.set(path, Observation.observed(value, evidence, field_path=path)
                    if evidence else Observation.default_assumed(value, field_path=path))

        put("id", rule.id)
        put("action", rule.action)
        put("position", rule.order)
        if rule.logging is not None:
            put("log", rule.logging)

        # Resolved values where resolution succeeded; UNPARSED where it did not,
        # so an unresolved group can never read as "no sources".
        for leaf, key, names in (("source", "src", rule.source),
                                 ("destination", "dst", rule.destination),
                                 ("service", "svc", rule.services)):
            path = f"firewall.rules[{scope}].{leaf}"
            good = [r for r in res[key] if r.ok]
            bad = [r for r in res[key] if not r.ok]
            if bad:
                sbm.set(path, Observation.unparsed(ev, field_path=path))
            else:
                values = [v for r in good for v in r.values]
                sbm.set(path, Observation.observed(values, ev, field_path=path))

        if rule.source_zones or rule.destination_zones:
            put("direction", f"{','.join(rule.source_zones)}->{','.join(rule.destination_zones)}")

    # ------------------------------------------------------- default action
    # OBSERVED when the config states it; DEFAULT_ASSUMED otherwise, which
    # plan 7.3 then forbids from carrying a FAIL. Either way it is never a
    # silent assumption presented as fact.
    if graph.default_action_observed:
        # The default policy's OWN line, not a rule's.
        #
        # This used to borrow evidence from an arbitrary rule, which cited
        # `allow-web-out` as the proof that the default is permit-all. On a
        # device with a permit-all default and NO rules there was nothing to
        # borrow, so the observation degraded to an assumption and the control
        # went UNKNOWN -- losing the finding on precisely the configuration
        # that most needs it.
        ev_dp = list(getattr(graph, "default_action_evidence", []) or [])

        # The graph's word for this is "allow"; the SBM field's is "permit",
        # which is what every pack writes and what NCSA-CLD-004 compares
        # against. Translating between the two is this adapter's job.
        #
        # It never showed until a permit-all device appeared: every builder
        # before that set "deny", which is spelled the same on both sides.
        action = {"allow": "permit", "accept": "permit"}.get(
            graph.default_action, graph.default_action)

        sbm.set("firewall.default_action",
                Observation.observed(action, ev_dp,
                                     field_path="firewall.default_action")
                if ev_dp else
                # A builder may know the default from a platform invariant
                # rather than from a line -- an AWS security group cannot be
                # configured to default-allow. That is still not something we
                # READ, so it stays an assumption here and cannot carry a FAIL.
                Observation.default_assumed(action,
                                            field_path="firewall.default_action"))

    # ---------------------------------------------------------------- zones
    zones = [n.name for n in graph.of_kind(NodeKind.ZONE)]
    if zones:
        zev = [e for n in graph.of_kind(NodeKind.ZONE) for e in n.evidence]
        sbm.set("firewall.zones",
                Observation.observed(zones, zev, field_path="firewall.zones")
                if zev else Observation.default_assumed(zones, field_path="firewall.zones"))

    # interface -> zone, scoped per interface
    for iface, zone in graph.zones_of_interface.items():
        path = f"interfaces[{iface}].zone"
        sbm.set(path, Observation.default_assumed(zone, field_path=path))

    # ---------------------------------------------------------------- facts
    for field, fn in FACT_FIELDS.items():
        hits, evidence, skipped = fn(graph, resolver)

        if hits:
            # We found real violations. Report them -- they are provable
            # regardless of what else in the policy was unreadable. Skipped
            # rules are surfaced separately rather than suppressing findings.
            sbm.set(field, Observation.observed(hits, evidence, field_path=field))
        elif skipped:
            # Nothing found, but some rules were unevaluable. "No violations"
            # would be a false PASS manufactured from a dangling reference.
            sbm.set(field, Observation.unparsed(
                [_skip_evidence(sbm, skipped)], field_path=field))
        else:
            # Nothing found and every rule was readable -- a provable clean pass.
            sbm.set(field, Observation.observed(
                hits, evidence, field_path=field) if evidence
                else Observation.default_assumed(hits, field_path=field))

        # Always record how much of the policy we could not evaluate.
        if skipped:
            path = "firewall.rules_unevaluable"
            sbm.set(path, Observation.observed(
                [str(s) for s in skipped], [_skip_evidence(sbm, skipped)],
                field_path=path))

    # Unresolved references are themselves worth reporting to the customer.
    bad, _, res_objs = unresolved_references(graph, resolver)
    if bad:
        sbm.unrecognised.extend(
            _synthetic_evidence(sbm, [r]) for r in res_objs[:20]
        )

    # Lines the graph consumed are PARSED, not unread. Without this the policy
    # half of a config counted as 0% coverage even though it was fully analysed.
    if cfg is not None:
        consumed = {e.line for r in graph.rules for e in r.evidence if e.line}
        consumed |= {e.line for n in graph.nodes.values() for e in n.evidence if e.line}
        already = sbm.accounting.parsed
        extra = len({l for l in consumed})
        if extra:
            move = min(extra, sbm.accounting.unknown)
            sbm.accounting.parsed = already + move
            sbm.accounting.unknown -= move
    return sbm


def _skip_evidence(sbm: SecurityBaselineModel, skipped):
    """Evidence for "this rule could not be evaluated".

    The REASON is derived, but the rule it concerns sits on a real line, and
    that line is carried through from the rule itself. Reporting a problem
    rule with no position told an administrator a rule was unevaluable and
    gave them no way to find it.
    """
    from ..schema.evidence import EvidenceRef
    s = skipped[0]
    origin = next(iter(getattr(s, "evidence", []) or []), None)
    return EvidenceRef(
        file=(origin.file if origin else sbm.source_file),
        line=(origin.line if origin else None),
        raw=f"rule {s.rule} not evaluable: {s.reason}",
        # Prefer the rule's own record id where it has one -- on a key-value
        # export that is the setting ordinal, which is the real locator.
        record_id=(origin.record_id if origin and origin.record_id
                   else str(s.rule)),
    )


def _synthetic_evidence(sbm: SecurityBaselineModel, resolutions):
    from ..schema.evidence import EvidenceRef
    r = resolutions[0]
    return EvidenceRef(
        file=sbm.source_file, line=None,
        raw=f"unresolved reference: {' -> '.join(r.path) or r.name}",
        record_id=r.name,
    )
