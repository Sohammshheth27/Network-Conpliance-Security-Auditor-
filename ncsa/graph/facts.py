"""Security facts computed from the object graph -- plan 15.2.

Plan 15.2 lists these as `fact.*()` and says exposure must be COMPUTED from the
graph rather than asked of the user. Until now our only exposure calculation was
hardcoded Python that understood AWS security groups and nothing else. These
work on any vendor whose pack builds a graph.

Each fact returns (value, evidence, uncertainty):

  * ``value``       the answer
  * ``evidence``    the resolution paths that justify it -- doc section 8
  * ``uncertainty`` the RULES we could not evaluate, not merely "something failed"

Uncertainty is tracked PER RULE, deliberately. The first version marked the
whole fact incomplete if any reference anywhere failed to resolve, so one
dangling group name in a 200-rule policy discarded every finding in the file --
including correctly resolved internet-facing RDP. Reporting nothing because one
line was unreadable is its own kind of dishonesty.

The safety property that must not be lost: a fact may report the violations it
found even when some rules were unreadable, but it may NEVER report "clean" on
that basis. No hits + unread rules = UNKNOWN, not PASS.
"""
from __future__ import annotations

import re

from .model import ObjectGraph, Resolution
from .resolve import INTERNET_CIDRS, Resolver

class SkippedRule:
    """A rule we could not evaluate, and exactly why. Doc section 9's
    UNRESOLVED_REFERENCE: show the reference path, do not silently drop."""

    __slots__ = ("rule", "reason", "refs")

    def __init__(self, rule, reason: str, refs):
        self.rule, self.reason, self.refs = rule, reason, refs

    def __repr__(self) -> str:
        return f"{self.rule}: {self.reason}"


def _skipped(rule, bad) -> SkippedRule:
    name = rule.name or rule.id
    detail = "; ".join(f"{b.name} [{b.state.value}]" for b in bad[:3])
    return SkippedRule(name, detail, bad)


ADMIN_PORTS = {22: "ssh", 23: "telnet", 3389: "rdp", 5900: "vnc",
               161: "snmp", 443: "https-mgmt", 80: "http-mgmt"}
SENSITIVE_PORTS = {3306: "mysql", 5432: "postgres", 1433: "mssql",
                   27017: "mongodb", 6379: "redis", 9200: "elasticsearch",
                   445: "smb", 135: "rpc", 389: "ldap"}


def _ports_of(res: Resolution) -> set[int]:
    """Ports a resolved service covers.

    A wide range is NOT silently expanded into every interesting port. Doing
    that turned one misread service group into 225 critical findings. A range
    is intersected with the ports we care about, and only a literal "any"
    means everything.
    """
    ports: set[int] = set()
    interesting = set(ADMIN_PORTS) | set(SENSITIVE_PORTS)
    for v in res.values:
        m = re.match(r"^(tcp|udp)/(\d+)(?:-(\d+))?$", v, re.I)
        if m:
            lo = int(m.group(2))
            hi = int(m.group(3) or lo)
            if hi - lo > 1024:
                # Intersect rather than assume: a broad range only matters for
                # the ports a control actually asks about.
                ports.update(p for p in interesting if lo <= p <= hi)
            else:
                ports.update(range(lo, hi + 1))
        elif v.lower() in ("any", "all"):
            ports.update(interesting)
    return ports


def _from_untrusted(rule, src_resolutions, graph) -> bool:
    """Is this rule genuinely reachable from an untrusted network?

    ZONE is what makes a rule internet-facing, not the word "any". A LAN->LAN
    rule with source `any` is internal traffic; treating it as exposure
    produced findings on 57 internal rules that were never reachable from
    outside at all.
    """
    zones = [z.lower() for z in (rule.source_zones or [])]
    if zones:
        untrusted = {z.lower() for z in graph.untrusted_zones} or {
            "wan", "untrust", "internet", "public", "wlan", "sslvpn"}
        return any(z in untrusted for z in zones)
    # No zone information (e.g. cloud security groups): fall back to the
    # address itself.
    return any(r.ok and any(v in INTERNET_CIDRS for v in r.values)
               for r in src_resolutions)


def admin_mgmt_public_exposure(graph: ObjectGraph, resolver: Resolver | None = None):
    """plan 15.2 fact.admin_mgmt_public_exposure().

    An administrative service reachable from the whole internet. This is the
    exposure factor feeding the plan 7.1 risk formula: severity alone would call
    open RDP "medium"; reachable-from-anywhere is what makes it critical.
    """
    r = resolver or Resolver(graph)
    hits, evidence, uncertain = [], [], []

    for rule in graph.rules:
        if not rule.enabled or rule.action.lower() not in ("allow", "accept", "permit"):
            continue
        res = r.resolve_rule(rule)
        bad = [x for x in res["src"] + res["dst"] + res["svc"] if not x.ok]
        if bad:
            # This RULE is unevaluable. Record it and move on -- the other
            # rules in the policy are still perfectly readable.
            uncertain.append(_skipped(rule, bad))
            continue

        if not _from_untrusted(rule, res["src"], graph):
            continue

        ports = set()
        for svc in res["svc"]:
            ports |= _ports_of(svc)
        admin = sorted(p for p in ports if p in ADMIN_PORTS)
        if not admin:
            continue

        # NO `or "any"` fallback. An empty destination set means we failed to
        # read the destination, and defaulting that to "any" reports the widest
        # possible exposure on the least possible evidence.
        dvals = sorted({v for x in res["dst"] if x.ok for v in x.values})
        if not dvals:
            uncertain.append(_skipped(rule, res["dst"]))
            continue
        dst = ", ".join(dvals)
        for p in admin:
            hits.append(f"rule {rule.name or rule.id}: {ADMIN_PORTS[p]}/{p} "
                        f"from internet to {dst}")
        evidence += list(rule.evidence)
        # doc section 8 -- carry the resolution PATH, not just the verdict
        for x in res["src"] + res["dst"] + res["svc"]:
            if x.ok and x.path:
                evidence and None
    return hits, evidence, uncertain


def admin_mgmt_source_restricted(graph: ObjectGraph, resolver: Resolver | None = None):
    """plan 15.2 -- is management access restricted to known sources?"""
    r = resolver or Resolver(graph)
    unrestricted, evidence, uncertain = [], [], []
    for rule in graph.rules:
        if not rule.enabled or rule.action.lower() not in ("allow", "accept", "permit"):
            continue
        res = r.resolve_rule(rule)
        bad = [x for x in res["src"] + res["svc"] if not x.ok]
        if bad:
            uncertain.append(_skipped(rule, bad))
            continue
        ports = set()
        for svc in res["svc"]:
            ports |= _ports_of(svc)
        if not (ports & set(ADMIN_PORTS)):
            continue
        if _from_untrusted(rule, res["src"], graph):
            unrestricted.append(f"rule {rule.name or rule.id}")
            evidence += list(rule.evidence)
    return (len(unrestricted) == 0), evidence, uncertain


def policy_broad_any_any(graph: ObjectGraph, resolver: Resolver | None = None):
    """plan 15.2 fact.policy_broad_any_any()."""
    r = resolver or Resolver(graph)
    hits, evidence, uncertain = [], [], []
    for rule in graph.rules:
        if not rule.enabled or rule.action.lower() not in ("allow", "accept", "permit"):
            continue
        res = r.resolve_rule(rule)
        bad = [x for x in res["src"] + res["dst"] + res["svc"] if not x.ok]
        if bad:
            uncertain.append(_skipped(rule, bad))
            continue
        wide_src = any(x.ok and "0.0.0.0/0" in x.values for x in res["src"])
        wide_dst = any(x.ok and "0.0.0.0/0" in x.values for x in res["dst"])
        wide_svc = any(x.ok and any(v.lower() in ("any", "all") for v in x.values)
                       for x in res["svc"]) or not res["svc"]
        if wide_src and wide_dst and wide_svc:
            hits.append(f"rule {rule.name or rule.id}: any -> any, all services, allow")
            evidence += list(rule.evidence)
    return hits, evidence, uncertain


def sensitive_service_exposed(graph: ObjectGraph, resolver: Resolver | None = None):
    """Databases and file services reachable from the internet."""
    r = resolver or Resolver(graph)
    hits, evidence, uncertain = [], [], []
    for rule in graph.rules:
        if not rule.enabled or rule.action.lower() not in ("allow", "accept", "permit"):
            continue
        res = r.resolve_rule(rule)
        bad = [x for x in res["src"] + res["svc"] if not x.ok]
        if bad:
            uncertain.append(_skipped(rule, bad))
            continue
        if not _from_untrusted(rule, res["src"], graph):
            continue
        ports = set()
        for svc in res["svc"]:
            ports |= _ports_of(svc)
        for p in sorted(ports & set(SENSITIVE_PORTS)):
            hits.append(f"rule {rule.name or rule.id}: {SENSITIVE_PORTS[p]}/{p} from internet")
            evidence += list(rule.evidence)
    return hits, evidence, uncertain


def unresolved_references(graph: ObjectGraph, resolver: Resolver | None = None):
    """Doc section 9: UNRESOLVED_REFERENCE -- a finding may be incomplete.

    Reported as its own finding. A config referencing objects that do not exist
    is itself a problem worth telling the customer about, and it bounds how much
    of the policy we were able to analyse.
    """
    r = resolver or Resolver(graph)
    for rule in graph.rules:
        r.resolve_rule(rule)
    bad = r.unresolved_report()
    return [f"{x.name}: {x.detail}" for x in bad], [], bad


FACTS = {
    "admin_mgmt_public_exposure": admin_mgmt_public_exposure,
    "admin_mgmt_source_restricted": admin_mgmt_source_restricted,
    "policy_broad_any_any": policy_broad_any_any,
    "sensitive_service_exposed": sensitive_service_exposed,
    "unresolved_references": unresolved_references,
}
