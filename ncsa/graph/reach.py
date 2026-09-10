"""Reachability: what the policy actually permits, not what it says.

Batfish's central idea, at the scope we can honestly support. It does not ask
"is there a rule mentioning SSH"; it asks "can this packet get from here to
there", and answers by evaluating the policy the way the device does -- in
order, first match wins.

That distinction is the product's whole thesis. A config can contain a deny
rule for a host and still permit traffic to it, because an allow above it
matches first. This repo's own SonicWall does exactly that: rule #28 permits
any/any/any LAN to WAN, and rule #35 tries to deny one host below it. Asking
"does a deny exist" returns yes. Asking "can the packet through" returns yes
too -- and only the second question is the one that matters.

SCOPE, STATED PLAINLY, because the gap to Batfish is real:

  * ONE DEVICE. Batfish models a topology and computes a data plane across it;
    this evaluates a single policy. Multi-device reachability needs routing
    tables and interface maps we do not collect.
  * NO NAT, no policy-based routing, no VPN tunnelling. A NAT rule can change
    the destination a packet is evaluated against; we do not model that, and a
    query whose answer would depend on it is reported as such.
  * SET MEMBERSHIP, not subnet arithmetic. `10.0.0.0/8` covering `10.1.2.3` is
    computed; overlapping ranges expressed in exotic vendor syntax may not be.

Every answer carries the rule that decided it and the reason. An answer without
a deciding rule is not returned.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

from .resolve import Resolver

ANY_TOKENS = {"any", "all", "0.0.0.0/0", "::/0", "*"}


@dataclass
class Query:
    source: str = "any"
    destination: str = "any"
    port: int | None = None
    protocol: str = "tcp"
    source_zone: str = ""
    destination_zone: str = ""

    def describe(self) -> str:
        p = f"{self.protocol}/{self.port}" if self.port else self.protocol
        sz = f"[{self.source_zone}]" if self.source_zone else ""
        dz = f"[{self.destination_zone}]" if self.destination_zone else ""
        return f"{self.source}{sz} -> {self.destination}{dz} : {p}"


@dataclass
class Answer:
    permitted: bool | None          # None = undecidable, never guessed
    query: Query = None
    decided_by: str = ""
    action: str = ""
    reason: str = ""
    evaluated: int = 0
    skipped: list = field(default_factory=list)
    #: True when the deciding rule is scoped to zones the query did not name.
    #: The verdict then rests on an assumption -- that the traffic traverses
    #: that boundary -- rather than on anything the caller stated.
    zone_assumed: bool = False

    def to_json(self) -> dict:
        return {"query": self.query.describe() if self.query else "",
                "permitted": self.permitted, "decided_by": self.decided_by,
                "action": self.action, "reason": self.reason,
                "rules_evaluated": self.evaluated,
                "rules_unevaluable": len(self.skipped),
                "zone_assumed": self.zone_assumed}

    def explain(self) -> str:
        if self.permitted is None:
            return (f"UNDECIDABLE  {self.query.describe()}\n"
                    f"   {self.reason}")
        verdict = "PERMITTED" if self.permitted else "DENIED"
        out = [f"{verdict}  {self.query.describe()}",
               f"   decided by: {self.decided_by} ({self.action})",
               f"   {self.reason}"]
        if self.skipped:
            out.append(f"   caveat: {len(self.skipped)} rule(s) above this one "
                       "could not be evaluated; a match there would have "
                       "decided differently")
        if self.zone_assumed:
            # On FortiOS and PAN-OS every rule is scoped to zones or
            # interfaces, so an unzoned question is decided by whichever
            # scoped rule comes first -- even one carrying traffic that never
            # crosses that boundary. Saying so is the difference between an
            # answer and an answer the reader can trust.
            out.append("   caveat: the deciding rule is scoped to zones this "
                       "query did not name, so it was assumed to apply. Re-ask "
                       "with source_zone and destination_zone to remove the "
                       "assumption.")
        return "\n".join(out)


def _addr_in(value: str, candidate: str) -> bool:
    """Is `candidate` covered by the resolved value `value`?"""
    v, c = value.strip(), candidate.strip()
    # Only the RULE side being "any" makes a match. A QUERY of "any" asks
    # "can an arbitrary host reach this", and an arbitrary host is covered
    # only by a rule that accepts anything -- not by a rule listing specific
    # addresses. Treating a query of "any" as matching every rule made a
    # deny rule scoped to a malicious-IP list appear to block all inbound
    # traffic on every port, which would have reported a wide-open firewall
    # as fully protected.
    if v.lower() in ANY_TOKENS:
        return True
    if c.lower() in ANY_TOKENS:
        return False
    if v == c:
        return True
    try:
        net = ipaddress.ip_network(v, strict=False)
        try:
            return ipaddress.ip_address(c) in net
        except ValueError:
            return ipaddress.ip_network(c, strict=False).subnet_of(net)
    except ValueError:
        pass
    # A range, as several vendors write it.
    m = re.match(r"^(\d+\.\d+\.\d+\.\d+)-(\d+\.\d+\.\d+\.\d+)$", v)
    if m:
        try:
            lo, hi = (ipaddress.ip_address(m.group(1)),
                      ipaddress.ip_address(m.group(2)))
            return lo <= ipaddress.ip_address(c) <= hi
        except ValueError:
            return False
    return False


def _svc_matches(value: str, proto: str, port: int | None) -> bool:
    v = value.strip().lower()
    if v in ANY_TOKENS:
        return True
    if port is None:
        return v.startswith(proto.lower())
    m = re.match(r"^(tcp|udp|icmp|icmpv6)/(\d+)(?:-(\d+))?$", v)
    if not m:
        return False
    if m.group(1) != proto.lower():
        return False
    lo = int(m.group(2))
    hi = int(m.group(3) or lo)
    return lo <= port <= hi


def _side_matches(resolutions, candidate: str) -> bool | None:
    """True/False, or None when a reference could not be resolved.

    A QUERY candidate of "any" does NOT short-circuit to True. That was the
    same mistake `_addr_in` made, in a second place: it let a deny rule scoped
    to a specific malicious-IP list match a query about arbitrary traffic, so
    a wide-open firewall reported every port as blocked. Asking "can an
    arbitrary host reach this" is answered only by rules whose own side accepts
    anything.

    An unresolved reference yields None -- undecidable. Rule #5 on this
    appliance points at a group whose membership the export does not fully
    publish, and a rule we cannot read must never be reported as the one that
    decided the answer.
    """
    unresolved = False
    matched = False
    for r in resolutions:
        if not r.ok:
            unresolved = True
            continue
        for v in r.values:
            if _addr_in(v, candidate):
                matched = True
                break
        if matched:
            break
    if matched:
        return True
    return None if unresolved else False


def _zone_matches(rule_zones, want: str) -> bool:
    if not want:
        return True
    if not rule_zones:
        return True
    return want.lower() in {z.lower() for z in rule_zones}


def ask(graph, query: Query, resolver=None) -> Answer:
    """Evaluate the policy in order, first match wins."""
    r = resolver or Resolver(graph)
    rules = sorted(graph.rules, key=lambda x: (x.order, x.id))
    ans = Answer(permitted=None, query=query)

    for rule in rules:
        if not rule.enabled:
            continue
        if not (_zone_matches(rule.source_zones, query.source_zone)
                and _zone_matches(rule.destination_zones,
                                  query.destination_zone)):
            continue
        ans.evaluated += 1

        # A program-scoped rule permits one binary to receive; whether the
        # port is reachable depends on whether that program is listening,
        # which a configuration cannot tell us. Answering anyway made every
        # port on a laptop report PERMITTED, decided by a printer utility.
        if getattr(rule, "program", None) and query.port is not None:
            ans.skipped.append(f"{rule.name or rule.id} (scoped to a program)")
            continue

        res = r.resolve_rule(rule)

        src = _side_matches(res["src"], query.source)
        dst = _side_matches(res["dst"], query.destination)
        svc = None
        if any(not x.ok for x in res["svc"]):
            svc = None
        else:
            svc = any(_svc_matches(v, query.protocol, query.port)
                      for x in res["svc"] for v in x.values) or \
                any(v.lower() in ANY_TOKENS
                    for x in res["svc"] for v in x.values)

        if None in (src, dst, svc):
            # A rule we cannot evaluate might match. Record it and keep going:
            # if a LATER rule decides, the answer is still caveated, because a
            # match here would have decided first.
            ans.skipped.append(rule.name or rule.id)
            continue
        if not (src and dst and svc):
            continue

        permit = rule.action.lower() in ("allow", "accept", "permit")
        ans.permitted = permit
        ans.decided_by = rule.name or rule.id
        ans.action = rule.action
        # The zone matcher lets an unzoned query match a zone-scoped rule,
        # which is the only workable default -- but on FortiOS and PAN-OS
        # every rule is zone-scoped, so that default quietly decides the
        # answer. Record it so the caveat can be stated instead of assumed.
        ans.zone_assumed = bool(
            (rule.source_zones and not query.source_zone)
            or (rule.destination_zones and not query.destination_zone))
        ans.reason = ("first matching rule in policy order"
                      + (f"; {len(ans.skipped)} earlier rule(s) were unevaluable"
                         if ans.skipped else ""))
        return ans

    # Nothing matched. The default policy decides -- if we observed one.
    default = getattr(graph, "default_action", None)
    observed = getattr(graph, "default_action_observed", False)
    if default and observed:
        ans.permitted = default.lower() in ("allow", "accept", "permit")
        ans.decided_by = "default policy"
        ans.action = default
        ans.reason = "no rule matched; the device's stated default applies"
        return ans

    # Assuming default-deny would be right on most platforms and wrong on
    # exactly the ones where it matters. Undecidable is the honest answer.
    ans.reason = ("no rule matched and the export does not state a default "
                  "policy, so the outcome depends on a platform default we "
                  "have not observed")
    return ans


def audit(graph, queries, resolver=None) -> list:
    r = resolver or Resolver(graph)
    return [ask(graph, q, r) for q in queries]


# Questions worth asking of any firewall, phrased the way an auditor would.
STANDARD_QUERIES = [
    Query(destination="any", port=22, protocol="tcp", source_zone="WAN"),
    Query(destination="any", port=23, protocol="tcp", source_zone="WAN"),
    Query(destination="any", port=80, protocol="tcp", source_zone="WAN"),
    Query(destination="any", port=443, protocol="tcp", source_zone="WAN"),
    Query(destination="any", port=3389, protocol="tcp", source_zone="WAN"),
    Query(destination="any", port=445, protocol="tcp", source_zone="WAN"),
    Query(destination="any", port=1433, protocol="tcp", source_zone="WAN"),
    Query(destination="any", port=3306, protocol="tcp", source_zone="WAN"),
]
