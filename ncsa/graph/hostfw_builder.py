"""Host firewall -> ObjectGraph, so everything already built applies.

The point of a vendor-neutral model: once Windows Firewall rules become
`SecurityRule` objects, rule hygiene, reachability and the control engine work
on a laptop exactly as they do on an NSA 3700. No new analysis code.

TWO SEMANTICS THAT DIFFER FROM AN APPLIANCE, and are handled rather than
ignored:

  * NO EVALUATION ORDER. Windows Firewall does not match top-to-bottom; a
    block rule wins over an allow rule wherever it sits. `order` is therefore
    left at 0 for every rule and the graph is marked unordered, so shadow
    analysis -- which assumes first-match-wins -- does not run and cannot
    invent a finding that the platform's semantics make meaningless.
  * PROFILE IS THE ZONE. The same rule is harmless on Domain and dangerous on
    Public, so the profile is carried as the zone and reachability can be
    asked per profile.
"""
from __future__ import annotations

from .model import Node, NodeKind, ObjectGraph, SecurityRule

# Windows reports "Any" for an unconstrained field; the graph's word is "any".
_ANY = {"any", "", "*", "0.0.0.0", "::"}
UNTRUSTED_PROFILES = {"public"}


def _norm(v) -> list:
    s = str(v or "").strip()
    if s.lower() in _ANY:
        return ["any"]
    return [p.strip() for p in s.split(",") if p.strip()]


def _services(proto, port) -> list:
    """Windows writes a protocol and a port separately, and "Any" for either.

    A bare protocol name is NOT a resolvable service: `udp` alone left 402 of
    703 rules unevaluable because the resolver had no object by that name.
    "UDP, any port" is the full port range, so it is written that way and
    resolves as a literal.
    """
    p = str(proto or "").strip().lower()
    ports = _norm(port)
    if p in ("", "any"):
        return ["any"] if ports == ["any"] else [f"tcp/{o}" for o in ports]
    if p not in ("tcp", "udp", "icmp", "icmpv4", "icmpv6"):
        # ICMP types, GRE, ESP and numeric protocols are real but not
        # port-addressable; naming them keeps them in the policy without
        # pretending a port query can decide them.
        return [f"proto:{p}"]
    if ports == ["any"]:
        return [f"{p}/1-65535"]
    return [f"{p}/{o}" for o in ports]


def build(fw) -> ObjectGraph:
    g = ObjectGraph()

    for prof in fw.profiles:
        name = prof.get("name") or ""
        if not name:
            continue
        g.add(Node(id=name, kind=NodeKind.ZONE, name=name,
                   attrs={"enabled": prof.get("enabled"),
                          "default_inbound": prof.get("inbound"),
                          "default_outbound": prof.get("outbound")},
                   evidence=[fw.evidence(0, f"profile {name}")]))
        if name.lower() in UNTRUSTED_PROFILES:
            g.untrusted_zones.add(name)

    for i, r in enumerate(fw.rules):
        enabled = str(r.get("enabled", "")).strip().lower() in ("true", "1", "yes")
        action = str(r.get("action", "")).strip().lower()
        action = "allow" if action in ("allow", "accept") else "deny"
        inbound = str(r.get("direction", "")).strip().lower() == "inbound"

        # Remote is the far side; on an inbound rule that is the SOURCE, and on
        # an outbound rule it is the destination. Getting this backwards would
        # make every outbound rule look like inbound exposure.
        remote = _norm(r.get("remoteAddress"))
        local = _norm(r.get("localAddress"))
        src, dst = (remote, local) if inbound else (local, remote)
        zone = r.get("profile") or "Any"

        # A rule scoped to a PROGRAM does not open a port to the network; it
        # permits one binary to receive. Modelling it as any/any made every
        # port on this laptop report PERMITTED, decided by an HP printer
        # utility. The program is carried so reachability can decline to
        # answer rather than assert a port is open.
        program = (r.get("program") or "").strip()

        g.add_rule(SecurityRule(
            id=r.get("name") or f"rule{i}",
            name=r.get("display") or r.get("name") or f"rule{i}",
            # Deliberately 0: this platform has no positional evaluation.
            order=0,
            enabled=enabled, action=action,
            source=src, destination=dst,
            services=_services(r.get("protocol"),
                               r.get("localPort") if inbound
                               else r.get("remotePort")),
            source_zones=[zone] if inbound else [],
            destination_zones=[] if inbound else [zone],
            program=program or None,
            evidence=[fw.evidence(r.get("line", 0),
                                  r.get("raw") or r.get("display")
                                  or r.get("name") or "")]))

    # Default action, taken from the profiles rather than assumed.
    inbound_defaults = {str(p.get("inbound", "")).strip().lower()
                        for p in fw.profiles}
    if inbound_defaults and inbound_defaults <= {"block", "blockinbound"}:
        g.default_action = "deny"
        g.default_action_observed = True
    elif inbound_defaults and "allow" in inbound_defaults:
        g.default_action = "allow"
        g.default_action_observed = True
    else:
        # "NotConfigured" means the effective default comes from group policy
        # or the OS default, neither of which is in this data. Windows blocks
        # inbound by default, but assuming that here would be asserting
        # something we did not read.
        g.default_action_observed = False

    # Consumed by the analysis, so the accounting reflects what was read.
    fw._consumed.update(range(len(fw.rules)))
    g.unordered = True
    return g
