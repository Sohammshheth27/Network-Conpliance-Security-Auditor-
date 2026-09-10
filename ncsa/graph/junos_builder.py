"""Build an ObjectGraph from a parsed Junos configuration.

The vendor adapter of doc section 3: vendor-specific in, vendor-neutral graph
out. A sibling builder per vendor is the whole extension mechanism -- the
resolver, the facts and the checks never learn any vendor syntax.

Reads ``cfg.multi`` rather than ``cfg.values``: Junos writes sibling leaves with
the same key (``address A ...;`` then ``address B ...;``), and reading only the
last one silently under-reports group membership.
"""
from __future__ import annotations

import re

from ..readers.braces import BracesConfig
from .model import Node, NodeKind, ObjectGraph, SecurityRule

# Vendor guide, `set security address-book <book> address <name> ...`:
# an address is NOT always a CIDR. The documented forms are a prefix, a
# dns-name, or a range-address. Handling only prefixes meant DNS and range
# objects parsed to an object with NO values, which the resolver then reported
# as UNRESOLVED -- an unreadable config rather than a readable one.
_ADDR = re.compile(r"^security/address-book/(?:[^/]+/)?address/([^/]+)$")
_ADDR_SUB = re.compile(
    r"^security/address-book/(?:[^/]+/)?address/([^/]+)/(dns-name|range-address|ip-prefix|wildcard-address)$")
_SET_MEMBER = re.compile(
    r"^security/address-book/(?:[^/]+/)?address-set/([^/]+)/(?:address|address-set)$"
)
# `set applications application <name> term <t> custom-options protocol udp`
# -- the documented syntax nests options under a TERM. A single-term
# application omits it, so both shapes must be accepted or multi-term
# applications silently lose their ports.
_APP = re.compile(
    r"^applications/application/([^/]+)/(?:term/[^/]+/)?(?:custom-options/)?"
    r"(protocol|destination-port|port)$")
_APPSET = re.compile(r"^applications/application-set/([^/]+)/application$")
_ZONE_IF = re.compile(r"^security/zones/security-zone/([^/]+)/interfaces/([^/]+)$")
_ZONE_IF2 = re.compile(r"^security/zones/security-zone/([^/]+)/interfaces$")
_POLICY = re.compile(
    r"^security/policies/from-zone/([^/]+)/to-zone/([^/]+)/policy/([^/]+)/(.+)$"
)

UNTRUSTED = {"untrust", "internet", "wan", "outside", "public", "external"}


def build(cfg: BracesConfig) -> ObjectGraph:
    g = ObjectGraph()

    for path, entries in cfg.multi.items():
        for val, ln, raw in entries:
            ev = [cfg.evidence(ln, raw)]

            if m := _ADDR_SUB.match(path):
                name, form = m.group(1), m.group(2)
                node = g.lookup(name)
                if node is None:
                    node = Node(id=name, kind=NodeKind.ADDRESS, name=name, evidence=ev)
                    g.add(node)
                node.values = [val]
                node.attrs["form"] = form
                continue

            if m := _ADDR.match(path):
                name = m.group(1)
                node = g.lookup(name)
                if node is None:
                    node = Node(id=name, kind=NodeKind.ADDRESS, name=name, evidence=ev)
                    g.add(node)
                if val:
                    node.values = [val]
                    node.attrs.setdefault("form", "ip-prefix")
                continue

            if m := _SET_MEMBER.match(path):
                gname = m.group(1)
                node = g.lookup(gname)
                if node is None:
                    node = Node(id=gname, kind=NodeKind.ADDRESS_GROUP,
                                name=gname, evidence=ev)
                    g.add(node)
                if val and val not in node.members:
                    node.members.append(val)
                continue

            if m := _APP.match(path):
                name, leaf = m.group(1), m.group(2)
                node = g.lookup(name)
                if node is None:
                    node = Node(id=name, kind=NodeKind.SERVICE, name=name, evidence=ev)
                    g.add(node)
                node.attrs["protocol" if leaf == "protocol" else "port"] = val
                continue

            if m := _APPSET.match(path):
                gname = m.group(1)
                node = g.lookup(gname)
                if node is None:
                    node = Node(id=gname, kind=NodeKind.SERVICE_GROUP,
                                name=gname, evidence=ev)
                    g.add(node)
                if val and val not in node.members:
                    node.members.append(val)
                continue

            zm = _ZONE_IF.match(path) or _ZONE_IF2.match(path)
            if zm:
                zone = zm.group(1)
                iface = zm.group(2) if zm.re is _ZONE_IF else val
                if iface:
                    g.zones_of_interface[iface] = zone
                if zone.lower() in UNTRUSTED:
                    g.untrusted_zones.add(zone)
                znode = g.lookup(zone)
                if znode is None:
                    znode = Node(id=zone, kind=NodeKind.ZONE, name=zone, evidence=ev)
                    g.add(znode)
                if iface and iface not in znode.members:
                    znode.members.append(iface)
                continue

    # protocol + port -> a concrete "tcp/443"
    for n in g.nodes.values():
        if n.kind is NodeKind.SERVICE:
            port = n.attrs.get("port")
            if port:
                n.values = [f"{n.attrs.get('protocol', 'tcp')}/{port}"]

    # ------------------------------------------------------------- policies
    rules: dict[str, SecurityRule] = {}
    for path, entries in cfg.multi.items():
        m = _POLICY.match(path)
        if not m:
            continue
        szone, dzone, pname, leaf = m.groups()
        key = f"{szone}->{dzone}:{pname}"
        rule = rules.get(key)
        if rule is None:
            rule = SecurityRule(id=key, name=pname, order=len(rules) + 1,
                                source_zones=[szone], destination_zones=[dzone],
                                action="deny")
            rules[key] = rule
        for val, ln, raw in entries:
            rule.evidence.append(cfg.evidence(ln, raw))
            if leaf.endswith("source-address"):
                rule.source.append(val)
            elif leaf.endswith("destination-address"):
                rule.destination.append(val)
            elif leaf.endswith("application"):
                rule.services.append(val)
            elif "permit" in leaf:
                rule.action = "allow"
            elif "deny" in leaf or "reject" in leaf:
                rule.action = "deny"
            elif "log" in leaf:
                rule.logging = True

    # `set security policies default-policy permit-all` is valid and documented.
    # Assuming deny would report a permit-all device as compliant -- a false
    # PASS on a high-severity control, from a single wrong assumption.
    dp = cfg.get("security/policies/default-policy")
    if dp is not None:
        val, ln, raw = dp
        g.default_action = "allow" if "permit" in (val + raw).lower() else "deny"
        g.default_action_observed = True
    else:
        for p2 in cfg.multi:
            if p2.endswith("security/policies/default-policy/permit-all"):
                g.default_action, g.default_action_observed = "allow", True
                break
            if p2.endswith("security/policies/default-policy/deny-all"):
                g.default_action, g.default_action_observed = "deny", True
                break

    for r in rules.values():
        g.add_rule(r)
    return g
