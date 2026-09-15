"""Build an ObjectGraph from Azure Network Security Group exports.

    az network nsg list --output json          a list of NSGs
    az network nsg show -g RG -n NAME          one NSG
    ARM / REST                                  rules nested under "properties"

Vendor adapter: Azure in, vendor-neutral graph out. Once an NSG rule is a
SecurityRule, reachability, hygiene and the exposure facts work on it exactly
as they do on an NSA 3700.

WHERE AZURE DIFFERS FROM AN AWS SECURITY GROUP
----------------------------------------------
1. ORDERED, FIRST MATCH, AND DENY EXISTS.
   Custom rules carry priority 100-4096, the built-in defaults 65000+, lower
   wins and the first match decides. Unlike a security group, position here
   is meaning -- so the graph is NOT marked unordered.

2. EACH NSG IS ITS OWN POLICY.
   Rules in different NSGs never compete. Each NSG's rules are kept contiguous
   (sorted by direction, then priority) and scoped to that NSG's zone.
   Interleaving every NSG by priority would let a rule in one NSG "shadow" a
   rule in another -- a finding about semantics Azure does not have.

3. SERVICE TAGS ARE NOT ADDRESSES, AND ARE NOT ALL ALIKE.
     Internet                          the public address space -> 0.0.0.0/0,
                                       so internet exposure is caught
     VirtualNetwork, AzureLoadBalancer internal by definition -> resolved as
                                       identifiers, never mistaken for the
                                       internet
     anything else (AzureCloud, ...)   Azure-managed sets that may contain
                                       public ranges -> UNSUPPORTED. AzureCloud
                                       is every Azure tenant's public IP space;
                                       treating it as internal would hide an
                                       exposure.

4. THE DEFAULT RULES ARE IN THE EXPORT.
   `defaultSecurityRules` carries DenyAllInBound at priority 65500. It is read
   from the file and cited as the default policy's evidence. An NSG cannot
   delete its default rules, so if an export omits them the default is still
   deny -- but it is then recorded as assumed, not observed.

Validated on a FIXTURE built from the documented `az network nsg list` output
shape, not on a real subscription export.
"""
from __future__ import annotations

import re

from .model import Node, NodeKind, ObjectGraph, SecurityRule

#: Service tags that are internal by definition.
INTERNAL_TAGS = {"virtualnetwork", "azureloadbalancer"}


def _nsgs(data) -> list:
    if isinstance(data, dict):
        if isinstance(data.get("value"), list):       # REST list envelope
            return data["value"]
        return [data]
    return data if isinstance(data, list) else []


def _prop(obj: dict, key: str):
    """Top-level (az CLI) or under `properties` (ARM/REST)."""
    if key in obj:
        return obj[key]
    return (obj.get("properties") or {}).get(key)


def _is_address(v: str) -> bool:
    return "/" in v or ":" in v or bool(re.fullmatch(r"[\d.]+", v))


def _addresses(rule: dict, side: str, g: ObjectGraph, ev) -> list[str]:
    """Everything on one side of a rule: CIDRs, tags, application groups."""
    out: list[str] = []
    single = _prop(rule, f"{side}AddressPrefix")
    multi = _prop(rule, f"{side}AddressPrefixes") or []
    for raw in ([single] if single else []) + list(multi):
        v = str(raw).strip()
        if not v:
            continue
        if v == "*":
            out.append("any")
            continue
        if _is_address(v):
            out.append(v)
            continue
        if g.lookup(v) is None:
            if v.lower() == "internet":
                g.add(Node(id=v, kind=NodeKind.ADDRESS, name=v,
                           values=["0.0.0.0/0"],
                           attrs={"detail": "Azure service tag for the public "
                                            "internet"},
                           evidence=list(ev)))
            elif v.lower() in INTERNAL_TAGS:
                g.add(Node(id=v, kind=NodeKind.ADDRESS_GROUP, name=v,
                           values=[f"tag:{v}"],
                           attrs={"value_is_identifier": True,
                                  "detail": "Azure service tag that is internal "
                                            "by definition; its addresses are "
                                            "managed by Azure"},
                           evidence=list(ev)))
            else:
                g.add(Node(id=v, kind=NodeKind.ADDRESS_GROUP, name=v,
                           attrs={"members_unknown": True,
                                  "detail": "Azure service tag whose address "
                                            "set is managed by Azure, may "
                                            "include public ranges, and is "
                                            "not in this export"},
                           evidence=list(ev)))
        out.append(v)

    for asg in _prop(rule, f"{side}ApplicationSecurityGroups") or []:
        name = str(asg.get("id", "")).rsplit("/", 1)[-1] or "application-security-group"
        if g.lookup(name) is None:
            g.add(Node(id=name, kind=NodeKind.ADDRESS_GROUP, name=name,
                       values=[f"asg:{name}"],
                       attrs={"value_is_identifier": True,
                              "detail": "application security group; which "
                                        "NICs belong to it is runtime state"},
                       evidence=list(ev)))
        out.append(name)
    return out


def _services(rule: dict) -> list[str]:
    proto = str(_prop(rule, "protocol") or "*").lower()
    single = _prop(rule, "destinationPortRange")
    multi = _prop(rule, "destinationPortRanges") or []
    ports = [str(p).strip() for p in ([single] if single else []) + list(multi)]

    if proto in ("*", "any"):
        if not ports or ports == ["*"]:
            return ["any"]
        protos = ["tcp", "udp"]
    elif proto in ("tcp", "udp"):
        protos = [proto]
    else:
        return [proto]                  # icmp, esp, ah: protocol only
    out = []
    for pr in protos:
        for p in ports or ["*"]:
            # "*" is every port. Written as an explicit range so the exposure
            # facts intersect it with the ports that matter rather than
            # treating it as a literal "any".
            out.append(f"{pr}/0-65535" if p == "*" else f"{pr}/{p}")
    return out


def build(doc) -> ObjectGraph:
    g = ObjectGraph()
    data = getattr(doc, "data", doc)
    nsgs = _nsgs(data)
    top = "$" if isinstance(data, dict) and not isinstance(data.get("value"), list) else None
    default_ev: list = []
    order = 0

    for ni, nsg in enumerate(nsgs):
        name = nsg.get("name") or f"nsg-{ni}"
        base = top or (f"$.value[{ni}]" if isinstance(data, dict) else f"$[{ni}]")
        ev = [doc.evidence(base, {"name": name, "id": nsg.get("id")})]

        if g.lookup(name) is None:
            g.add(Node(id=name, kind=NodeKind.ZONE, name=name, values=[name],
                       attrs={"value_is_identifier": True,
                              "location": nsg.get("location") or "",
                              "resource_group": nsg.get("resourceGroup") or "",
                              "detail": "the NSG is the attachment point; the "
                                        "addresses of its subnets and NICs are "
                                        "runtime state"},
                       evidence=ev))

        entries = []
        for key in ("securityRules", "defaultSecurityRules"):
            where = key if key in nsg else f"properties.{key}"
            for i, r in enumerate(_prop(nsg, key) or []):
                entries.append((r, f"{base}.{where}[{i}]", key == "defaultSecurityRules"))
        # Each direction is its own chain; within it, priority decides.
        entries.sort(key=lambda t: (str(_prop(t[0], "direction") or "").lower(),
                                    int(_prop(t[0], "priority") or 65535)))

        for r, path, is_default in entries:
            order += 1
            rname = _prop(r, "name") or f"rule-{order}"
            prio = _prop(r, "priority")
            rev = [doc.evidence(path, {k: _prop(r, k) for k in (
                "name", "priority", "direction", "access", "protocol",
                "sourceAddressPrefix", "destinationPortRange")
                if _prop(r, k) is not None})]
            inbound = str(_prop(r, "direction") or "").lower() == "inbound"
            services = _services(r)
            # Port-less protocols (icmp, esp, ah) become known services, or the
            # resolver reports them as broken references.
            for s in services:
                if "/" not in s and s.lower() != "any" and g.lookup(s) is None:
                    g.add(Node(id=s, kind=NodeKind.SERVICE, name=s, values=[s],
                               attrs={"detail": "IP protocol with no port component"},
                               evidence=list(rev)))
            g.add_rule(SecurityRule(
                id=f"{name}:{rname}",
                name=f"{name}/{rname} (priority {prio})",
                order=order,
                enabled=True,
                action="allow" if str(_prop(r, "access") or "").lower() == "allow" else "deny",
                source=_addresses(r, "source", g, rev),
                destination=_addresses(r, "destination", g, rev),
                services=services,
                source_zones=[] if inbound else [name],
                destination_zones=[name] if inbound else [],
                # Per-rule counters and flow logs are separate Azure resources.
                hit_count=None,
                logging=None,
                evidence=rev))
            if is_default and rname == "DenyAllInBound":
                default_ev = rev

    g.default_action = "deny"
    g.default_action_observed = True
    # With evidence the bridge records OBSERVED; without it (defaults omitted
    # from the export) it records the invariant as DEFAULT_ASSUMED.
    g.default_action_evidence = default_ev
    return g
