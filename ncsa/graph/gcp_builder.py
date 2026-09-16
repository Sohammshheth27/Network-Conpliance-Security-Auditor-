"""Build an ObjectGraph from Google Cloud VPC firewall rules.

    gcloud compute firewall-rules list --format=json

WHERE GCP DIFFERS
-----------------
1. VPC-WIDE, ORDERED BY PRIORITY, DENY WINS TIES.
   Priority 0-65535, lower first. At equal priority a DENY takes precedence
   over an ALLOW, so rules are sorted (priority, deny-before-allow) and first
   match is then correct.

2. TARGETS ARE TAGS AND SERVICE ACCOUNTS.
   `targetTags` / `targetServiceAccounts` restrict which instances a rule
   applies to; no target means every instance in the network. Which instances
   carry a tag is runtime state, so a tag resolves to its IDENTIFIER, as an
   AWS security group does. That keeps "0.0.0.0/0 -> tag:db on 5432" an
   exposure finding instead of an unevaluable rule -- the tagged instances
   are unknown, but the exposure of whichever they are is not.

3. THE IMPLIED RULES ARE NOT IN THE EXPORT.
   Every VPC has an implied deny-all ingress and an implied ALLOW-all egress
   at priority 65535. They are not in the file. A single graph-wide default of
   "deny" would therefore answer every unmatched egress question wrongly, so
   the default is left UNOBSERVED: unmatched traffic is reported undecidable,
   not denied. The ingress default is recorded by the pack, as assumed.

4. DISABLED RULES ARE PRESENT.
   `disabled: true` rules are in the export and do not apply.

5. LOGGING IS PER RULE.
   `logConfig.enable` is a real per-rule setting, so unlike AWS it is read
   rather than left unknown.

6. AN INGRESS RULE WITH NO STATED SOURCE is not guessed. It resolves as
   UNSUPPORTED and is reported unevaluable rather than assumed to be 0.0.0.0/0.

Validated on a FIXTURE built from the documented `gcloud` output shape, using
the real default-network rule names and priority (65534).
"""
from __future__ import annotations

from .model import Node, NodeKind, ObjectGraph, SecurityRule


def _identifier(g: ObjectGraph, name: str, detail: str, ev) -> str:
    if g.lookup(name) is None:
        g.add(Node(id=name, kind=NodeKind.ADDRESS_GROUP, name=name,
                   values=[name],
                   attrs={"value_is_identifier": True, "detail": detail},
                   evidence=list(ev)))
    return name


def _protocol_nodes(g: ObjectGraph, services: list[str], ev) -> None:
    """Register port-less protocols (icmp, esp, ...) as known services.

    The resolver treats a bare `icmp` as an unknown object, which reported the
    default-network ICMP rule as a broken reference. A protocol with no ports
    contributes no ports to the exposure facts, so resolving it cannot create
    an exposure finding either.
    """
    for s in services:
        if "/" not in s and s.lower() != "any" and g.lookup(s) is None:
            g.add(Node(id=s, kind=NodeKind.SERVICE, name=s, values=[s],
                       attrs={"detail": "IP protocol with no port component"},
                       evidence=list(ev)))


def _services(r: dict) -> list[str]:
    out = []
    for entry in (r.get("allowed") or r.get("denied") or []):
        proto = str(entry.get("IPProtocol", "")).lower()
        if proto in ("all", ""):
            return ["any"]
        ports = entry.get("ports") or []
        if proto in ("tcp", "udp", "sctp"):
            if not ports:
                out.append(f"{proto}/0-65535")
            else:
                out.extend(f"{proto}/{p}" for p in ports)
        else:
            out.append(proto)
    return out


def build(doc) -> ObjectGraph:
    g = ObjectGraph()
    data = getattr(doc, "data", doc)
    rules = data if isinstance(data, list) else (data.get("items") or [])

    entries = [(i, r) for i, r in enumerate(rules) if isinstance(r, dict)]
    entries.sort(key=lambda t: (int(t[1].get("priority", 1000)),
                                0 if t[1].get("denied") else 1))

    for order, (i, r) in enumerate(entries, start=1):
        net = str(r.get("network", "")).rstrip("/").rsplit("/", 1)[-1] or "network"
        name = r.get("name") or f"rule-{i}"
        ev = [doc.evidence(f"$[{i}]", {k: r[k] for k in (
            "name", "direction", "priority", "sourceRanges", "destinationRanges",
            "allowed", "denied", "targetTags", "disabled") if k in r})]

        if g.lookup(net) is None:
            g.add(Node(id=net, kind=NodeKind.ZONE, name=net, values=[net],
                       attrs={"value_is_identifier": True,
                              "detail": "VPC network; the addresses of its "
                                        "instances are runtime state"},
                       evidence=ev))

        targets = [_identifier(g, f"tag:{t}", "instances carrying this network "
                               "tag; which ones is runtime state", ev)
                   for t in r.get("targetTags") or []]
        targets += [_identifier(g, f"sa:{s}", "instances running as this "
                                "service account; which ones is runtime state", ev)
                    for s in r.get("targetServiceAccounts") or []]
        local = targets or [net]

        ingress = str(r.get("direction", "INGRESS")).upper() == "INGRESS"
        if ingress:
            remote = list(r.get("sourceRanges") or [])
            remote += [_identifier(g, f"tag:{t}", "instances carrying this "
                                   "network tag", ev) for t in r.get("sourceTags") or []]
            remote += [_identifier(g, f"sa:{s}", "instances running as this "
                                   "service account", ev)
                       for s in r.get("sourceServiceAccounts") or []]
            if not remote:
                unstated = "unstated-source"
                if g.lookup(unstated) is None:
                    g.add(Node(id=unstated, kind=NodeKind.ADDRESS_GROUP,
                               name=unstated,
                               attrs={"members_unknown": True,
                                      "detail": "the rule states no source; "
                                                "not assumed to be 0.0.0.0/0"},
                               evidence=list(ev)))
                remote = [unstated]
            source, destination = remote, local
        else:
            source = local
            destination = list(r.get("destinationRanges") or []) or ["any"]

        services = _services(r)
        _protocol_nodes(g, services, ev)
        log = r.get("logConfig")
        g.add_rule(SecurityRule(
            id=f"{net}:{name}",
            name=f"{name} (priority {r.get('priority', 1000)})",
            order=order,
            enabled=not bool(r.get("disabled", False)),
            action="deny" if r.get("denied") else "allow",
            source=source,
            destination=destination,
            services=services,
            source_zones=[] if ingress else [net],
            destination_zones=[net] if ingress else [],
            hit_count=None,
            logging=(bool(log.get("enable")) if isinstance(log, dict) else None),
            evidence=ev))

    # Implied rules are not in the file, and egress defaults to ALLOW -- so a
    # single graph-wide default must not be claimed. See point 3 above.
    g.default_action = "deny"
    g.default_action_observed = False
    return g
