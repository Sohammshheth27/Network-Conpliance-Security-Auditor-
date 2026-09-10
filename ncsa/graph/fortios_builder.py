"""Build an ObjectGraph from a parsed FortiOS configuration.

Vendor adapter, doc section 3: FortiOS-specific in, vendor-neutral graph out.
The resolver, the facts and the controls never learn FortiOS naming.

VALIDATION STATUS
-----------------
CONSTRUCTED FIXTURE, NOT CAPTURED DEVICE OUTPUT.

tests/fixtures/fortios_edge.conf is written from Fortinet's published CLI
syntax; it is not a real "show full-configuration". That makes this builder and
its fixture agree by construction, which is weaker evidence than the Palo Alto
builder has -- that one is validated against a genuine export, and the real
config immediately exposed an XML reader bug that no fixture had found.

Every mapping here should be re-verified against a real FortiGate config
before this builder is relied on. test_fortios_graph.py states the same caveat
and holds a tripwire on it.

FORTIOS SEMANTICS THAT A NAIVE READING GETS WRONG
-------------------------------------------------
1. AN ABSENT "status" MEANS ENABLED.
   FortiOS writes "set status disable" only to turn a policy off; an enabled
   policy carries no status line at all. SonicOS is the exact opposite -- an
   absent enabled flag there means off. Carrying the SonicOS assumption across
   would silently disable a live rulebase and report a permissive firewall as
   harmless, which is the most dangerous direction for this error to run.

2. AN ABSENT "action" MEANS DENY.
   The platform default for a firewall policy is deny. Assuming allow would
   invent permitted traffic.

3. PREDEFINED SERVICES ARE NOT IN THE CONFIGURATION.
   ALL, HTTP, HTTPS, DNS and the rest are built into FortiOS and never
   written to the config file. Leaving them unresolved would be tolerable for
   most names, but not for ALL: an unresolved service makes a rule
   UNEVALUABLE, and a rule permitting every port would then be hidden rather
   than reported. The direction of that error matters, so the documented
   platform services are supplied with their provenance recorded.

4. NEGATION INVERTS THE MATCH.
   "set srcaddr-negate enable" means the policy matches everything EXCEPT the
   listed addresses. The vendor-neutral SecurityRule has no negation, so a
   negated policy read literally means the opposite of what the device does.
   It is marked unevaluable rather than mis-modelled.

5. A POLICY IS SCOPED TO INTERFACES OR ZONES, INTERCHANGEABLY.
   srcintf/dstintf accept either an interface name or a zone name. Interfaces
   are translated through "config system zone" where a zone claims them, and
   left as-is where none does; inventing a zone per interface would fabricate
   a segmentation boundary that the device does not have.
"""
from __future__ import annotations

import ipaddress
import re

from ..readers.fortinet_block import BlockConfig
from .model import Node, NodeKind, ObjectGraph, SecurityRule

_POLICY = re.compile(r"^firewall policy/(?P<id>[^/]+)/(?P<leaf>.+)$")
_ADDRESS = re.compile(r"^firewall address/(?P<name>[^/]+)/(?P<leaf>.+)$")
_ADDRGRP = re.compile(r"^firewall addrgrp/(?P<name>[^/]+)/(?P<leaf>.+)$")
_SERVICE = re.compile(r"^firewall service custom/(?P<name>[^/]+)/(?P<leaf>.+)$")
_SVCGRP = re.compile(r"^firewall service group/(?P<name>[^/]+)/(?P<leaf>.+)$")
_ZONE = re.compile(r"^system zone/(?P<name>[^/]+)/(?P<leaf>.+)$")
_IFACE = re.compile(r"^system interface/(?P<name>[^/]+)/(?P<leaf>.+)$")

#: FortiOS marks an internet-facing interface with "set role wan". That is the
#: device's own statement about the interface, not our guess from its name.
UNTRUSTED_ROLES = {"wan"}
UNTRUSTED_NAMES = {"wan", "untrust", "internet", "outside", "public", "external"}

#: Documented FortiOS predefined services. NOT exhaustive -- FortiOS ships
#: roughly a hundred. A name absent from this table stays unresolved, which is
#: the safe direction: the rule becomes unevaluable and says so, rather than
#: being silently treated as unconstrained.
#:
#: ALL is the one that must be here. It means every protocol and every port,
#: and reach.py treats the token "all" as unconstrained, so a policy using it
#: is correctly reported as wide open instead of quietly unevaluable.
PREDEFINED_SERVICES: dict[str, list[str]] = {
    "ALL": ["all"],
    "ALL_TCP": ["tcp/1-65535"],
    "ALL_UDP": ["udp/1-65535"],
    "ALL_ICMP": ["icmp"],
    "PING": ["icmp"],
    "HTTP": ["tcp/80"],
    "HTTPS": ["tcp/443"],
    "SSH": ["tcp/22"],
    "TELNET": ["tcp/23"],
    "FTP": ["tcp/21"],
    "SMTP": ["tcp/25"],
    "POP3": ["tcp/110"],
    "IMAP": ["tcp/143"],
    "DNS": ["tcp/53", "udp/53"],
    "NTP": ["udp/123"],
    "SNMP": ["udp/161", "udp/162"],
    "SYSLOG": ["udp/514"],
    "LDAP": ["tcp/389"],
    "RDP": ["tcp/3389"],
    "SAMBA": ["tcp/139"],
    "SMB": ["tcp/445"],
    "MS-SQL": ["tcp/1433"],
    "MYSQL": ["tcp/3306"],
}

_QUOTED = re.compile(r'"([^"]*)"')


def _names(value: str) -> list[str]:
    """Split a FortiOS multi-value into names.

    The reader strips the quotes from a single quoted value but leaves them on
    a list, because "set srcaddr" takes either form:

        set srcaddr "lan-subnet"                 -> lan-subnet
        set srcaddr "web servers" "db servers"   -> "web servers" "db servers"

    Splitting the second on whitespace would produce four names, two of them
    fabricated. Splitting on the quotes is the only reading that survives an
    object name containing a space, which is common on a real device.
    """
    v = (value or "").strip()
    if not v:
        return []
    if '"' in v:
        return [n for n in _QUOTED.findall(v) if n]
    return [v]


def _cidr(value: str) -> str | None:
    """FortiOS writes "set subnet <addr> <mask>". Return it as a CIDR."""
    parts = (value or "").split()
    try:
        if len(parts) == 2:
            return str(ipaddress.ip_network(f"{parts[0]}/{parts[1]}",
                                            strict=False))
        if len(parts) == 1 and "/" in parts[0]:
            return str(ipaddress.ip_network(parts[0], strict=False))
    except ValueError:
        return None
    return None


def _portrange(spec: str, proto: str) -> list[str]:
    """FortiOS port ranges: "80", "8000-8100", "80 443", "80:1024-65535".

    The part after the colon is the SOURCE port range. Folding it into the
    destination service would answer a destination-port question with the
    client's port number.
    """
    out = []
    for token in (spec or "").split():
        dst = token.split(":")[0].strip()
        if dst:
            out.append(f"{proto}/{dst}")
    return out


def _leaf_values(cfg: BlockConfig, prefix_rx, ) -> dict:
    """Group path leaves by object name, preserving first-seen line order."""
    grouped: dict[str, dict[str, tuple[str, int, str]]] = {}
    for path, (val, ln, raw) in cfg.values.items():
        m = prefix_rx.match(path)
        if m:
            grouped.setdefault(m.group("name"), {})[m.group("leaf")] = (val, ln, raw)
    return grouped


def _addresses(cfg: BlockConfig, g: ObjectGraph) -> None:
    for name, leaves in _leaf_values(cfg, _ADDRESS).items():
        first = next(iter(leaves.values()))
        node = Node(id=name, kind=NodeKind.ADDRESS, name=name,
                    evidence=[cfg.evidence(first[1], first[2])])
        kind = (leaves.get("type") or ("ipmask",))[0]
        if "subnet" in leaves:
            cidr = _cidr(leaves["subnet"][0])
            if cidr:
                node.values = [cidr]
        if kind == "iprange" and "start-ip" in leaves:
            lo = leaves["start-ip"][0]
            hi = (leaves.get("end-ip") or (lo,))[0]
            node.values = [f"{lo}-{hi}"]
        elif kind == "fqdn" and "fqdn" in leaves:
            # An FQDN object resolves at runtime through DNS. Its addresses
            # are genuinely not in the configuration, so the name is recorded
            # as the value and the form says why it cannot be compared to a
            # CIDR.
            node.values = [leaves["fqdn"][0]]
        elif kind == "wildcard" and "wildcard" in leaves:
            node.values = [leaves["wildcard"][0]]
        node.attrs["form"] = kind
        g.add(node)


def _address_groups(cfg: BlockConfig, g: ObjectGraph) -> None:
    for name, leaves in _leaf_values(cfg, _ADDRGRP).items():
        if "member" not in leaves:
            continue
        val, ln, raw = leaves["member"]
        node = g.lookup(name)
        if node is None:
            node = Node(id=name, kind=NodeKind.ADDRESS_GROUP, name=name,
                        evidence=[cfg.evidence(ln, raw)])
            g.add(node)
        node.kind = NodeKind.ADDRESS_GROUP
        for member in _names(val):
            if member not in node.members:
                node.members.append(member)


def _services(cfg: BlockConfig, g: ObjectGraph) -> None:
    for name, leaves in _leaf_values(cfg, _SERVICE).items():
        first = next(iter(leaves.values()))
        node = Node(id=name, kind=NodeKind.SERVICE, name=name,
                    evidence=[cfg.evidence(first[1], first[2])])
        if "tcp-portrange" in leaves:
            node.values += _portrange(leaves["tcp-portrange"][0], "tcp")
        if "udp-portrange" in leaves:
            node.values += _portrange(leaves["udp-portrange"][0], "udp")
        if "sctp-portrange" in leaves:
            node.values += _portrange(leaves["sctp-portrange"][0], "sctp")
        if not node.values and "protocol" in leaves:
            # An IP-protocol service (protocol IP, protocol-number 47 for GRE)
            # has no ports at all. Recorded by name so the resolver reports it
            # as a real object we cannot express in port terms, rather than as
            # a missing one.
            node.attrs["protocol"] = leaves["protocol"][0]
            number = leaves.get("protocol-number")
            if number:
                node.attrs["protocol_number"] = number[0]
        g.add(node)


def _service_groups(cfg: BlockConfig, g: ObjectGraph) -> None:
    for name, leaves in _leaf_values(cfg, _SVCGRP).items():
        if "member" not in leaves:
            continue
        val, ln, raw = leaves["member"]
        node = g.lookup(name)
        if node is None:
            node = Node(id=name, kind=NodeKind.SERVICE_GROUP, name=name,
                        evidence=[cfg.evidence(ln, raw)])
            g.add(node)
        node.kind = NodeKind.SERVICE_GROUP
        for member in _names(val):
            if member not in node.members:
                node.members.append(member)


def _zones_and_interfaces(cfg: BlockConfig, g: ObjectGraph) -> None:
    for name, leaves in _leaf_values(cfg, _ZONE).items():
        if "interface" not in leaves:
            continue
        val, ln, raw = leaves["interface"]
        node = g.lookup(name)
        if node is None:
            node = Node(id=name, kind=NodeKind.ZONE, name=name,
                        evidence=[cfg.evidence(ln, raw)])
            g.add(node)
        node.kind = NodeKind.ZONE
        for iface in _names(val):
            g.zones_of_interface[iface] = name
            if iface not in node.members:
                node.members.append(iface)
        if name.lower() in UNTRUSTED_NAMES:
            g.untrusted_zones.add(name)

    # An interface not claimed by a zone is its own policy scope on FortiOS,
    # so it is recorded as an interface node. Its "role wan" is the device's
    # own statement that it faces the internet -- stronger evidence than
    # guessing from the name, though the name is used as a fallback.
    for name, leaves in _leaf_values(cfg, _IFACE).items():
        role = (leaves.get("role") or ("",))[0].lower()
        if g.lookup(name) is None:
            first = next(iter(leaves.values()))
            g.add(Node(id=name, kind=NodeKind.INTERFACE, name=name,
                       attrs={"role": role} if role else {},
                       evidence=[cfg.evidence(first[1], first[2])]))
        if role in UNTRUSTED_ROLES or name.lower() in UNTRUSTED_NAMES:
            # The zone the policy will name is this interface, when no zone
            # claims it.
            g.untrusted_zones.add(g.zones_of_interface.get(name, name))


def _predefined(g: ObjectGraph) -> None:
    """Supply the platform services a policy referenced but the config lacks.

    Only names actually referenced are added, and never over an object the
    config defines: FortiOS lets an administrator override a predefined
    service, and the device's own definition wins.
    """
    # Group members count as references. A service group listing HTTP and
    # HTTPS is the common way a policy reaches a predefined service, and
    # looking only at rules would leave the group's members unresolved --
    # making every policy that uses the group unevaluable.
    referenced = {s for r in g.rules for s in r.services}
    referenced |= {m for n in g.nodes.values()
                   if n.kind is NodeKind.SERVICE_GROUP for m in n.members}
    for name, values in PREDEFINED_SERVICES.items():
        if name not in referenced or g.lookup(name) is not None:
            continue
        ev = next((r.evidence for r in g.rules
                   if name in r.services and r.evidence), [])
        g.add(Node(id=name, kind=NodeKind.SERVICE, name=name, values=list(values),
                   attrs={"predefined": True,
                          "provenance": "FortiOS platform default, not read "
                                        "from this configuration"},
                   evidence=list(ev)))


def _scope(names: list[str], g: ObjectGraph) -> list[str]:
    """Translate interface names to the zone that claims them.

    A policy may name either. Leaving an interface untranslated where a zone
    owns it would make two policies on the same boundary look unrelated.
    """
    return [g.zones_of_interface.get(n, n) for n in names]


def _rules(cfg: BlockConfig, g: ObjectGraph) -> None:
    grouped: dict[str, dict[str, tuple[str, int, str]]] = {}
    order: list[str] = []
    for path, entry in cfg.values.items():
        m = _POLICY.match(path)
        if not m:
            continue
        pid = m.group("id")
        if pid not in grouped:
            grouped[pid] = {}
            order.append(pid)
        grouped[pid][m.group("leaf")] = entry

    for position, pid in enumerate(order, start=1):
        leaves = grouped[pid]

        def val(leaf: str, default: str = "", _lv=leaves) -> str:
            return (_lv.get(leaf) or (default, 0, ""))[0]

        name = val("name") or f"policy {pid}"
        ev_src = leaves.get("name") or leaves.get("action") or \
            next(iter(leaves.values()))

        rule = SecurityRule(
            id=f"policy:{pid}",
            name=f"{name} [#{pid}]",
            # Document order is evaluation order on FortiOS. The policyid is
            # an identifier, not a position -- policies can be reordered
            # without renumbering, so sorting by id would evaluate the
            # rulebase in an order the device does not use.
            order=position,
            # Absent status means ENABLED on FortiOS. See the module docstring.
            enabled=val("status", "enable").strip().lower() != "disable",
            # Absent action means DENY. Assuming allow would invent traffic.
            action="allow" if val("action", "deny").strip().lower()
            in ("accept", "allow", "permit") else "deny",
            source=_names(val("srcaddr")) or ["any"],
            destination=_names(val("dstaddr")) or ["any"],
            services=_names(val("service")) or ["any"],
            source_zones=_scope(_names(val("srcintf")), g),
            destination_zones=_scope(_names(val("dstintf")), g),
            # "set logtraffic disable" is explicit; all/utm both log.
            logging=(val("logtraffic", "").strip().lower() not in
                     ("", "disable")) or None,
            # FortiOS keeps per-policy counters on the device, not in the
            # configuration file. None, never 0: zero would make every policy
            # look dead and turn a healthy rulebase into deletion candidates.
            hit_count=None,
            evidence=[cfg.evidence(ev_src[1], ev_src[2])],
        )

        # Negation and a non-permanent schedule both mean the same thing to a
        # reachability question: this policy cannot decide it from the
        # configuration alone. `program` is the model's existing word for a
        # rule scoped by something a port question cannot settle, so reach
        # skips it and discloses it rather than guessing.
        undecidable = []
        for leaf, label in (("srcaddr-negate", "negate-source"),
                            ("dstaddr-negate", "negate-destination"),
                            ("service-negate", "negate-service")):
            if val(leaf, "disable").strip().lower() == "enable":
                undecidable.append(label)
        schedule = val("schedule", "always").strip().strip('"')
        if schedule and schedule.lower() != "always":
            # A policy active only inside a time window is not in force at an
            # arbitrary moment, and the configuration does not say when the
            # question is being asked.
            undecidable.append(f"schedule:{schedule}")
        if undecidable:
            rule.program = "; ".join(undecidable)

        g.add_rule(rule)


def build(cfg: BlockConfig) -> ObjectGraph:
    g = ObjectGraph()
    _addresses(cfg, g)
    _address_groups(cfg, g)
    _services(cfg, g)
    _service_groups(cfg, g)
    _zones_and_interfaces(cfg, g)
    _rules(cfg, g)
    _predefined(g)

    # A FortiOS policy set is default-deny: the implicit policy 0 drops
    # anything no policy accepted. That is a platform property we know rather
    # than something this file states, so `observed` stays False and a reader
    # can tell our assumption from our reading.
    g.default_action = "deny"
    g.default_action_observed = False
    return g
