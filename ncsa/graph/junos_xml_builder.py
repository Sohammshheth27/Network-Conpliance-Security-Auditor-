"""Build an ObjectGraph from `show configuration | display xml` on an SRX.

The XML sibling of junos_builder. Same device, same policy model, different
serialisation -- and the difference matters, because the two readers expose
repetition differently.

WHY THIS IS NOT junos_builder WITH A DIFFERENT READER
-----------------------------------------------------
junos_builder reads `cfg.multi`, the braces reader's map of repeated leaves.
XmlConfig has no `multi`; handing it to that builder raises AttributeError and
-- until the bare `except` in the pipeline was replaced with a logged one --
every Juniper XML device silently got no graph at all.

THE STRUCTURAL LIMIT, AND WHY THIS REFUSES RATHER THAN GUESSES
--------------------------------------------------------------
Junos XML nests policies inside a zone-pair container, and BOTH elements are
called <policy>:

    <policies>
      <policy>                          <- the zone pair
        <from-zone-name>trust</from-zone-name>
        <to-zone-name>untrust</to-zone-name>
        <policy>                        <- the rule
          <name>allow-web-out</name>

Repeated siblings carry no key attribute, so the reader flattens them onto one
path. With a single zone pair that is unambiguous. With several, `get_all`
returns every rule name and every zone name as two flat lists with nothing to
associate them by -- and pairing them by position would be a guess that
silently attaches rules to the wrong security boundary.

PAN-OS does not have this problem because its repeated elements carry
`entry[name]`, which the reader indexes.

So: one zone pair is read; more than one makes this builder return None with a
note. A missing graph is an honest gap the caller already handles -- the
analyses say "no rule-graph builder for this platform" and refuse. A graph with
rules attached to the wrong zones would answer reachability questions
confidently and wrongly, which is far worse.
"""
from __future__ import annotations

from .model import Node, NodeKind, ObjectGraph, SecurityRule

_POLICIES = "configuration/security/policies"
_PAIR = f"{_POLICIES}/policy"
_RULE = f"{_PAIR}/policy"

UNTRUSTED = {"untrust", "internet", "wan", "outside", "public", "external"}

#: Junos ships these predefined applications; they are not written into the
#: configuration. A rule referencing junos-https would otherwise resolve to
#: nothing and become unevaluable -- and almost every real policy uses them.
#: Supplied only when referenced, and labelled so a reader can tell a platform
#: constant from something we read off the device.
PREDEFINED_APPLICATIONS = {
    "junos-http": ["tcp/80"],
    "junos-https": ["tcp/443"],
    "junos-ssh": ["tcp/22"],
    "junos-telnet": ["tcp/23"],
    "junos-ftp": ["tcp/21"],
    "junos-smtp": ["tcp/25"],
    "junos-dns-udp": ["udp/53"],
    "junos-dns-tcp": ["tcp/53"],
    "junos-ntp": ["udp/123"],
    "junos-snmp": ["udp/161"],
    "junos-ldap": ["tcp/389"],
    "junos-ms-rdp": ["tcp/3389"],
    "junos-ping": ["icmp"],
}


def _values(cfg, path: str) -> list[str]:
    return [v for v, _ln, _raw in cfg.get_all(path)]


def _predefined(g: ObjectGraph, cfg) -> None:
    referenced = {s for r in g.rules for s in r.services}
    for name, values in PREDEFINED_APPLICATIONS.items():
        if name not in referenced or g.lookup(name) is not None:
            continue
        ev = next((r.evidence for r in g.rules
                   if name in r.services and r.evidence), [])
        g.add(Node(id=name, kind=NodeKind.SERVICE, name=name,
                   values=list(values),
                   attrs={"predefined": True,
                          "provenance": "Junos platform default, not read "
                                        "from this configuration"},
                   evidence=list(ev)))


def build(cfg) -> ObjectGraph | None:
    """`cfg` is an XmlConfig. Returns None when the structure is ambiguous."""
    zone_pairs = _values(cfg, f"{_PAIR}/from-zone-name")
    to_zones = _values(cfg, f"{_PAIR}/to-zone-name")

    if len(zone_pairs) > 1 or len(to_zones) > 1:
        # See the module docstring: several zone pairs cannot be associated
        # with their rules through this reader. Refuse.
        return None

    g = ObjectGraph()

    # ---------------------------------------------------------- default policy
    # `set security policies default-policy permit-all` is valid and documented.
    # Assuming deny would report a permit-all device as compliant -- a false
    # PASS on a high-severity control, from one wrong assumption.
    permit_all = cfg.get(f"{_POLICIES}/default-policy/permit-all")
    deny_all = cfg.get(f"{_POLICIES}/default-policy/deny-all")
    if permit_all is not None:
        g.default_action, g.default_action_observed = "allow", True
        g.default_action_evidence = [cfg.evidence(permit_all[1], permit_all[2])]
    elif deny_all is not None:
        g.default_action, g.default_action_observed = "deny", True
        g.default_action_evidence = [cfg.evidence(deny_all[1], deny_all[2])]
    else:
        g.default_action, g.default_action_observed = "deny", False

    from_zone = zone_pairs[0] if zone_pairs else ""
    to_zone = to_zones[0] if to_zones else ""
    for zone in (from_zone, to_zone):
        if zone and g.lookup(zone) is None:
            hit = cfg.get(f"{_PAIR}/from-zone-name")
            g.add(Node(id=zone, kind=NodeKind.ZONE, name=zone,
                       evidence=[cfg.evidence(hit[1], hit[2])] if hit else []))
        if zone and zone.lower() in UNTRUSTED:
            g.untrusted_zones.add(zone)

    # ----------------------------------------------------------------- rules
    names = _values(cfg, f"{_RULE}/name")
    for i, name in enumerate(names, start=1):
        hit = cfg.get(f"{_RULE}/name")
        ev = [cfg.evidence(hit[1], hit[2])] if hit else []

        # `then` carries the action as an EMPTY element -- <permit/> -- so its
        # presence is the value. Absence of both is not "allow": Junos requires
        # an explicit action, so a rule with neither is one we misread.
        permit = cfg.get(f"{_RULE}/then/permit")
        deny = (cfg.get(f"{_RULE}/then/deny")
                or cfg.get(f"{_RULE}/then/reject"))
        action = "allow" if permit is not None else "deny" if deny is not None else "deny"

        logged = (cfg.get(f"{_RULE}/then/log/session-close") is not None
                  or cfg.get(f"{_RULE}/then/log/session-init") is not None)

        g.add_rule(SecurityRule(
            id=f"{from_zone}->{to_zone}:{name}",
            name=name,
            order=i,
            enabled=True,
            action=action,
            source=_values(cfg, f"{_RULE}/match/source-address") or ["any"],
            destination=_values(cfg, f"{_RULE}/match/destination-address") or ["any"],
            services=_values(cfg, f"{_RULE}/match/application") or ["any"],
            source_zones=[from_zone] if from_zone else [],
            destination_zones=[to_zone] if to_zone else [],
            logging=logged or None,
            # A configuration export carries no counters. None, never 0: zero
            # would make every policy look dead and turn a healthy rulebase
            # into deletion candidates.
            hit_count=None,
            evidence=ev,
        ))

    # ---------------------------------------------------------- address book
    for path in cfg.paths:
        if "/address-book/" not in path or not path.endswith("/ip-prefix"):
            continue
        hit = cfg.get(path)
        if not hit:
            continue
        addr = path.rsplit("/address/", 1)[-1].rsplit("/", 1)[0]
        if addr and g.lookup(addr) is None:
            g.add(Node(id=addr, kind=NodeKind.ADDRESS, name=addr,
                       values=[hit[0]],
                       evidence=[cfg.evidence(hit[1], hit[2])]))

    _predefined(g, cfg)
    return g
