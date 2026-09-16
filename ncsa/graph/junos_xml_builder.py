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

ZONE PAIRS AND RULES ARE READ BY THEIR OWN KEYS
-----------------------------------------------
Junos XML nests policies inside a zone-pair container, and BOTH elements are
called <policy>:

    <policies>
      <policy>                          <- the zone pair  -> policy[trust>untrust]
        <from-zone-name>trust</from-zone-name>
        <to-zone-name>untrust</to-zone-name>
        <policy>                        <- the rule       -> policy[allow-web-out]
          <name>allow-web-out</name>

The reader keys each by its identity, so every rule is read from its own path.
Before that, repeated siblings shared one path: each rule was given the FIRST
rule's action and logging and the union of every rule's addresses, and a
device with several zone pairs got no graph at all. Rules are taken in document
order, because first-match order is the policy.
"""
from __future__ import annotations

import re
from urllib.parse import unquote

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


_PAIR_KEYED = re.compile(re.escape(_POLICIES) + r"/policy\[([^\]]*)\]/")
_RULE_KEYED = re.compile(re.escape(_POLICIES) + r"/policy\[([^\]]*)\]/policy\[([^\]]*)\]/")
_ADDR_KEYED = re.compile(r"/address\[([^\]]*)\]/ip-prefix$")


def _in_order(regex, cfg) -> list:
    """Distinct keys matched by `regex` over the paths, in DOCUMENT order."""
    seen: dict = {}
    for path in cfg.iter_paths():
        m = regex.match(path) if regex.pattern.startswith(re.escape(_POLICIES)) \
            else regex.search(path)
        if m:
            seen.setdefault(m.groups(), None)
    return list(seen)


def build(cfg) -> ObjectGraph | None:
    """`cfg` is an XmlConfig, whose repeated elements are keyed by identity:
    each zone pair is `policy[from>to]` and each rule `policy[<rule name>]`,
    so every rule is read from its own path -- its own action, logging and
    addresses -- across any number of zone pairs, in the device's order."""
    if not hasattr(cfg, "iter_paths"):
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

    # --------------------------------------------------- zone pairs and rules
    order = 0
    for (pair_key,) in _in_order(_PAIR_KEYED, cfg):
        pair = f"{_POLICIES}/policy[{pair_key}]"
        from_zone = (cfg.get(f"{pair}/from-zone-name") or ("",))[0]
        to_zone = (cfg.get(f"{pair}/to-zone-name") or ("",))[0]
        for zone, leaf in ((from_zone, "from-zone-name"), (to_zone, "to-zone-name")):
            if zone and g.lookup(zone) is None:
                hit = cfg.get(f"{pair}/{leaf}")
                g.add(Node(id=zone, kind=NodeKind.ZONE, name=zone,
                           evidence=[cfg.evidence(hit[1], hit[2])] if hit else []))
            if zone and zone.lower() in UNTRUSTED:
                g.untrusted_zones.add(zone)

        rules = [k for k in _in_order(_RULE_KEYED, cfg) if k[0] == pair_key]
        for _pk, rule_key in rules:
            rule = f"{pair}/policy[{rule_key}]"
            hit = cfg.get(f"{rule}/name")
            name = hit[0] if hit else unquote(rule_key)
            ev = [cfg.evidence(hit[1], hit[2])] if hit else []

            # `then` carries the action as an EMPTY element -- <permit/> -- so
            # its presence is the value. Junos requires an explicit action, so
            # a rule with neither is one we misread; it is treated as deny.
            permit = cfg.get(f"{rule}/then/permit")
            action = "allow" if permit is not None else "deny"
            logged = (cfg.get(f"{rule}/then/log/session-close") is not None
                      or cfg.get(f"{rule}/then/log/session-init") is not None)
            order += 1
            g.add_rule(SecurityRule(
                id=f"{from_zone}->{to_zone}:{name}",
                name=name,
                order=order,
                enabled=True,
                action=action,
                source=_values(cfg, f"{rule}/match/source-address") or ["any"],
                destination=_values(cfg, f"{rule}/match/destination-address") or ["any"],
                services=_values(cfg, f"{rule}/match/application") or ["any"],
                source_zones=[from_zone] if from_zone else [],
                destination_zones=[to_zone] if to_zone else [],
                logging=logged or None,
                # A configuration export carries no counters. None, never 0:
                # zero would make every policy look dead and turn a healthy
                # rulebase into deletion candidates.
                hit_count=None,
                evidence=ev,
            ))

    # ---------------------------------------------------------- address book
    for path in cfg.iter_paths():
        if "/address-book" not in path:
            continue
        m = _ADDR_KEYED.search(path)
        if not m:
            continue
        hit = cfg.get(path)
        addr = unquote(m.group(1))
        if hit and addr and g.lookup(addr) is None:
            g.add(Node(id=addr, kind=NodeKind.ADDRESS, name=addr,
                       values=[hit[0]],
                       evidence=[cfg.evidence(hit[1], hit[2])]))

    _predefined(g, cfg)
    return g
