"""Build an ObjectGraph from a parsed PAN-OS running-config.

Vendor adapter, doc section 3: PAN-OS-specific in, vendor-neutral graph out.
The resolver, the facts and the controls never learn PAN-OS naming.

Validated against a genuine running-config.xml export rather than a fixture
written alongside this file.

FOUR PAN-OS SEMANTICS THAT A PORT-ORIENTED READING GETS WRONG
------------------------------------------------------------
These are not edge cases. Every one of them appears in the real export, and
each would turn a correct policy into a fabricated finding, or the reverse.

1. APP-ID IS THE PRIMARY MATCH CRITERION, NOT THE PORT.
   A rule carrying "application: 4shared" does not permit a port -- it permits
   an application, wherever App-ID finds it. Whether that application uses the
   port a caller asks about is decided by Palo Alto's application database,
   which we do not hold. Reading only the service field would report such a
   rule as permitting tcp/55 outright, discarding the constraint that is doing
   the actual security work.

   These rules are marked with the model's existing `program` field. The
   concept is already there for host firewalls, where a rule is scoped to a
   BINARY rather than a port, and the consequence is identical: a port
   question cannot be decided by this rule alone. Reachability skips it and
   discloses it as unevaluable instead of guessing.

   The effect on a real firewall is large, because most production rules
   specify applications. That is the honest result. The alternative is a
   confident PERMITTED derived from a field that does not decide the matter.

2. "application-default" IS NOT "any".
   It means "whatever ports App-ID considers standard for the matched
   application" -- again the database we do not have. The danger is not
   leaving it unresolved; it is treating an unrecognised service token as
   unconstrained, which reads a tightly scoped rule as wide open.

3. NEGATION INVERTS THE MATCH.
   negate-source: yes means the rule matches everything EXCEPT the listed
   addresses. The vendor-neutral SecurityRule has no negation, so a negated
   rule read literally means the precise opposite of what the device does. It
   is marked unevaluable rather than mis-modelled.

4. THE IMPLICIT RULES ARE REAL POLICY.
   Every PAN-OS firewall ends with intrazone-default (allow) and
   interzone-default (deny), which do not appear in the rulebase unless an
   administrator overrides them. default_action is set to deny for the
   interzone case, and default_action_observed stays False, because we know it
   from the platform rather than read it from this file.

ORDER
-----
PAN-OS is first-match-wins in document order. Where a config carries Panorama
pre- and post-rulebases the true order is pre-rules, then local rules, then
post-rules, and that is the order assembled here. A local rule evaluated ahead
of a Panorama pre-rule would be a fabricated shadow finding.
"""
from __future__ import annotations

import re

from ..readers.xml_reader import XmlConfig
from .model import Node, NodeKind, ObjectGraph, SecurityRule


def _unesc(name: str) -> str:
    """Undo the XML reader's escaping of "/" inside an entry name.

    The reader writes ethernet1/1 as ethernet1%2F1 so that a name containing a
    slash cannot be mistaken for two path segments. Rule members carry the raw
    name, so the escaping has to come off before anything is matched by name.
    """
    return name.replace("%2F", "/").replace("%25", "%")


#: Only the SECURITY rulebase is policy. The nat, pbf, qos, captive-portal,
#: dos and application-override rulebases live at sibling paths and describe
#: different decisions entirely; counting a NAT rule as a security rule would
#: report address translation as permitted traffic.
_SECURITY_RULE = re.compile(
    r"^(?P<base>.*?)/(?P<book>rulebase|pre-rulebase|post-rulebase)"
    r"/security/rules/entry\[(?P<name>[^\]]*)\]/(?P<leaf>.+)$")

_ADDRESS = re.compile(r"^(?P<base>.*?)/address/entry\[(?P<name>[^\]]*)\]/(?P<leaf>.+)$")
_ADDR_GROUP = re.compile(
    r"^(?P<base>.*?)/address-group/entry\[(?P<name>[^\]]*)\]/(?P<leaf>.+)$")
_SERVICE = re.compile(r"^(?P<base>.*?)/service/entry\[(?P<name>[^\]]*)\]/(?P<leaf>.+)$")
_SVC_GROUP = re.compile(
    r"^(?P<base>.*?)/service-group/entry\[(?P<name>[^\]]*)\]/(?P<leaf>.+)$")
_ZONE = re.compile(r"^(?P<base>.*?)/zone/entry\[(?P<name>[^\]]*)\]/(?P<leaf>.+)$")
_SVC_PORT = re.compile(r"^protocol/(tcp|udp|sctp)/port$")
_ZONE_IF = re.compile(r"^network/(?:layer3|layer2|virtual-wire|tap)/member$")

#: Documented address forms. ip-netmask is the common one; the others are not
#: exotic, and an address object parsed to NO values is reported by the
#: resolver as UNRESOLVED -- an unreadable config rather than a readable one.
_ADDR_FORMS = ("ip-netmask", "ip-range", "fqdn", "ip-wildcard")

UNTRUSTED = {"untrust", "untrusted", "internet", "wan", "outside", "public",
             "external"}

#: PAN-OS writes the literal string "any" in a member list to mean
#: unconstrained. It is a token, not an object name, and must not be looked up.
ANY = "any"

#: Service token meaning "the ports App-ID considers default for the matched
#: application". Not resolvable without Palo Alto's application database.
APP_DEFAULT = "application-default"


def _members(cfg: XmlConfig, path: str) -> list[str]:
    """Every value at a repeated path.

    PAN-OS writes list membership as sibling <member> elements sharing one
    path. Reading only the first would silently drop every address in a group
    after the first, shrinking a rule's scope without saying so.
    """
    return [v for v, _ln, _raw in cfg.get_all(path)]


def _ports(spec: str) -> list[str]:
    """PAN-OS port specs: 55, or 389,646, or 8000-8080, or a mix."""
    return [p.strip() for p in str(spec or "").split(",") if p.strip()]


def _addresses(cfg: XmlConfig, g: ObjectGraph) -> None:
    for path in cfg.paths:
        m = _ADDRESS.match(path)
        # region/entry[x]/address/member also contains "/address/" but defines
        # a region, not an address object. Requiring both the entry[...] form
        # and a known address leaf excludes it.
        if not m or m.group("leaf") not in _ADDR_FORMS:
            continue
        hit = cfg.get(path)
        if not hit:
            continue
        val, ln, raw = hit
        name = _unesc(m.group("name"))
        node = g.lookup(name)
        if node is None:
            node = Node(id=name, kind=NodeKind.ADDRESS, name=name,
                        evidence=[cfg.evidence(ln, raw)])
            g.add(node)
        node.values = [val]
        node.attrs["form"] = m.group("leaf")


def _address_groups(cfg: XmlConfig, g: ObjectGraph) -> None:
    for path in cfg.paths:
        m = _ADDR_GROUP.match(path)
        if not m:
            continue
        name, leaf = _unesc(m.group("name")), m.group("leaf")
        node = g.lookup(name)
        if node is None:
            hit = cfg.get(path)
            node = Node(id=name, kind=NodeKind.ADDRESS_GROUP, name=name,
                        evidence=[cfg.evidence(hit[1], hit[2])] if hit else [])
            g.add(node)
        node.kind = NodeKind.ADDRESS_GROUP
        if leaf in ("member", "static/member"):
            for v in _members(cfg, path):
                if v and v not in node.members:
                    node.members.append(v)
        elif leaf.startswith("dynamic"):
            # A dynamic group's membership is decided at runtime by tag match,
            # not by the configuration, so it is genuinely unknowable from a
            # config file. Marked rather than left empty: an empty group reads
            # as "matches nothing", which would make a live rule look inert.
            node.attrs["members_unknown"] = True
            node.attrs["dynamic_filter"] = (cfg.get(path) or ("",))[0]


def _services(cfg: XmlConfig, g: ObjectGraph) -> None:
    for path in cfg.paths:
        m = _SERVICE.match(path)
        if not m:
            continue
        pm = _SVC_PORT.match(m.group("leaf"))
        if not pm:
            continue                    # description, override, source-port
        hit = cfg.get(path)
        if not hit:
            continue
        val, ln, raw = hit
        name = _unesc(m.group("name"))
        node = g.lookup(name)
        if node is None:
            node = Node(id=name, kind=NodeKind.SERVICE, name=name,
                        evidence=[cfg.evidence(ln, raw)])
            g.add(node)
        # source-port is deliberately not read: it constrains the CLIENT port,
        # and folding it into the destination service would answer a
        # destination-port question with the wrong number.
        for p in _ports(val):
            v = f"{pm.group(1)}/{p}"
            if v not in node.values:
                node.values.append(v)


def _service_groups(cfg: XmlConfig, g: ObjectGraph) -> None:
    for path in cfg.paths:
        m = _SVC_GROUP.match(path)
        if not m or not m.group("leaf").endswith("member"):
            continue
        name = _unesc(m.group("name"))
        node = g.lookup(name)
        if node is None:
            hit = cfg.get(path)
            node = Node(id=name, kind=NodeKind.SERVICE_GROUP, name=name,
                        evidence=[cfg.evidence(hit[1], hit[2])] if hit else [])
            g.add(node)
        node.kind = NodeKind.SERVICE_GROUP
        for v in _members(cfg, path):
            if v and v not in node.members:
                node.members.append(v)


def _zones(cfg: XmlConfig, g: ObjectGraph) -> None:
    for path in cfg.paths:
        m = _ZONE.match(path)
        if not m:
            continue
        zone, leaf = _unesc(m.group("name")), m.group("leaf")
        node = g.lookup(zone)
        if node is None:
            hit = cfg.get(path)
            node = Node(id=zone, kind=NodeKind.ZONE, name=zone,
                        evidence=[cfg.evidence(hit[1], hit[2])] if hit else [])
            g.add(node)
        if zone.lower() in UNTRUSTED:
            g.untrusted_zones.add(zone)
        if _ZONE_IF.match(leaf):
            for iface in _members(cfg, path):
                if not iface:
                    continue
                g.zones_of_interface[iface] = zone
                if iface not in node.members:
                    node.members.append(iface)


#: Panorama pushes pre-rules that evaluate BEFORE local rules and post-rules
#: that evaluate after. Assembling by document order alone would place a local
#: rule ahead of a pre-rule and invent shadowing the device does not have.
_BOOK_ORDER = {"pre-rulebase": 0, "rulebase": 1, "post-rulebase": 2}


def _rules(cfg: XmlConfig, g: ObjectGraph) -> None:
    specs: dict[str, dict] = {}
    seq: list[str] = []
    for path in cfg.paths:
        m = _SECURITY_RULE.match(path)
        if not m:
            continue
        key = f"{m.group('base')}|{m.group('book')}|{m.group('name')}"
        if key not in specs:
            specs[key] = {"book": m.group("book"),
                          "name": _unesc(m.group("name")), "leaves": {}}
            seq.append(key)
        specs[key]["leaves"][m.group("leaf")] = path

    order_of = {k: i for i, k in enumerate(seq)}
    ordered = sorted(seq, key=lambda k: (_BOOK_ORDER.get(specs[k]["book"], 1),
                                         order_of[k]))

    for position, key in enumerate(ordered, start=1):
        spec = specs[key]
        leaves = spec["leaves"]

        def one(leaf: str, default: str = "", _lv=leaves) -> str:
            hit = cfg.get(_lv[leaf]) if leaf in _lv else None
            return hit[0] if hit else default

        def many(leaf: str, _lv=leaves) -> list[str]:
            return _members(cfg, _lv[leaf]) if leaf in _lv else []

        services = many("service/member") or [ANY]
        applications = [a for a in many("application/member") if a and a != ANY]

        ev_path = leaves.get("action") or next(iter(leaves.values()), None)
        ev_hit = cfg.get(ev_path) if ev_path else None

        rule = SecurityRule(
            id=f"{spec['book']}:{spec['name']}",
            name=f"{spec['name']} [{spec['book']}#{position}]",
            order=position,
            # PAN-OS omits <disabled> on an enabled rule, so absence means
            # ENABLED -- the opposite of SonicOS, where an absent flag means
            # off. Carrying that assumption across vendors would disable a
            # live rulebase and report a permissive firewall as harmless.
            enabled=one("disabled", "no").strip().lower() != "yes",
            action=("allow" if one("action").strip().lower() in ("allow", "permit")
                    else "deny"),
            source=many("source/member") or [ANY],
            destination=many("destination/member") or [ANY],
            services=services,
            source_zones=[z for z in many("from/member") if z and z != ANY],
            destination_zones=[z for z in many("to/member") if z and z != ANY],
            # log-end records the session and its outcome. log-start alone
            # records only the SYN, which is not logging in the sense the
            # control asks about, so it does not count here.
            logging=(one("log-end", "").strip().lower() == "yes") or None,
            # A running-config carries no per-rule counter. None, never 0:
            # zero would make every rule look dead and turn an entire healthy
            # rulebase into deletion candidates.
            hit_count=None,
            evidence=[cfg.evidence(ev_hit[1], ev_hit[2])] if ev_hit else [],
        )

        # App-ID, negation and application-default all mean the same thing to
        # a port question: this rule cannot decide it. `program` is the model's
        # existing word for exactly that, so reachability already skips the
        # rule and discloses it rather than guessing.
        undecidable = []
        if applications:
            undecidable.append("app-id:" + ",".join(applications[:6]))
        if one("negate-source", "no").strip().lower() == "yes":
            undecidable.append("negate-source")
        if one("negate-destination", "no").strip().lower() == "yes":
            undecidable.append("negate-destination")
        if APP_DEFAULT in services:
            undecidable.append(APP_DEFAULT)
        if undecidable:
            rule.program = "; ".join(undecidable)

        g.add_rule(rule)


#: PAN-OS ships exactly two predefined SERVICE objects. They are not written
#: into the configuration, so a rule referencing service-https would otherwise
#: resolve to nothing and become unevaluable -- and most real rules reference
#: them. Their ports are fixed by the platform and documented by the vendor.
#:
#: They are added only when a rule actually references one, and never over a
#: same-named object defined in the config: an administrator may redefine
#: these, and the device's own definition wins.
PREDEFINED_SERVICES = {
    "service-http": ["tcp/80", "tcp/8080"],
    "service-https": ["tcp/443"],
}


def _predefined(g: ObjectGraph) -> None:
    # Group members count as references: a service group listing service-https
    # is a common way a rule reaches a predefined service, and looking only at
    # rules would leave the group's members unresolved.
    referenced = {s for r in g.rules for s in r.services}
    referenced |= {m for n in g.nodes.values()
                   if n.kind is NodeKind.SERVICE_GROUP for m in n.members}
    for name, values in PREDEFINED_SERVICES.items():
        if name not in referenced or g.lookup(name) is not None:
            continue
        # Evidence is the rule that referenced it. The value did NOT come from
        # this file, and attrs says so, so a reader can tell a platform
        # constant from something we actually read off the device.
        ev = next((r.evidence for r in g.rules
                   if name in r.services and r.evidence), [])
        g.add(Node(id=name, kind=NodeKind.SERVICE, name=name, values=list(values),
                   attrs={"predefined": True,
                          "provenance": "PAN-OS platform default, not read "
                                        "from this configuration"},
                   evidence=list(ev)))


def build(cfg: XmlConfig) -> ObjectGraph:
    g = ObjectGraph()
    _addresses(cfg, g)
    _address_groups(cfg, g)
    _services(cfg, g)
    _service_groups(cfg, g)
    _zones(cfg, g)
    _rules(cfg, g)
    _predefined(g)

    # An interzone session matching no rule is dropped by the implicit
    # interzone-default rule. That is a platform property we know rather than
    # something this file states, so `observed` stays False and a reader can
    # tell our assumption from our reading.
    g.default_action = "deny"
    g.default_action_observed = False
    return g
