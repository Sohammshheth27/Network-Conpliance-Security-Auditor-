"""Build an ObjectGraph from `aws ec2 describe-security-groups` output.

Vendor adapter, doc section 3: AWS-specific in, vendor-neutral graph out. Once
a security-group rule is a SecurityRule, rule hygiene and reachability work on
a VPC exactly as they do on an NSA 3700 -- no cloud-specific analysis code.

FOUR SECURITY-GROUP SEMANTICS THAT AN APPLIANCE-SHAPED READING GETS WRONG
------------------------------------------------------------------------
1. THERE IS NO EVALUATION ORDER, AND NO DENY RULE.
   A security group is a set of ALLOW rules that union together. Nothing can
   deny, and no rule can shadow another -- position is meaningless. The graph
   is marked `unordered` so shadow analysis does not run, exactly as it is for
   Windows Firewall: a "shadowed rule" finding here would describe semantics
   the platform does not have.

2. THE GROUP IS THE POLICY ATTACHMENT POINT, NOT A DEVICE.
   Rules attach to a group, and instances join groups. The group is therefore
   modelled as a ZONE, and each rule is scoped to it -- so "can the internet
   reach db-tier-sg on 5432" is a question the resolver can answer.

3. A RULE MAY REFERENCE ANOTHER GROUP INSTEAD OF A CIDR.
   `UserIdGroupPairs` means "whatever instances are in that group right now".
   That membership lives in the EC2 API, not in this file, so the referenced
   group is recorded with `members_unknown` -- which the resolver reports as
   UNSUPPORTED. An empty group would instead read as "matches nothing" and
   silently turn a live database path into a clean result.

4. DIRECTION DECIDES WHICH SIDE THE REMOTE ADDRESS GOES ON.
   For ingress the CIDR is the SOURCE and the group is the destination; for
   egress it is reversed. Writing both the same way makes an outbound rule look
   like an inbound exposure, which is the difference between "this database may
   call out to 443" and "the internet may reach this database".

KNOWN LIMIT: TWO-ENDED EVALUATION IS NOT MODELLED
-------------------------------------------------
Group-to-group traffic in a VPC must satisfy BOTH the source group's egress
rules and the destination group's ingress rules. The reachability engine walks
one flat rule list and stops at the first match, so for a group-to-group
question it can answer PERMITTED on the strength of the egress side alone.

That answer is NECESSARY but not SUFFICIENT: the traffic is permitted to leave,
and may still be dropped on arrival. Treat a group-to-group PERMITTED as "not
blocked by the source group" and check the destination group's ingress rules
before acting on it.

Questions scoped to a single group -- "what may reach web-tier-sg on 22", which
is the exposure question that matters -- are unaffected, because only that
group's ingress rules can answer them.
"""
from __future__ import annotations

from .model import Node, NodeKind, ObjectGraph, SecurityRule

#: AWS writes "-1" for "every protocol", and omits the port range with it.
ALL_PROTOCOLS = "-1"

#: A group open to this is open to the internet.
ANY_V4 = "0.0.0.0/0"
ANY_V6 = "::/0"


def _service(permission: dict) -> list[str]:
    """The protocol/port set a permission covers, in graph terms.

    `IpProtocol: "-1"` carries no FromPort/ToPort because it means everything.
    Rendering that as a port range would invent a bound the rule does not have.
    """
    proto = str(permission.get("IpProtocol", "")).strip()
    if proto in (ALL_PROTOCOLS, "", "all"):
        return ["any"]

    lo, hi = permission.get("FromPort"), permission.get("ToPort")
    if lo is None and hi is None:
        # A named protocol with no ports -- icmp, esp, gre. It constrains the
        # protocol and nothing else.
        return [proto.lower()]
    if lo == hi:
        return [f"{proto.lower()}/{lo}"]
    return [f"{proto.lower()}/{lo}-{hi}"]


def _remotes(permission: dict, graph: ObjectGraph, evidence) -> list[str]:
    """Everything on the far side of this permission.

    CIDRs are literals the resolver understands directly. A group reference is
    a name, and the group it names becomes a node so the reference resolves to
    something rather than dangling.
    """
    out: list[str] = []

    for r in permission.get("IpRanges") or []:
        if r.get("CidrIp"):
            out.append(r["CidrIp"])
    for r in permission.get("Ipv6Ranges") or []:
        if r.get("CidrIpv6"):
            out.append(r["CidrIpv6"])

    for pair in permission.get("UserIdGroupPairs") or []:
        gid = pair.get("GroupId")
        if not gid:
            continue
        out.append(gid)
        if graph.lookup(gid) is None:
            # Membership is runtime state held by the EC2 API, not by this
            # file. Marked unknown rather than empty -- see the module note.
            graph.add(Node(
                id=gid, kind=NodeKind.ADDRESS_GROUP, name=gid,
                attrs={"members_unknown": True,
                       "detail": "security-group reference; its member "
                                 "instances are runtime state, not present "
                                 "in this export"},
                evidence=list(evidence)))

    for p in permission.get("PrefixListIds") or []:
        pl = p.get("PrefixListId")
        if not pl:
            continue
        out.append(pl)
        if graph.lookup(pl) is None:
            graph.add(Node(
                id=pl, kind=NodeKind.ADDRESS_GROUP, name=pl,
                attrs={"members_unknown": True,
                       "detail": "managed prefix list; its entries are not "
                                 "present in this export"},
                evidence=list(evidence)))

    # A permission with no remote at all matches nothing. Returning ["any"]
    # here would convert an inert rule into a wide-open one.
    return out


def build(doc) -> ObjectGraph:
    """`doc` is a JsonDocument over describe-security-groups output."""
    g = ObjectGraph()

    data = getattr(doc, "data", doc)
    groups = data if isinstance(data, list) else (
        data.get("SecurityGroups") or [] if isinstance(data, dict) else [])

    order = 0
    for sg in groups:
        gid = sg.get("GroupId") or sg.get("GroupName")
        if not gid:
            continue
        name = sg.get("GroupName") or gid
        path = f"$.SecurityGroups[?GroupId='{gid}']"
        ev = [doc.evidence(path, {"GroupId": gid, "GroupName": name})]

        # The group is the attachment point policy is written against.
        node = g.lookup(gid)
        if node is None:
            node = Node(
                id=gid, kind=NodeKind.ZONE, name=gid,
                # The group resolves to its own IDENTIFIER, not to a CIDR.
                #
                # Its instance addresses are runtime state held by the EC2 API,
                # so there is no address here to give. Leaving `values` empty
                # instead makes the resolver report the group as unevaluable --
                # correct in the abstract, but it renders every rule in the VPC
                # unanswerable, which is a useless kind of honesty.
                #
                # Resolving to the id means "can X reach sg-...0002 on 22" is
                # answerable, while "can 10.0.5.9 reach it" correctly does NOT
                # match by address -- because we genuinely do not know which
                # addresses are in the group.
                values=[gid],
                attrs={"group_name": name,
                       "vpc": sg.get("VpcId") or "",
                       "description": sg.get("Description") or "",
                       "value_is_identifier": True,
                       "detail": "resolves to the group id; member instance "
                                 "addresses are runtime state and are not in "
                                 "this export"},
                evidence=ev)
            g.add(node)

        for direction, key in (("ingress", "IpPermissions"),
                               ("egress", "IpPermissionsEgress")):
            for i, perm in enumerate(sg.get(key) or []):
                order += 1
                ppath = f"$.SecurityGroups[?GroupId='{gid}'].{key}[{i}]"
                pev = [doc.evidence(ppath, perm)]
                remotes = _remotes(perm, g, pev)
                services = _service(perm)

                # The LOCAL side is the GROUP, named. Not "any": the instances
                # in a group are a bounded set, and writing "any" there made
                # the hygiene analyser read every ordinary ingress rule as
                # permitting any destination -- seven fabricated
                # "overly permissive" findings on a three-group VPC, including
                # one on a rule that only opens 443.
                if direction == "ingress":
                    source, destination = remotes, [gid]
                else:
                    source, destination = [gid], remotes

                g.add_rule(SecurityRule(
                    id=f"{gid}:{key}[{i}]",
                    name=f"{name} {direction} {'/'.join(services)}",
                    # Position is recorded so findings have a stable handle,
                    # but it carries NO evaluation meaning here -- see
                    # `unordered` below.
                    order=order,
                    enabled=True,          # a present rule is in force
                    action="allow",        # security groups cannot deny
                    source=source,
                    destination=destination,
                    services=services,
                    source_zones=[gid] if direction == "egress" else [],
                    destination_zones=[gid] if direction == "ingress" else [],
                    # There is no per-rule counter in this API response. None,
                    # never 0: zero would make every rule look dead and turn
                    # the whole VPC into deletion candidates.
                    hit_count=None,
                    # Flow logs are a separate VPC resource; this export says
                    # nothing about whether the rule is logged.
                    logging=None,
                    evidence=pev,
                ))

        if name.lower() in ("default",):
            g.untrusted_zones.add(gid)

    # No ordering, so no shadowing. Marking this is what stops the hygiene
    # analyser inventing findings from positions that do not exist.
    g.unordered = True

    # Default-deny is OBSERVED here, and this is the one platform where that
    # claim is safe to make without reading it from the file.
    #
    # Elsewhere the default policy is configurable -- `set security policies
    # default-policy permit-all` is a real Junos command -- so assuming deny
    # would report a permit-all device as compliant, and every other builder
    # therefore leaves `observed` False. A security group cannot be configured
    # that way: it holds allow rules only, there is no deny form, and anything
    # unmatched is dropped. That is an invariant of the service, not a setting.
    #
    # Marking it observed is what turns "we cannot say" into "DENIED" for
    # traffic no rule permits -- which is the answer, and the useful one.
    g.default_action = "deny"
    g.default_action_observed = True
    return g
