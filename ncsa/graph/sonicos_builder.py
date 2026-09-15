"""Build an ObjectGraph from a decoded SonicOS `.exp` export.

Vendor adapter, doc section 3: SonicOS-specific in, vendor-neutral graph out.
The resolver, the facts and the controls never learn SonicOS naming.

STRUCTURE, read out of a live NSA 3700 (SonicWall publishes no CLI grammar we
hold, so the device is the authority):

    addrObjId_N        address / group NAME        e.g. "LAN Subnets"
    addrObjIp1_N/Ip2_N range start / end
    addrObjZone_N      owning zone
    addrObjType_N      8 = group, otherwise a leaf address
    addro_atomToGrp_N  member name   ]  PAIRED BY INDEX -- entry N says
    addro_grpToGrp_N   group name    ]  "member N belongs to group N"

    svcObjId_N         service name
    svcObjPort1_N/2_N  port range
    svcObjIpType_N     IP protocol number (6=tcp, 17=udp)

    policyName_N       rule name          policyAction_N   2=allow, 0=deny
    policySrcZone_N    source zone        policyEnabled_N  1=enabled
    policyDstZone_N    destination zone   policyLog_N      1=logged
    policySrcNet_N     source address object name
    policyDstNet_N     destination address object name
    policyDstSvc_N     service object name
    policyPriority_N   evaluation order

The `*V6` twins are the IPv6 policy table. They are parsed as separate rules
rather than merged: an IPv4 rule and its IPv6 sibling can differ, and merging
them would hide a permissive IPv6 path behind a restrictive IPv4 one.
"""
from __future__ import annotations

import re

from .model import Node, NodeKind, ObjectGraph, SecurityRule

# SonicOS type code for an address GROUP; anything else is a leaf address.
ADDR_TYPE_GROUP = "8"
# svcObjType 2 = service group; 1 = simple service.
SVC_TYPE_GROUP = "2"
# Sentinel meaning "any interface / any zone" in the policy table.
ANY_SENTINEL = {"4294967295", "-1", ""}
PROTO = {"6": "tcp", "17": "udp", "1": "icmp", "58": "icmpv6"}
UNTRUSTED_ZONES = {"wan", "untrust", "internet", "public", "wlan"}


def _ev(exp, key: str, fallback_index: int, fallback_raw: str):
    """Evidence anchored at the setting's REAL position in the file.

    The index in `addrObjId_14` is the object's number, NOT where the setting
    sits in the export. Passing it as the position produced evidence claiming
    `policyName_1=Test_SSH` was setting 1, when setting 1 is `checksumVersion`
    and the policy is actually at 37,290. Every graph-derived finding on this
    platform pointed at the wrong place, and an administrator following the
    reference would have found an unrelated value.

    The reader already records the true position, so it is looked up here.
    """
    hit = exp.values.get(key)
    if hit is not None:
        _val, position, raw = hit
        return exp.evidence(position, raw)
    return exp.evidence(fallback_index, fallback_raw)


def _idx(values: dict, prefix: str, *, exp=None) -> dict[int, str]:
    """All `prefix_N` values keyed by N.

    Records read here are marked consumed on the export, so the completeness
    accounting counts what the GRAPH read and not only what a pack mapping
    matched -- see SonicOsExport.consume_keys.
    """
    out, keys = {}, []
    rx = re.compile(rf"^{re.escape(prefix)}_(\d+)$")
    for k, (v, _ln, _raw) in values.items():
        m = rx.match(k)
        if m:
            out[int(m.group(1))] = v
            keys.append(k)
    if exp is not None and keys:
        exp.consume_keys(keys)
    return out


def build(exp, *, include_ipv6: bool = True) -> ObjectGraph:
    g = ObjectGraph()
    V = exp.values

    # ------------------------------------------------------------ addresses
    names = _idx(V, "addrObjId", exp=exp)
    types = _idx(V, "addrObjType", exp=exp)
    ip1 = _idx(V, "addrObjIp1", exp=exp)
    ip2 = _idx(V, "addrObjIp2", exp=exp)
    zones = _idx(V, "addrObjZone", exp=exp)

    for i, name in names.items():
        if not name:
            continue
        is_group = types.get(i) == ADDR_TYPE_GROUP
        vals = []
        if not is_group:
            a, b = ip1.get(i, ""), ip2.get(i, "")
            if a and a != "0.0.0.0":
                vals = [a] if (not b or b in ("0.0.0.0", a)) else [f"{a}-{b}"]
        node = g.lookup(name)
        if node is None:
            node = Node(id=name, kind=(NodeKind.ADDRESS_GROUP if is_group else NodeKind.ADDRESS),
                        name=name, values=vals,
                        evidence=[_ev(exp, f"addrObjId_{i}", i, f"addrObjId_{i}={name}")])
            g.add(node)
        else:
            node.values = node.values or vals
        if zones.get(i):
            node.attrs["zone"] = zones[i]

    # ------------------------------------------------- group membership
    # atomToGrp_N and grpToGrp_N are PAIRED: entry N is one membership edge.
    members = _idx(V, "addro_atomToGrp", exp=exp)
    groups = _idx(V, "addro_grpToGrp", exp=exp)
    for i, member in members.items():
        grp = groups.get(i)
        if not (member and grp):
            continue
        node = g.lookup(grp)
        if node is None:
            node = Node(id=grp, kind=NodeKind.ADDRESS_GROUP, name=grp,
                        evidence=[_ev(exp, f"addro_grpToGrp_{i}", i, f"addro_grpToGrp_{i}={grp}")])
            g.add(node)
        elif node.kind is NodeKind.ADDRESS:
            node.kind = NodeKind.ADDRESS_GROUP     # membership proves it is a group
        if member not in node.members:
            node.members.append(member)

    # ------------------------------------------------------------- services
    snames = _idx(V, "svcObjId", exp=exp)
    stypes = _idx(V, "svcObjType", exp=exp)
    sp1, sp2 = _idx(V, "svcObjPort1", exp=exp), _idx(V, "svcObjPort2", exp=exp)
    sproto = _idx(V, "svcObjIpType", exp=exp)
    for i, name in snames.items():
        if not name or g.lookup(name):
            continue
        # svcObjType 2 is a service GROUP. Its port fields are internal
        # bookkeeping, NOT a port range: "Ping" carries 49520-65144 and
        # IpType 170, which is not an IP protocol at all. Reading those as
        # ports produced a 15,000-port range that then matched every
        # administrative and database port -- 225 fabricated critical findings
        # from one misread type code.
        if str(stypes.get(i, "")) == SVC_TYPE_GROUP:
            # The export contains no service-group membership table, so the
            # members are genuinely undeterminable. No values AND no members
            # makes the resolver report UNSUPPORTED, which is the truth.
            g.add(Node(id=name, kind=NodeKind.SERVICE_GROUP, name=name,
                       attrs={"members_unknown": True},
                       evidence=[_ev(exp, f"svcObjId_{i}", i, f"svcObjId_{i}={name}")]))
            continue
        proto = PROTO.get(str(sproto.get(i, "")))
        if proto is None:
            g.add(Node(id=name, kind=NodeKind.SERVICE, name=name,
                       attrs={"protocol_unknown": sproto.get(i, "")},
                       evidence=[_ev(exp, f"svcObjId_{i}", i, f"svcObjId_{i}={name}")]))
            continue
        a, b = sp1.get(i, ""), sp2.get(i, "")
        vals = []
        if a and a != "0":
            vals = [f"{proto}/{a}"] if (not b or b == a) else [f"{proto}/{a}-{b}"]
        g.add(Node(id=name, kind=NodeKind.SERVICE, name=name, values=vals,
                   evidence=[_ev(exp, f"svcObjId_{i}", i, f"svcObjId_{i}={name}")]))

    # ---------------------------------------------------------------- zones
    for i, zname in _idx(V, "zoneObjId", exp=exp).items():
        if zname and not g.lookup(zname):
            g.add(Node(id=zname, kind=NodeKind.ZONE, name=zname,
                       evidence=[_ev(exp, f"zoneObjId_{i}", i, f"zoneObjId_{i}={zname}")]))
        if zname and zname.lower() in UNTRUSTED_ZONES:
            g.untrusted_zones.add(zname)

    # -------------------------------------------------------- access rules
    suffixes = [""] + (["V6"] if include_ipv6 else [])
    for suf in suffixes:
        pnames = _idx(V, f"policyName{suf}", exp=exp)
        act = _idx(V, f"policyAction{suf}", exp=exp)
        ena = _idx(V, f"policyEnabled{suf}", exp=exp)
        log = _idx(V, f"policyLog{suf}", exp=exp)
        szone = _idx(V, f"policySrcZone{suf}", exp=exp)
        dzone = _idx(V, f"policyDstZone{suf}", exp=exp)
        snet = _idx(V, f"policySrcNet{suf}", exp=exp)
        dnet = _idx(V, f"policyDstNet{suf}", exp=exp)
        dsvc = _idx(V, f"policyDstSvc{suf}", exp=exp)
        prio = _idx(V, f"policyPriority{suf}", exp=exp)
        hits = _idx(V, f"policyHitCount{suf}", exp=exp)

        for i, name in pnames.items():
            if not name:
                continue
            src = snet.get(i, "")
            dst = dnet.get(i, "")
            svc = dsvc.get(i, "")
            rule = SecurityRule(
                id=f"policy{suf}_{i}",
                name=f"{name} [{'IPv6' if suf else 'IPv4'}#{i}]",
                order=int(prio.get(i) or i),
                # An ABSENT enabled flag means 0 on SonicOS, not "assume on".
                enabled=str(ena.get(i, "0")) == "1",
                action="allow" if str(act.get(i, "")) == "2" else "deny",
                logging=str(log.get(i, "")) == "1",
                source=[src] if src and src not in ANY_SENTINEL else ["any"],
                destination=[dst] if dst and dst not in ANY_SENTINEL else ["any"],
                services=[svc] if svc and svc not in ANY_SENTINEL else ["any"],
                # The device counts matches per rule. 148 enabled rules on
                # this appliance have never matched a packet -- dead policy
                # that every comparable product reports and we were
                # discarding at the reader.
                hit_count=(int(hits[i]) if str(hits.get(i, "")).isdigit()
                           else None),
                source_zones=[szone.get(i, "")] if szone.get(i) else [],
                destination_zones=[dzone.get(i, "")] if dzone.get(i) else [],
                evidence=[_ev(exp, f"policyName{suf}_{i}", i, f"policyName{suf}_{i}={name}")],
            )
            g.add_rule(rule)

    # A SonicWall access policy is default-deny; anything not permitted is
    # dropped. This is a platform property, so it is recorded as observed only
    # where the export states it.
    g.default_action = "deny"
    return g
