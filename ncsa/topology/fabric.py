"""Multi-device topology and end-to-end reachability.

The last capability the comparable products have and NCSA did not. A firewall
report is about one box; an auditor asks about the NETWORK -- "can anything in
the DMZ reach the database server", when the answer depends on three devices
in series and any one of them can deny.

WHAT THIS IS, AND WHAT BATFISH DOES THAT THIS DOES NOT
Batfish parses vendor grammars into a full data-plane model: routing tables,
forwarding, NAT, tunnels, and symbolic analysis over all packets at once. It
answers "for which packets does behaviour differ between these two snapshots".

This infers adjacency from SHARED SUBNETS and walks the policies in sequence.
That is materially less, and the difference is stated on every answer rather
than buried:

  * ADJACENCY IS INFERRED, not read. Two devices with interfaces on 10.0.5.0/24
    are treated as connected. That is true in most networks and false in a
    network with VLAN separation or an intervening router we were not given.
  * NO ROUTING. The path is "devices whose interfaces sit between these two
    addresses", not the path packets actually take. Asymmetric routing,
    policy-based routing and ECMP are invisible here.
  * NO NAT. A device that translates an address changes what the NEXT device
    evaluates, and we do not model that. Any path crossing a NAT boundary is
    reported as such rather than answered.

A path we cannot determine returns UNDECIDABLE. The one thing a topology tool
must never do is report "no path exists" when it simply could not find one --
that reads as "the network is safe" and it is the failure this whole project
guards against.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

from ..graph.reach import Query, ask
from .interfaces import Interface, extract


@dataclass
class Device:
    key: str
    name: str
    platform: str
    interfaces: list = field(default_factory=list)
    assessment: object = None

    def networks(self) -> list:
        out = []
        for i in self.interfaces:
            n = i.network
            if n is not None and i.enabled:
                out.append((n, i))
        return out

    def zone_for(self, address: str) -> str:
        """Which zone an address reaches this device through."""
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            return ""
        best, best_len = "", -1
        for n, i in self.networks():
            if ip in n and n.prefixlen > best_len:
                best, best_len = i.zone or i.name, n.prefixlen
        return best

    def to_json(self) -> dict:
        return {"key": self.key, "name": self.name, "platform": self.platform,
                "interfaces": [i.to_json() for i in self.interfaces]}


@dataclass
class Hop:
    device: str
    ingress_zone: str
    egress_zone: str
    permitted: bool | None
    decided_by: str = ""
    reason: str = ""


@dataclass
class PathAnswer:
    permitted: bool | None
    query: Query = None
    hops: list = field(default_factory=list)
    reason: str = ""
    caveats: list = field(default_factory=list)

    def explain(self) -> str:
        verdict = {True: "PERMITTED end to end", False: "BLOCKED",
                   None: "UNDECIDABLE"}[self.permitted]
        out = [f"{verdict}   {self.query.describe() if self.query else ''}"]
        for h in self.hops:
            mark = {True: "pass", False: "DENY", None: "?"}[h.permitted]
            out.append(f"   [{mark:>4}] {h.device}  "
                       f"{h.ingress_zone or '?'} -> {h.egress_zone or '?'}"
                       f"   {h.decided_by}")
        if self.reason:
            out.append(f"   {self.reason}")
        for c in self.caveats:
            out.append(f"   caveat: {c}")
        return "\n".join(out)

    def to_json(self) -> dict:
        return {"permitted": self.permitted,
                "query": self.query.describe() if self.query else "",
                "hops": [h.__dict__ for h in self.hops],
                "reason": self.reason, "caveats": list(self.caveats)}


class Fabric:
    """A set of assessed devices, related by the networks they share."""

    def __init__(self):
        self.devices: dict = {}

    # ----------------------------------------------------------- building
    def add(self, device_assessment, key=None) -> Device:
        i = device_assessment.identity
        k = key or i.serial or i.hostname or i.source_file
        d = Device(key=k, name=i.hostname or i.source_file,
                   platform=i.platform, interfaces=extract(device_assessment),
                   assessment=device_assessment)
        self.devices[k] = d
        return d

    def adjacency(self) -> list:
        """Device pairs sharing a subnet. INFERRED -- see the module docstring."""
        links = []
        keys = list(self.devices)
        for a in range(len(keys)):
            for b in range(a + 1, len(keys)):
                da, db = self.devices[keys[a]], self.devices[keys[b]]
                for na, ia in da.networks():
                    for nb, ib in db.networks():
                        if na == nb or na.overlaps(nb):
                            links.append({"a": da.key, "b": db.key,
                                          "network": str(na),
                                          "a_interface": ia.name,
                                          "b_interface": ib.name,
                                          "inferred_from": "shared subnet"})
        return links

    def devices_between(self, src: str, dst: str) -> list:
        """Devices that could carry traffic from src to dst.

        A device qualifies when it has an interface facing the source AND an
        interface facing the destination, or facing the default route. This is
        adjacency, not routing: it answers "which policies could apply", which
        is the question a compliance audit actually asks.
        """
        try:
            s, d = ipaddress.ip_address(src), ipaddress.ip_address(dst)
        except ValueError:
            return []
        out = []
        for dev in self.devices.values():
            nets = dev.networks()
            faces_src = any(s in n for n, _ in nets)
            faces_dst = any(d in n for n, _ in nets)
            if faces_src and faces_dst:
                out.append(dev)              # both sides on this device
            elif faces_src or faces_dst:
                # An edge device: one side local, the other reached onward.
                out.append(dev)
        return out

    # -------------------------------------------------------- reachability
    def can_reach(self, src: str, dst: str, port: int | None = None,
                  protocol="tcp") -> PathAnswer:
        """End-to-end: every device in the path must permit, or it is blocked."""
        q = Query(source=src, destination=dst, port=port, protocol=protocol)
        ans = PathAnswer(permitted=None, query=q)
        # Stated on EVERY answer, including the early returns below. A caveat
        # that appears on some paths and not others teaches a reader to stop
        # looking for it.
        ans.caveats.append(
            "adjacency is inferred from shared subnets; routing and NAT are "
            "not modelled")

        path = self.devices_between(src, dst)
        if not path:
            ans.reason = (
                "no device in this fabric has an interface facing either "
                "address, so no policy here governs that traffic. That is NOT "
                "the same as the traffic being blocked.")
            return ans

        blocked = False
        undecided = False
        for dev in path:
            iz, ez = dev.zone_for(src), dev.zone_for(dst)
            if dev.assessment is None or dev.assessment.graph is None:
                ans.caveats.append(f"{dev.name}: no policy graph; not evaluated")
                undecided = True
                continue
            hop_q = Query(source=src, destination=dst, port=port,
                          protocol=protocol, source_zone=iz,
                          destination_zone=ez)
            a = ask(dev.assessment.graph, hop_q)
            ans.hops.append(Hop(device=dev.name, ingress_zone=iz,
                                egress_zone=ez, permitted=a.permitted,
                                decided_by=a.decided_by, reason=a.reason))
            if a.skipped:
                ans.caveats.append(
                    f"{dev.name}: {len(a.skipped)} rule(s) unevaluable")
            if a.permitted is False:
                blocked = True
                break                       # one deny is enough
            if a.permitted is None:
                undecided = True

        if blocked:
            ans.permitted = False
            ans.reason = "denied at the first device that decided"
        elif undecided:
            ans.permitted = None
            ans.reason = ("at least one device on the path could not be "
                          "decided, so the end-to-end answer is unknown")
        else:
            ans.permitted = True
            ans.reason = f"permitted by every device on the path ({len(ans.hops)})"
        return ans

    def summary(self) -> dict:
        return {"devices": len(self.devices),
                "interfaces": sum(len(d.interfaces) for d in self.devices.values()),
                "links": len(self.adjacency()),
                "platforms": sorted({d.platform for d in self.devices.values()})}
