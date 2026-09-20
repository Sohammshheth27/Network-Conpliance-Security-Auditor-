"""Blast radius: what an attacker reaches from a foothold.

THE QUESTION THIS ANSWERS
-------------------------
Not "is this rule compliant?" but "if this segment is compromised, what else
can be touched?" A compliance report lists rules; this walks the policy from a
starting point and reports what is reachable, naming the rule that permits each
step.

This is the one analysis that needs everything underneath it to already exist:
the object graph resolves the named groups, the reachability engine evaluates
policy in order, and the topology fabric supplies the segments. It is a query
over machinery already built and tested, not new machinery.

THREE RULES IT INHERITS, AND MUST NOT BREAK
-------------------------------------------
1. AN UNEVALUABLE RULE IS NOT A SAFE RULE. If a rule above the deciding one
   could not be resolved, the step is reported as UNCERTAIN rather than
   dropped. A blast radius that silently omits what it could not evaluate
   reads as a smaller blast radius, which is the most dangerous direction for
   this particular error.

2. REACHABLE IS NOT THE SAME AS EXPLOITABLE. Policy permitting a packet says
   nothing about whether a service is listening, patched, or authenticated.
   This reports exposure, never compromise, and the wording says so.

3. ADJACENCY IS INFERRED. The fabric derives links from shared subnets, which
   is true of most networks and false in some. Every multi-device answer
   carries that caveat, because a path built on a guessed link is a guess.

WHY PORT SELECTION IS DELIBERATE
--------------------------------
Asking "can anything reach anything" returns a wall of true and tells an
operator nothing. The default probe set is the ports an attacker actually uses
to move laterally -- remote administration and the databases behind it -- so a
hit is a sentence someone can act on.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..graph.reach import Query, ask

#: Ports that matter when an attacker already has a foothold. Administrative
#: access first, because that is how a foothold becomes control; then the data
#: stores, because that is what the intrusion was usually for.
LATERAL_PORTS: list[tuple[int, str, str]] = [
    (22, "tcp", "SSH — remote administration"),
    (23, "tcp", "Telnet — remote administration, unencrypted"),
    (3389, "tcp", "RDP — remote desktop"),
    (5985, "tcp", "WinRM — Windows remote management"),
    (445, "tcp", "SMB — file shares and lateral movement"),
    (135, "tcp", "RPC — Windows service control"),
    (161, "udp", "SNMP — device management"),
    (443, "tcp", "HTTPS — web management"),
    (80, "tcp", "HTTP — web management, unencrypted"),
    (3306, "tcp", "MySQL"),
    (5432, "tcp", "PostgreSQL"),
    (1433, "tcp", "MS-SQL"),
    (27017, "tcp", "MongoDB"),
    (6379, "tcp", "Redis — frequently unauthenticated"),
    (9200, "tcp", "Elasticsearch"),
    (389, "tcp", "LDAP — directory, credential store"),
]

#: A step whose severity we report. Administrative access from an untrusted
#: origin is the worst case; a database is next.
ADMIN_PORTS = {22, 23, 3389, 5985, 445, 135, 161}

#: What an attacker would be attempting, in ATT&CK's vocabulary, if they used
#: this port from a foothold. IDS ONLY -- the names are resolved from the
#: bundle in reference/attack so a technique cannot be described here from
#: memory and drift from what MITRE actually publishes.
#:
#: These describe the ATTEMPT the open path enables, not a detection: nothing
#: here asserts the technique has been used, only that policy permits the
#: traffic it needs. T1078 (Valid Accounts) and T1110 (Brute Force) accompany
#: every login-bearing service because reaching a login prompt is what the
#: path actually grants.
ATTACK_BY_PORT: dict[int, tuple[str, ...]] = {
    22: ("T1021.004", "T1078", "T1110"),        # SSH
    23: ("T1021", "T1040", "T1110"),            # Telnet, cleartext on the wire
    3389: ("T1021.001", "T1078", "T1110"),      # RDP
    5985: ("T1021.006", "T1078"),               # WinRM
    445: ("T1021.002", "T1078"),                # SMB
    135: ("T1021.003",),                        # RPC / DCOM
    161: ("T1602.001", "T1046"),                # SNMP MIB dump, discovery
    443: ("T1190", "T1078"),                    # web management
    80: ("T1190", "T1040"),                     # web management, cleartext
    3306: ("T1210", "T1213"),
    5432: ("T1210", "T1213"),
    1433: ("T1210", "T1213"),
    27017: ("T1210", "T1213"),
    6379: ("T1210", "T1213"),                   # Redis, frequently unauthenticated
    9200: ("T1210", "T1213"),
    389: ("T1087.002", "T1078"),                # LDAP: directory enumeration
}


@dataclass
class Step:
    """One thing reachable from the foothold, and the rule that permits it."""

    to_zone: str
    port: int
    protocol: str
    service: str
    permitted: bool
    decided_by: str
    reason: str
    #: True when a rule above the deciding one could not be evaluated, so this
    #: step's verdict could be wrong in either direction.
    uncertain: bool = False
    #: True when the deciding rule was zone-scoped but the query named no zone.
    zone_assumed: bool = False

    @property
    def administrative(self) -> bool:
        return self.port in ADMIN_PORTS

    @property
    def attack_ids(self) -> list[str]:
        """ATT&CK techniques this open path would let an attacker attempt."""
        return list(ATTACK_BY_PORT.get(self.port, ()))

    def to_json(self) -> dict:
        return {"to_zone": self.to_zone, "port": self.port,
                "protocol": self.protocol, "service": self.service,
                "permitted": self.permitted, "decided_by": self.decided_by,
                "reason": self.reason, "uncertain": self.uncertain,
                "zone_assumed": self.zone_assumed,
                "administrative": self.administrative,
                "attack_ids": self.attack_ids}


@dataclass
class BlastRadius:
    origin: str
    origin_address: str
    reachable: list = field(default_factory=list)      # list[Step]
    blocked: int = 0
    undecidable: int = 0
    zones_considered: list = field(default_factory=list)
    notes: list = field(default_factory=list)
    #: Undecidable probes, counted per destination zone.
    #:
    #: A bare total is not actionable. "48 probes undecidable" tells an
    #: operator nothing; "every probe into MGMT was undecidable" tells them
    #: exactly where the policy is unreadable, and MGMT is the zone they would
    #: most want certainty about.
    undecidable_by_zone: dict = field(default_factory=dict)
    #: What actually sits in the origin zone today: interfaces, access points.
    #:
    #:   None -> could not tell
    #:   []   -> nothing. Every path is then LATENT: the policy permits it,
    #:           but no host is in the zone to use it yet.
    #:
    #: Without this, "if the guest Wi-Fi is compromised" reads as a live risk
    #: on a device that has no guest Wi-Fi -- true of the policy, false of the
    #: network, and exactly the overstatement an auditor gets challenged on.
    origin_members: list | None = None

    @property
    def latent(self) -> bool:
        return self.origin_members == []

    @property
    def administrative_paths(self) -> list:
        return [s for s in self.reachable if s.administrative]

    def summary(self) -> dict:
        zones = {s.to_zone for s in self.reachable}
        return {
            "origin": self.origin,
            "zones_reachable": len(zones),
            "zones_considered": len(self.zones_considered),
            "paths_open": len(self.reachable),
            "administrative_paths": len(self.administrative_paths),
            "uncertain_paths": sum(1 for s in self.reachable if s.uncertain),
            "blocked": self.blocked,
            "undecidable": self.undecidable,
            "undecidable_by_zone": dict(self.undecidable_by_zone),
            # A zone where EVERY probe was undecidable is the sharpest signal
            # here: the policy says nothing we could read about traffic into
            # it, so its exposure is unknown rather than absent.
            "zones_fully_undecidable": sorted(
                z for z, n in self.undecidable_by_zone.items()
                if n == len(LATERAL_PORTS)),
            "origin_populated": (None if self.origin_members is None
                                 else bool(self.origin_members)),
            "origin_members": list(self.origin_members or []),
            "latent": self.latent,
        }

    def explain(self) -> str:
        s = self.summary()
        out = [f"BLAST RADIUS from {self.origin}",
               f"   {s['paths_open']} path(s) open into "
               f"{s['zones_reachable']} of {s['zones_considered']} zone(s)"]
        if s["administrative_paths"]:
            out.append(f"   {s['administrative_paths']} of these are "
                       f"ADMINISTRATIVE access")
        if self.latent and self.reachable:
            out.append(f"   LATENT: nothing is in {self.origin} today (no "
                       f"interface, no access point). The policy permits these "
                       f"paths; they go live the moment something joins the "
                       f"zone.")
        elif self.origin_members:
            out.append(f"   LIVE: {self.origin} contains "
                       f"{', '.join(self.origin_members[:4])}")
        for step in sorted(self.reachable,
                           key=lambda x: (not x.administrative, x.port))[:12]:
            mark = "!" if step.administrative else " "
            tail = " [UNCERTAIN]" if step.uncertain else ""
            out.append(f"  {mark} -> {step.to_zone}: {step.protocol}/{step.port}"
                       f" {step.service}{tail}")
            out.append(f"        permitted by {step.decided_by}")
        if s["uncertain_paths"]:
            out.append(f"   caveat: {s['uncertain_paths']} path(s) rest on rules "
                       "that could not be fully evaluated; the true radius may "
                       "be larger")
        if s["undecidable"]:
            out.append(f"   caveat: {s['undecidable']} probe(s) undecidable "
                       f"-- no rule matched and this platform does not state "
                       f"its default policy, so exposure is UNPROVEN, not "
                       f"absent")
            for zone in s["zones_fully_undecidable"]:
                out.append(f"      {zone}: every probe undecidable")
        out.append("   NOTE: reachable is not exploitable. Policy permitting a "
                   "packet says nothing about whether a service is listening, "
                   "patched or authenticated.")
        return "\n".join(out)

    def to_json(self) -> dict:
        return {"summary": self.summary(),
                "origin": self.origin, "origin_address": self.origin_address,
                "reachable": [s.to_json() for s in self.reachable],
                "zones_considered": self.zones_considered,
                "notes": self.notes,
                "explain": self.explain()}


def blast_radius(graph, origin_zone: str = "", origin_address: str = "any",
                 ports=None, targets=None,
                 origin_members: list | None = None) -> BlastRadius:
    """Walk the policy outward from a foothold.

    `origin_zone` is where the attacker already is -- a compromised guest
    wireless segment, a DMZ host, a contractor VPN. Every other zone in the
    policy is probed from there on the lateral-movement port set.

    `origin_members` is what the caller knows sits in that zone. Pass [] when
    it is known to be empty; the result is then marked LATENT.
    """
    probes = ports or LATERAL_PORTS
    zones = targets or sorted(
        {z for r in graph.rules for z in r.destination_zones if z}
        or {n.name for n in graph.nodes.values()
            if getattr(n.kind, "value", "") == "zone"})

    # A zone cannot be its own blast radius: reaching where you already are is
    # not lateral movement, and reporting it pads the result.
    zones = [z for z in zones if z != origin_zone]

    out = BlastRadius(origin=origin_zone or "unscoped",
                      origin_address=origin_address,
                      zones_considered=list(zones),
                      origin_members=(None if origin_members is None
                                      else list(origin_members)))
    if out.latent:
        out.notes.append(
            f"Nothing is in {origin_zone} today, so these paths are latent "
            "policy exposure rather than live reachability. They matter "
            "because they activate without any firewall change -- plugging in "
            "an access point is enough.")

    if not zones:
        out.notes.append(
            "This policy declares no destination zones other than the origin, "
            "so there is nothing to move laterally into within it.")
        return out

    for zone in zones:
        for port, proto, service in probes:
            answer = ask(graph, Query(
                source=origin_address, destination="any", port=port,
                protocol=proto, source_zone=origin_zone,
                destination_zone=zone))

            if answer.permitted is None:
                out.undecidable += 1
                out.undecidable_by_zone[zone] = (
                    out.undecidable_by_zone.get(zone, 0) + 1)
                continue
            if not answer.permitted:
                out.blocked += 1
                continue

            out.reachable.append(Step(
                to_zone=zone, port=port, protocol=proto, service=service,
                permitted=True, decided_by=answer.decided_by,
                reason=answer.reason,
                # An unevaluable rule ABOVE the match could have permitted or
                # denied differently. Carrying that forward is what stops a
                # blast radius reading smaller than it is.
                uncertain=bool(answer.skipped),
                zone_assumed=answer.zone_assumed))

    if any(s.uncertain for s in out.reachable):
        out.notes.append(
            "Some paths rest on rules that could not be fully evaluated, "
            "because they reference objects this configuration does not "
            "contain. The true blast radius may be larger than shown.")
    return out


def zone_members(da, zone: str):
    """What sits in a zone today: interfaces, plus access points for WLAN.

    Returns None when the device model is unavailable. "Could not tell" must
    never be reported as "empty", or every path would be mislabelled latent.
    One helper, used by the API and the report, so the two cannot disagree
    about the same device.
    """
    sbm = getattr(da, "sbm", None)
    if sbm is None or not zone:
        return None
    members = []
    for path, obs in sbm.observations.items():
        if (path.startswith("interfaces[") and path.endswith(".zone")
                and str(obs.value or "").upper() == zone.upper()):
            members.append("interface " + path[len("interfaces["):-len("].zone")])
    platform = (da.identity.platform or "").lower()
    if zone.upper() == "WLAN" and platform.startswith("sonicwall"):
        from ..extended.wireless import sonicos_provisioning
        provisioned, _reason, _ev = sonicos_provisioning(da)
        if provisioned:
            members.append("provisioned access points")
    return members


def fabric_blast_radius(fabric, origin_zone: str = "",
                        origin_address: str = "any", ports=None) -> dict:
    """Blast radius across several devices.

    Each device is walked separately and the results are reported per device
    rather than merged. Merging would imply a single evaluated path across the
    fabric, and adjacency here is INFERRED from shared subnets -- a chained
    conclusion built on an inferred link is a guess presented as a path.
    """
    per_device, skipped = [], []
    for key, device in fabric.devices.items():
        graph = getattr(device.assessment, "graph", None)
        if graph is None:
            skipped.append({
                "device": key,
                "reason": "no policy object graph for this platform, so its "
                          "contribution to the blast radius cannot be "
                          "evaluated"})
            continue
        radius = blast_radius(graph, origin_zone, origin_address, ports)
        per_device.append({"device": key, "name": device.name,
                           **radius.to_json()})

    return {
        "origin_zone": origin_zone or "unscoped",
        "devices": per_device,
        "skipped": skipped,
        "adjacency": fabric.adjacency(),
        "caveat": "Device adjacency is INFERRED from shared subnets, not read "
                  "from the wire. Per-device results are reported separately "
                  "rather than chained, because a path across an inferred link "
                  "would be a guess presented as a fact.",
    }
