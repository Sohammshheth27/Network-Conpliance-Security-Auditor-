"""IPsec VPN checks.

WHAT IS DECIDED, AND WHAT IS DELIBERATELY NOT
---------------------------------------------
Only settings whose encoding is self-evident are judged:

    on / off switches        PFS, anti-replay, management over the tunnel
    plain integers           SA lifetimes, in seconds

The cryptographic ALGORITHMS are not. SonicOS stores them as private codes --
`ipsecPh1CryptAlg=250`, `ipsecP1DHGrp=3` -- which are not the IANA IKE
numbers (250 sits in IANA's private-use range), and SonicWall publishes no
decoding for the settings export. Failing a tunnel for "weak encryption" on the
strength of a guessed code table would be exactly the fabricated finding this
project refuses to make. Those checks therefore come back UNKNOWN, with the raw
codes shown, and with the one-step way to calibrate them: open a single tunnel
in the device's GUI and read its proposal.

DISABLED TUNNELS
----------------
A tunnel that is switched off carries no traffic, so its settings are moot.
It is reported NOT_APPLICABLE with that reason -- the same logic the compliance
engine applies to the TLS version of a disabled HTTPS interface.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from .model import CLOUD_PLATFORMS, DomainResult, ExtendedFinding, roll_up

#: Conventional maxima, matching the defaults most IKE implementations ship
#: with. Longer lifetimes mean more traffic protected by one key.
IKE_SA_MAX_SECONDS = 86_400        # 24 h
IPSEC_SA_MAX_SECONDS = 28_800      # 8 h


@dataclass
class VpnTunnel:
    """One IPsec tunnel, vendor-neutral. None means "not stated"."""

    name: str
    enabled: bool | None = None
    peer: str | None = None
    pfs: bool | None = None
    anti_replay: bool | None = None
    ike_lifetime_s: int | None = None
    ipsec_lifetime_s: int | None = None
    #: transport -> permitted, for device management arriving over the tunnel
    management: dict = field(default_factory=dict)
    #: Vendor algorithm settings we hold but cannot decode. Shown, not judged.
    algorithms_raw: dict = field(default_factory=dict)
    evidence: dict = field(default_factory=dict)        # setting -> EvidenceRef

    def to_json(self) -> dict:
        return {"name": self.name, "enabled": self.enabled, "peer": self.peer,
                "pfs": self.pfs, "anti_replay": self.anti_replay,
                "ike_lifetime_s": self.ike_lifetime_s,
                "ipsec_lifetime_s": self.ipsec_lifetime_s,
                "management": self.management,
                "algorithms_raw": self.algorithms_raw}


# ------------------------------------------------------------ SonicOS adapter

def _onoff(v: str) -> bool | None:
    return {"on": True, "off": False}.get((v or "").strip().lower())


def _int(v: str) -> int | None:
    try:
        return int(str(v).strip())
    except (TypeError, ValueError):
        return None


#: SonicOS setting -> (tunnel attribute, parser). Only self-describing values.
_SONICOS_DECODED = {
    "ipsecPFSEnablePFS": ("pfs", _onoff),
    "ipsecP1LifeSecs": ("ike_lifetime_s", _int),
    "ipsecLifeSecs": ("ipsec_lifetime_s", _int),
}
#: Management transports permitted from the tunnel's peer network.
_SONICOS_MGMT = {"ipsecSshMgmt": "ssh", "ipsecHttpsMgmt": "https",
                 "ipsecHttpMgmt": "http", "ipsecSnmpMgmt": "snmp"}
#: Held but not decodable -- see the module docstring.
_SONICOS_OPAQUE = ("ipsecPh1CryptAlg", "ipsecPh1AuthAlg", "ipsecP1DHGrp",
                   "ipsecPh2CryptAlg", "ipsecPh2AuthAlg", "ipsecP2DHGrp",
                   "ipsecP1Exch")


def tunnels_from_sonicos(exp) -> list[VpnTunnel]:
    """Read the tunnel table out of a decoded SonicOS export.

    Reads `exp.values` directly rather than through `get()`, which marks
    settings consumed: the extended checks must not alter the parse accounting
    reported for the compliance assessment.
    """
    V = exp.values
    names = {}
    for key, (val, _pos, _raw) in V.items():
        m = re.match(r"^ipsecName_(\d+)$", key)
        if m and val:
            names[int(m.group(1))] = val

    def hit(base: str, i: int):
        return V.get(f"{base}_{i}")

    out = []
    for i in sorted(names):
        t = VpnTunnel(name=names[i])
        ev = {}

        name_hit = hit("ipsecName", i)
        ev["name"] = exp.evidence(name_hit[1], name_hit[2])

        # `ipsecSaDisabled=on` switches the tunnel off.
        h = hit("ipsecSaDisabled", i)
        if h:
            disabled = _onoff(h[0])
            t.enabled = None if disabled is None else not disabled
            ev["enabled"] = exp.evidence(h[1], h[2])

        h = hit("ipsecGwAddr", i)
        if h and h[0] and h[0] != "0.0.0.0":
            t.peer = h[0]
            ev["peer"] = exp.evidence(h[1], h[2])

        # Anti-replay is stored inverted: `...Disabled=on` means it is OFF.
        h = hit("ipsecAntiReplayDisabled", i)
        if h:
            disabled = _onoff(h[0])
            t.anti_replay = None if disabled is None else not disabled
            ev["anti_replay"] = exp.evidence(h[1], h[2])

        for key, (attr, parse) in _SONICOS_DECODED.items():
            h = hit(key, i)
            if h:
                setattr(t, attr, parse(h[0]))
                ev[attr] = exp.evidence(h[1], h[2])

        for key, transport in _SONICOS_MGMT.items():
            h = hit(key, i)
            if h and _onoff(h[0]) is not None:
                t.management[transport] = _onoff(h[0])
                ev[f"management.{transport}"] = exp.evidence(h[1], h[2])

        for key in _SONICOS_OPAQUE:
            h = hit(key, i)
            if h:
                t.algorithms_raw[key] = h[0]
                ev[f"alg.{key}"] = exp.evidence(h[1], h[2])

        t.evidence = ev
        out.append(t)
    return out


# ------------------------------------------------------------------ checks

def _na_disabled(check_id, title, t, nist, sev, rationale) -> ExtendedFinding:
    return ExtendedFinding(
        check_id=check_id, title=title, domain="vpn",
        state="NOT_APPLICABLE", severity=sev, scope=t.name,
        reason="the tunnel is disabled, so its settings carry no traffic",
        evidence=[t.evidence["enabled"]] if "enabled" in t.evidence else [],
        nist_800_53=nist, rationale=rationale)


def check_tunnel(t: VpnTunnel) -> list[ExtendedFinding]:
    out = []

    # --- VPN-001: perfect forward secrecy -----------------------------------
    cid, title = "NCSA-X-VPN-001", "IPsec tunnels must use perfect forward secrecy"
    nist, sev = ["SC-12", "SC-8(1)"], "medium"
    why = ("Without PFS every IPsec key is derived from the one IKE key "
           "exchange, so recovering that key exposes all traffic the tunnel "
           "ever carried rather than a single rekey interval.")
    if t.enabled is False:
        out.append(_na_disabled(cid, title, t, nist, sev, why))
    elif t.pfs is None:
        out.append(ExtendedFinding(cid, title, "vpn", "UNKNOWN", sev, t.name,
                   "the PFS setting was not found for this tunnel",
                   nist_800_53=nist, rationale=why))
    else:
        out.append(ExtendedFinding(
            cid, title, "vpn", "PASS" if t.pfs else "FAIL", sev, t.name,
            "PFS is enabled" if t.pfs else "PFS is disabled on this tunnel",
            observed=t.pfs, expected=True, evidence=[t.evidence["pfs"]],
            nist_800_53=nist, rationale=why))

    # --- VPN-002: anti-replay -----------------------------------------------
    cid, title = "NCSA-X-VPN-002", "IPsec anti-replay protection must be enabled"
    nist, sev = ["SC-23", "SC-8"], "medium"
    why = ("Anti-replay rejects captured packets re-sent by an attacker. "
           "Disabling it is sometimes done to work around packet reordering, "
           "and should be a recorded exception rather than a default.")
    if t.enabled is False:
        out.append(_na_disabled(cid, title, t, nist, sev, why))
    elif t.anti_replay is None:
        out.append(ExtendedFinding(cid, title, "vpn", "UNKNOWN", sev, t.name,
                   "the anti-replay setting was not found for this tunnel",
                   nist_800_53=nist, rationale=why))
    else:
        out.append(ExtendedFinding(
            cid, title, "vpn", "PASS" if t.anti_replay else "FAIL", sev,
            t.name,
            "anti-replay is enabled" if t.anti_replay
            else "anti-replay is disabled on this tunnel",
            observed=t.anti_replay, expected=True,
            evidence=[t.evidence["anti_replay"]],
            nist_800_53=nist, rationale=why))

    # --- VPN-003: SA lifetimes ----------------------------------------------
    cid, title = "NCSA-X-VPN-003", "IKE and IPsec SA lifetimes must be bounded"
    nist, sev = ["SC-12"], "low"
    why = (f"A longer lifetime means more traffic protected by one key. The "
           f"conventional maxima are {IKE_SA_MAX_SECONDS // 3600} h for the "
           f"IKE SA and {IPSEC_SA_MAX_SECONDS // 3600} h for the IPsec SA.")
    if t.enabled is False:
        out.append(_na_disabled(cid, title, t, nist, sev, why))
    elif t.ike_lifetime_s is None and t.ipsec_lifetime_s is None:
        out.append(ExtendedFinding(cid, title, "vpn", "UNKNOWN", sev, t.name,
                   "no lifetime settings were found for this tunnel",
                   nist_800_53=nist, rationale=why))
    else:
        problems, ev = [], []
        if t.ike_lifetime_s is not None:
            ev.append(t.evidence["ike_lifetime_s"])
            if t.ike_lifetime_s == 0 or t.ike_lifetime_s > IKE_SA_MAX_SECONDS:
                problems.append(f"IKE SA lifetime {t.ike_lifetime_s}s")
        if t.ipsec_lifetime_s is not None:
            ev.append(t.evidence["ipsec_lifetime_s"])
            if t.ipsec_lifetime_s == 0 or t.ipsec_lifetime_s > IPSEC_SA_MAX_SECONDS:
                problems.append(f"IPsec SA lifetime {t.ipsec_lifetime_s}s")
        out.append(ExtendedFinding(
            cid, title, "vpn", "FAIL" if problems else "PASS", sev, t.name,
            ("exceeds the bound: " + ", ".join(problems)) if problems else
            f"IKE {t.ike_lifetime_s}s, IPsec {t.ipsec_lifetime_s}s -- "
            f"within bounds",
            observed={"ike_s": t.ike_lifetime_s, "ipsec_s": t.ipsec_lifetime_s},
            expected={"ike_s_max": IKE_SA_MAX_SECONDS,
                      "ipsec_s_max": IPSEC_SA_MAX_SECONDS},
            evidence=ev, nist_800_53=nist, rationale=why))

    # --- VPN-004: management from the peer network ---------------------------
    cid = "NCSA-X-VPN-004"
    title = "Device management from VPN peers must be deliberate"
    nist, sev = ["AC-17", "AC-6"], "low"
    why = ("Management over a tunnel lets the remote site's network reach the "
           "firewall's administrative interface. That is often intended in a "
           "hub-and-spoke design and occasionally an accident, which only the "
           "network owner can tell apart -- hence a review, not a verdict.")
    if t.enabled is False:
        out.append(_na_disabled(cid, title, t, nist, sev, why))
    elif not t.management:
        out.append(ExtendedFinding(cid, title, "vpn", "UNKNOWN", sev, t.name,
                   "no management-over-tunnel settings were found",
                   nist_800_53=nist, rationale=why))
    else:
        on = sorted(k for k, v in t.management.items() if v)
        ev = [t.evidence[f"management.{k}"] for k in on] or \
             [t.evidence[f"management.{k}"] for k in t.management]
        out.append(ExtendedFinding(
            cid, title, "vpn", "MANUAL_REVIEW" if on else "PASS", sev, t.name,
            (f"{', '.join(on).upper()} management is permitted from this "
             f"tunnel's peer network") if on
            else "no management transport is permitted over this tunnel",
            observed=t.management, expected="none, or a recorded exception",
            evidence=ev, nist_800_53=nist, rationale=why))

    # --- VPN-005: algorithm strength -----------------------------------------
    cid = "NCSA-X-VPN-005"
    title = "Tunnel cryptography must meet current strength requirements"
    nist, sev = ["SC-13", "SC-12"], "high"
    why = ("Encryption, integrity and Diffie-Hellman group together decide "
           "whether captured tunnel traffic can be decrypted.")
    if t.enabled is False:
        out.append(_na_disabled(cid, title, t, nist, sev, why))
    elif t.algorithms_raw:
        codes = ", ".join(f"{k}={v}" for k, v in t.algorithms_raw.items())
        out.append(ExtendedFinding(
            cid, title, "vpn", "UNKNOWN", sev, t.name,
            "the algorithms are stored as vendor-private codes with no "
            "verified decoding, so strength cannot be judged from the file. "
            "To calibrate, open this tunnel's Proposals tab on the device and "
            f"record what these codes display as: {codes}",
            observed=dict(t.algorithms_raw),
            expected="AES-GCM or AES-CBC with SHA-2; DH group 14 or higher",
            evidence=[t.evidence[f"alg.{k}"] for k in t.algorithms_raw],
            nist_800_53=nist, rationale=why))
    else:
        out.append(ExtendedFinding(cid, title, "vpn", "UNKNOWN", sev, t.name,
                   "no algorithm settings were found for this tunnel",
                   nist_800_53=nist, rationale=why))
    return out


def assess_vpn(da) -> DomainResult:
    platform = (da.identity.platform or "").lower()
    doc = getattr(da, "document", None)

    if platform.startswith("sonicwall") and doc is not None and hasattr(doc, "values"):
        tunnels = tunnels_from_sonicos(doc)
        validated = "real device (SonicWall NSA 3700, 15 tunnels)"
    elif platform in CLOUD_PLATFORMS:
        return DomainResult("vpn", False,
                            "A cloud firewall-rule export describes no IPsec "
                            "tunnels; VPN gateways are a separate cloud "
                            "resource not included in this file.",
                            validated_on="n/a")
    else:
        # No adapter is a gap in THIS TOOL, not a statement about the device.
        return DomainResult("vpn", None,
                            f"No VPN adapter is built for {platform or 'this platform'} "
                            "yet, so tunnels on this device were not examined. "
                            "That is a gap in the tool, not a finding about the "
                            "device.", validated_on="n/a")

    if not tunnels:
        return DomainResult("vpn", False,
                            "The configuration defines no IPsec tunnels.",
                            validated_on=validated)

    findings = []
    for t in tunnels:
        findings.extend(check_tunnel(t))

    enabled = [t for t in tunnels if t.enabled is not False]
    headline = {}
    for f in findings:
        headline.setdefault(f.check_id, []).append(f.state)
    summary = (f"{len(tunnels)} IPsec tunnel(s) defined, {len(enabled)} enabled. "
               + "; ".join(f"{cid}: {roll_up(states)}"
                           for cid, states in sorted(headline.items())))

    notes = ["Algorithm strength (NCSA-X-VPN-005) is UNKNOWN by design: the "
             "codes are vendor-private and no verified decoding is held. "
             "Reading one tunnel's proposal in the GUI calibrates the table."]
    return DomainResult("vpn", True, summary, findings=findings,
                        inventory=[t.to_json() for t in tunnels],
                        notes=notes, validated_on=validated)
