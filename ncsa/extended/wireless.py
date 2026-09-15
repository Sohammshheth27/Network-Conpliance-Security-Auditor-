"""Wireless network checks.

VENDOR ADAPTERS, VENDOR-NEUTRAL CHECKS
--------------------------------------
Each adapter turns a device's configuration into `WirelessNetwork` objects;
the checks never learn vendor syntax. Two adapters exist:

  * Cisco Catalyst 9800 (IOS-XE `wlan` blocks). Semantics taken from Cisco's
    published 9800 configuration guides, quoted in the comments where a
    default matters. Validated on a FIXTURE built from those documented
    commands -- not on a real controller export, and reported as such.

  * SonicWall SonicOS. Validated on the REAL NSA 3700, where the honest
    answer is that no access point is provisioned: the only SonicPoint object
    carries the placeholder MAC 00:00:00:00:00:00 and no interface sits in the
    WLAN zone. The file does contain wireless profile settings -- including
    WEP keys -- but they are unused defaults. Failing them would report
    networks that do not exist, so every check comes back NOT_APPLICABLE with
    that evidence.

WHY DEFAULTS ARE SPELLED OUT
----------------------------
An IOS-XE running configuration omits default settings. A `wlan` block with no
`security` lines is therefore NOT an open network: Cisco documents the default
security policy as WPA2 with AES and 802.1X. Reading absence as "open" would
invent a critical finding on every enterprise WLAN. Where a verdict rests on a
documented default rather than a stated line, the finding says so.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from .model import CLOUD_PLATFORMS, DomainResult, ExtendedFinding

#: Guest classification is a heuristic, and is reported as one.
GUEST_NAME = re.compile(r"guest|visitor|public|hotspot", re.I)


@dataclass
class WirelessNetwork:
    profile: str
    ssid: str
    enabled: bool
    #: 'open' | 'owe' | 'wep' | 'wpa1' | 'wpa2' | 'wpa3' | 'wpa2+wpa3' | ...
    security: str
    akm: set = field(default_factory=set)
    ciphers: set = field(default_factory=set)
    #: 'mandatory' | 'optional' | None (no enabling command present)
    pmf: str | None = None
    web_auth: bool = False
    #: 'drop' | 'forward-upstream' | None (no enabling command present)
    peer_blocking: str | None = None
    broadcast: bool | None = None
    cleartext_psk: bool = False
    guest: bool = False
    guest_basis: str = ""
    #: "stated" when a security line decides it; "platform default" otherwise
    security_basis: str = "stated"
    line: int | None = None
    evidence: dict = field(default_factory=dict)        # attribute -> EvidenceRef

    def to_json(self) -> dict:
        return {"profile": self.profile, "ssid": self.ssid,
                "enabled": self.enabled, "security": self.security,
                "security_basis": self.security_basis,
                "akm": sorted(self.akm), "ciphers": sorted(self.ciphers),
                "pmf": self.pmf, "web_auth": self.web_auth,
                "peer_blocking": self.peer_blocking,
                "broadcast": self.broadcast, "guest": self.guest,
                "guest_basis": self.guest_basis,
                "cleartext_psk": self.cleartext_psk, "line": self.line}


# --------------------------------------------------- Cisco Catalyst 9800 adapter

_WLAN_HEADER = re.compile(r"^wlan\s+(\S+)\s+(\d+)\s+(\S+)")


def _mask_psk(text: str) -> str:
    """Keep the evidence line, never the key."""
    return re.sub(r"(set-key\s+\S+\s+\d+\s+)\S+", r"\1<redacted>", text)


def networks_from_cisco(doc) -> list[WirelessNetwork]:
    """Parse IOS-XE `wlan <profile> <id> <ssid>` blocks.

    Uses the underlying parser directly rather than `doc.parents()`, which
    marks lines consumed: the extended checks must not alter the parse
    accounting reported for the compliance assessment.
    """
    out = []
    for parent in doc.parse.find_objects(r"^wlan\s+\S+\s+\d+"):
        m = _WLAN_HEADER.match(parent.text.strip())
        if not m:
            continue
        profile, _wid, ssid = m.groups()
        header_ev = doc.evidence(parent.linenum + 1, parent.text)

        # Cisco: "The configured WLAN is disabled by default."
        enabled = False
        # Cisco: "The default values for security policy WPA2 are: Encryption
        # is AES. Authentication Key Management (AKM) is dot1x."
        wpa, wpa1, wpa2, wpa3 = True, False, True, False
        akm, ciphers = {"dot1x"}, {"aes"}
        pmf = web_auth = wep = None
        peer = broadcast = None
        cleartext_psk = False
        stated_security = False
        ev = {"header": header_ev}

        for child in parent.children:
            t = child.text.strip()
            e = doc.evidence(child.linenum + 1, _mask_psk(child.text))
            if t == "no shutdown":
                enabled, ev["enabled"] = True, e
            elif t == "shutdown":
                enabled, ev["enabled"] = False, e
            elif t == "no security wpa":
                wpa, stated_security, ev["security"] = False, True, e
            elif t == "security wpa":
                wpa, stated_security = True, True
            elif re.fullmatch(r"(no )?security wpa wpa([123])", t):
                on = not t.startswith("no ")
                v = t[-1]
                wpa1, wpa2, wpa3 = (on if v == "1" else wpa1,
                                    on if v == "2" else wpa2,
                                    on if v == "3" else wpa3)
                stated_security = True
                ev.setdefault("security", e)
                if on and v == "1":
                    ev["deprecated"] = e
            elif m2 := re.fullmatch(r"(no )?security wpa wpa[12] ciphers (aes|tkip)", t):
                (ciphers.discard if m2.group(1) else ciphers.add)(m2.group(2))
                stated_security = True
                if not m2.group(1) and m2.group(2) == "tkip":
                    ev["deprecated"] = e
            elif m2 := re.fullmatch(r"(no )?security wpa akm (\S+)", t):
                (akm.discard if m2.group(1) else akm.add)(m2.group(2))
                stated_security = True
                ev.setdefault("security", e)
            elif m2 := re.fullmatch(r"security pmf (mandatory|optional)", t):
                pmf, ev["pmf"] = m2.group(1), e
            elif re.fullmatch(r"no security pmf(?: mandatory| optional)?", t):
                # Cisco's documented disable form is `no security pmf mandatory`.
                pmf, ev["pmf"] = None, e
            elif t.startswith("security web-auth"):
                web_auth, ev["web_auth"] = True, e
            elif t.startswith("security static-wep-key"):
                wep, stated_security, ev["deprecated"] = True, True, e
            elif m2 := re.fullmatch(r"peer-blocking (drop|forward-upstream)", t):
                peer, ev["peer_blocking"] = m2.group(1), e
            elif t == "broadcast-ssid":
                broadcast = True
            elif t == "no broadcast-ssid":
                broadcast, ev["broadcast"] = False, e
            elif re.match(r"security wpa psk set-key \S+ 0 ", t):
                cleartext_psk, ev["cleartext_psk"] = True, e

        # --- resolve the security mode ------------------------------------
        if wep:
            security = "wep"
        elif not wpa or not (wpa1 or wpa2 or wpa3):
            security = "open"
        elif akm == {"owe"}:
            security = "owe"          # encrypted, unauthenticated
        else:
            security = "+".join(v for v, on in
                                (("wpa1", wpa1), ("wpa2", wpa2), ("wpa3", wpa3))
                                if on)
        if wpa3 and pmf is None:
            # Cisco: "For WPA3, PMF is mandatory."
            pmf = "mandatory (required by WPA3)"

        guest_basis = ""
        if web_auth:
            guest_basis = "captive-portal web authentication is configured"
        elif GUEST_NAME.search(profile) or GUEST_NAME.search(ssid):
            guest_basis = f"its name ({ssid}) marks it as a guest network"

        out.append(WirelessNetwork(
            profile=profile, ssid=ssid, enabled=enabled, security=security,
            akm=akm if wpa else set(), ciphers=ciphers if wpa else set(),
            pmf=pmf, web_auth=bool(web_auth), peer_blocking=peer,
            broadcast=broadcast, cleartext_psk=cleartext_psk,
            guest=bool(guest_basis), guest_basis=guest_basis,
            security_basis="stated" if stated_security else "platform default",
            line=parent.linenum + 1, evidence=ev))
    return out


# ----------------------------------------------------------- SonicOS adapter

def sonicos_provisioning(da) -> tuple[bool, str, list]:
    """Is any access point actually provisioned on this SonicWall?

    Returns (provisioned, reason, evidence). Read from the SonicPoint object
    table and from the interface zone assignments -- both are needed, because
    a wired interface placed in the WLAN zone would also make the zone live.
    """
    exp = da.document
    macs = [(k, v) for k, v in exp.values.items()
            if re.match(r"^sonicPointMac_\d+$", k)]
    real = [(k, v) for k, v in macs if v[0] and set(v[0]) != {"0"}]
    ev = [exp.evidence(v[1], v[2]) for _k, v in macs[:3]]

    wlan_ifaces = []
    sbm = getattr(da, "sbm", None)
    if sbm is not None:
        for path, obs in sbm.observations.items():
            if (path.startswith("interfaces[") and path.endswith(".zone")
                    and str(obs.value or "").upper() == "WLAN"):
                wlan_ifaces.append(path)

    if real:
        return True, (f"{len(real)} access point(s) provisioned "
                      f"(SonicPoint MAC entries)"), ev
    if wlan_ifaces:
        return True, (f"no access point is provisioned, but "
                      f"{len(wlan_ifaces)} interface(s) are in the WLAN zone"), ev
    return False, ("no access point is provisioned -- the only SonicPoint "
                   "object carries the placeholder MAC 00:00:00:00:00:00 -- "
                   "and no interface is assigned to the WLAN zone"), ev


# --------------------------------------------------------------- the checks

CHECKS = {
    "NCSA-X-WLAN-001": ("Wireless networks must not be open (unencrypted)",
                        "high", ["AC-18.1", "SC-8"],
                        "An open network sends every frame in the clear, so "
                        "anyone in radio range reads the traffic. A captive "
                        "portal authenticates users but encrypts nothing; "
                        "Enhanced Open (OWE) is the encrypted alternative for "
                        "guest networks."),
    "NCSA-X-WLAN-002": ("Deprecated wireless security (WEP, WPA1, TKIP) must "
                        "not be used", "high", ["AC-18.1", "SC-13"],
                        "WEP keys are recoverable in minutes, and WPA1/TKIP "
                        "are deprecated by the Wi-Fi Alliance."),
    "NCSA-X-WLAN-003": ("Protected Management Frames must be enabled",
                        "medium", ["AC-18.1", "SC-8"],
                        "Without 802.11w an attacker can forge deauthentication "
                        "frames and knock clients off the network, often as "
                        "the first step of an evil-twin attack."),
    "NCSA-X-WLAN-004": ("Guest wireless clients must be isolated from each "
                        "other", "medium", ["AC-4", "SC-7"],
                        "On a guest network the other clients are strangers. "
                        "Peer-to-peer blocking stops one compromised laptop "
                        "attacking the rest."),
    "NCSA-X-WLAN-005": ("Wireless pre-shared keys must not be stored in "
                        "cleartext", "medium", ["IA-5"],
                        "A type-0 key is readable by anyone who sees the "
                        "configuration -- including every backup of it."),
}


def _f(cid, state, net, reason, observed=None, expected=None, ev=None):
    title, sev, nist, why = CHECKS[cid]
    return ExtendedFinding(cid, title, "wireless", state, sev,
                           f"{net.ssid} ({net.profile})" if net else "device",
                           reason, observed=observed, expected=expected,
                           evidence=ev or [], nist_800_53=nist, rationale=why)


def check_network(n: WirelessNetwork) -> list[ExtendedFinding]:
    if not n.enabled:
        e = [n.evidence.get("enabled", n.evidence["header"])]
        return [_f(cid, "NOT_APPLICABLE", n,
                   "the WLAN is shut down, so it serves no clients", ev=e)
                for cid in CHECKS]

    out = []
    hdr = n.evidence["header"]
    sec_ev = [n.evidence.get("security", hdr)]
    basis = ("" if n.security_basis == "stated" else
             " (no security line is present; Cisco documents WPA2 with AES "
             "and 802.1X as the default)")

    # 001 open
    if n.security == "open":
        why = ("WPA is disabled, so traffic is not encrypted over the air"
               + ("; web authentication is configured, which authenticates "
                  "users but does not encrypt" if n.web_auth else ""))
        out.append(_f("NCSA-X-WLAN-001", "FAIL", n, why, n.security,
                      "WPA2/WPA3 or OWE", sec_ev))
    else:
        out.append(_f("NCSA-X-WLAN-001", "PASS", n,
                      f"link encryption is in place: {n.security}{basis}",
                      n.security, "WPA2/WPA3 or OWE", sec_ev))

    # 002 deprecated
    bad = []
    if n.security == "wep":
        bad.append("WEP")
    if "wpa1" in n.security:
        bad.append("WPA1")
    if "tkip" in n.ciphers:
        bad.append("TKIP")
    if bad:
        out.append(_f("NCSA-X-WLAN-002", "FAIL", n,
                      f"deprecated security in use: {', '.join(bad)}",
                      bad, "none", [n.evidence.get("deprecated", hdr)]))
    elif n.security == "open":
        out.append(_f("NCSA-X-WLAN-002", "NOT_APPLICABLE", n,
                      "the network is open, which NCSA-X-WLAN-001 reports; "
                      "there is no cipher to judge", ev=sec_ev))
    else:
        out.append(_f("NCSA-X-WLAN-002", "PASS", n,
                      f"no WEP, WPA1 or TKIP{basis}", sorted(n.ciphers),
                      "AES only", sec_ev))

    # 003 PMF
    if n.security in ("open",):
        out.append(_f("NCSA-X-WLAN-003", "NOT_APPLICABLE", n,
                      "PMF protects encrypted associations; this network "
                      "has none", ev=sec_ev))
    elif n.pmf:
        out.append(_f("NCSA-X-WLAN-003", "PASS", n, f"PMF is {n.pmf}",
                      n.pmf, "optional or mandatory",
                      [n.evidence.get("pmf", sec_ev[0])]))
    else:
        out.append(_f("NCSA-X-WLAN-003", "FAIL", n,
                      "no `security pmf` command is present, and Cisco "
                      "documents that \"By default, the PMF is disabled\" -- "
                      "so this WPA2 network has no management-frame "
                      "protection", "disabled (platform default)",
                      "optional or mandatory", [n.evidence.get("pmf", hdr)]))

    # 004 guest isolation
    if not n.guest:
        out.append(_f("NCSA-X-WLAN-004", "NOT_APPLICABLE", n,
                      "not identified as a guest network (no captive portal, "
                      "and the name does not mark it as one)", ev=[hdr]))
    elif n.peer_blocking:
        out.append(_f("NCSA-X-WLAN-004", "PASS", n,
                      f"guest network ({n.guest_basis}); peer-to-peer "
                      f"blocking is {n.peer_blocking}", n.peer_blocking,
                      "drop or forward-upstream",
                      [n.evidence["peer_blocking"]]))
    else:
        out.append(_f("NCSA-X-WLAN-004", "FAIL", n,
                      f"guest network ({n.guest_basis}) with no "
                      "`peer-blocking` command, so clients can reach each "
                      "other", None, "drop or forward-upstream", [hdr]))

    # 005 cleartext PSK
    if "psk" not in n.akm and "sae" not in n.akm:
        out.append(_f("NCSA-X-WLAN-005", "NOT_APPLICABLE", n,
                      "the network does not use a pre-shared key", ev=[hdr]))
    elif n.cleartext_psk:
        out.append(_f("NCSA-X-WLAN-005", "FAIL", n,
                      "the pre-shared key is stored as type 0 (cleartext); "
                      "the key itself is redacted from this evidence",
                      "type 0", "type 8 (AES-encrypted)",
                      [n.evidence["cleartext_psk"]]))
    else:
        out.append(_f("NCSA-X-WLAN-005", "PASS", n,
                      "the pre-shared key is not stored in cleartext",
                      None, "not type 0", [hdr]))
    return out


def assess_wireless(da) -> DomainResult:
    platform = (da.identity.platform or "").lower()
    doc = getattr(da, "document", None)

    if platform.startswith("sonicwall") and doc is not None and hasattr(doc, "values"):
        provisioned, reason, ev = sonicos_provisioning(da)
        validated = "real device (SonicWall NSA 3700)"
        if not provisioned:
            net = None
            findings = [
                ExtendedFinding(cid, t, "wireless", "NOT_APPLICABLE", sev,
                                "device", reason.capitalize() + ". The "
                                "wireless profile settings in this file are "
                                "unused defaults, and judging them would "
                                "report networks that do not exist.",
                                evidence=ev, nist_800_53=nist, rationale=why)
                for cid, (t, sev, nist, why) in CHECKS.items()]
            return DomainResult(
                "wireless", False,
                f"No wireless network is live on this device: {reason}.",
                findings=findings, validated_on=validated,
                notes=["The firewall policy still defines a WLAN zone with "
                       "rules into other zones. Those paths are LATENT: they "
                       "become live the moment an access point is attached "
                       "or an interface joins the zone. See blast radius "
                       "from WLAN."])
        # Provisioned: SonicPoint security settings are vendor-private codes.
        findings = [
            ExtendedFinding(cid, t, "wireless", "UNKNOWN", sev, "device",
                            "access points are provisioned, but SonicPoint "
                            "security settings are stored as vendor-private "
                            "codes with no verified decoding",
                            evidence=ev, nist_800_53=nist, rationale=why)
            for cid, (t, sev, nist, why) in CHECKS.items()]
        return DomainResult("wireless", True, reason.capitalize() + ".",
                            findings=findings, validated_on=validated)

    if platform.startswith("cisco_ios") and doc is not None and hasattr(doc, "parse"):
        nets = networks_from_cisco(doc)
        validated = ("fixture built from Cisco's published Catalyst 9800 "
                     "commands -- not yet a real controller export")
        if not nets:
            return DomainResult("wireless", False,
                                "The configuration defines no `wlan` "
                                "networks, so this device serves no wireless "
                                "clients.", validated_on=validated)
        findings = [f for n in nets for f in check_network(n)]
        live = [n for n in nets if n.enabled]
        return DomainResult(
            "wireless", True,
            f"{len(nets)} WLAN(s) defined, {len(live)} enabled.",
            findings=findings, inventory=[n.to_json() for n in nets],
            validated_on=validated,
            notes=["WPS is not evaluated: it is a consumer-router feature and "
                   "this platform's configuration has no WPS setting.",
                   "Guest classification is a heuristic (captive portal, or "
                   "a name such as 'guest'); each finding states its basis."])

    if platform in CLOUD_PLATFORMS:
        return DomainResult("wireless", False,
                            "A cloud firewall-rule export has no wireless "
                            "networks.", validated_on="n/a")

    return DomainResult("wireless", None,
                        f"No wireless adapter is built for "
                        f"{platform or 'this platform'} yet, so wireless "
                        "settings on this device were not examined. That is a "
                        "gap in the tool, not a finding about the device.",
                        validated_on="n/a")
