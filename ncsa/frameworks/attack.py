"""MITRE ATT&CK tags: which adversary technique each control stands in front of.

A compliance finding says "SNMP uses a default community string". An ATT&CK
tag says what an adversary does with that: T1602.001, dump the device's
configuration over SNMP. The tag turns a checklist item into a threat a
defender can reason about, and lets findings be sorted by technique.

RULES FOR A TAG
---------------
  * DIRECT ONLY. A control is tagged with a technique it directly prevents or
    detects. Telnet enabled -> T1040 Network Sniffing is direct: credentials
    cross the wire in the clear. A login banner prevents no technique, so it
    has no tag -- and a tag added for completeness would be decoration that a
    reviewer who knows ATT&CK would rightly pick apart.
  * VERIFIED, EVERY TIME. Every ID below is checked against the ATT&CK STIX
    bundle on disk (tests/test_attack_tags.py) and must be ACTIVE -- neither
    revoked nor deprecated. That test is why this map uses T1685 and T1686:
    ATT&CK v19 revoked T1562 "Impair Defenses", which a map written from
    memory would still cite.
  * OUR WORDS. The `why` text is written here. Technique names come from the
    bundle at runtime; ATT&CK descriptions are not copied.

ATT&CK here describes the ADVERSARY. It is not a compliance framework and no
score is computed from it.
"""
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

BUNDLE = Path(__file__).resolve().parents[2] / "reference" / "attack" / "enterprise-attack.json"

#: control or extended-check id -> [(technique id, why this control is in front
#: of it)]. Controls absent from this map are untagged deliberately.
ATTACK_MAP: dict[str, list[tuple[str, str]]] = {
    # --- accounts and authentication --------------------------------------
    "NCSA-AAA-001": [("T1078.001", "local accounts are where default and shared credentials live; central AAA takes them out of daily use")],
    "NCSA-AAA-002": [("T1078.001", "every extra local account is another default or shared credential to find")],
    "NCSA-EXT-013": [("T1110", "lockout turns online password guessing from unlimited to a handful of tries")],
    "NCSA-SSH-004": [("T1110", "limiting attempts per connection slows online guessing")],
    "NCSA-PWD-001": [("T1110", "short passwords fall to guessing and cracking first")],
    "NCSA-PWD-002": [("T1110", "complexity widens the space a guessing attack has to search")],
    "NCSA-EXT-014": [("T1110", "a guessed password alone no longer grants administrative access")],
    "NCSA-EXT-012": [("T1552.001", "a reversible privileged password is recoverable from any copy of the configuration")],
    "NCSA-PWD-003": [("T1552.001", "unencrypted passwords are readable from any configuration backup")],
    "NCSA-PLT-002": [("T1552.001", "stored credentials in the clear are readable from exported configuration")],

    # --- management plane -------------------------------------------------
    "NCSA-TEL-001": [("T1040", "Telnet sends the administrator's credentials in the clear")],
    "NCSA-HTTP-001": [("T1040", "cleartext HTTP management exposes session credentials on the wire")],
    "NCSA-EXT-008": [("T1040", "without a redirect, administrators can land on the cleartext interface")],
    "NCSA-VTY-001": [("T1040", "any non-SSH transport on the management lines is a cleartext login path")],
    "NCSA-SSH-002": [("T1557", "SSH version 1 is breakable by an adversary in the middle")],
    "NCSA-EXT-001": [("T1557", "weak key exchange and ciphers let an interceptor recover the session")],
    "NCSA-SSH-003": [("T1557", "weak ciphers let an interceptor recover the session")],
    "NCSA-EXT-005": [("T1557", "short RSA host keys can be factored, allowing impersonation of the device")],
    "NCSA-HTTPS-001": [("T1689", "accepting old TLS versions is what a downgrade attack relies on"),
                       ("T1557", "legacy TLS sessions can be intercepted")],
    "NCSA-VTY-002": [("T1021", "without an ACL, any host that can reach the device can try to log in to it")],
    "NCSA-EXT-003": [("T1021", "binding SSH to a management interface keeps it off data-plane networks")],
    "NCSA-EXT-010": [("T1021", "outbound sessions let a compromised administrator login pivot onwards from the device")],
    "NCSA-EXT-031": [("T1210", "every unnecessary service is another listener an adversary can exploit")],

    # --- SNMP ---------------------------------------------------------------
    "NCSA-SNMP-001": [("T1602.001", "SNMP v1/v2c community strings are cleartext, enabling MIB and configuration dumps")],
    "NCSA-SNMP-002": [("T1602.001", "a default community string is the first thing a MIB dump tries")],
    "NCSA-EXT-023": [("T1602.001", "unauthenticated SNMP lets anyone who reaches it query the device")],
    "NCSA-EXT-024": [("T1040", "without SNMPv3 privacy the queried data crosses the wire readable")],
    "NCSA-EXT-025": [("T1602.001", "an ACL limits who can attempt a MIB dump at all")],
    "NCSA-EXT-026": [("T1602.001", "views limit how much of the device a successful query can read")],

    # --- logging: evidence that survives the intruder -----------------------
    "NCSA-LOG-001": [("T1070", "without logs there is no record of the intrusion to remove -- or to find")],
    "NCSA-LOG-002": [("T1070", "a second remote copy survives an adversary clearing the device's own logs")],
    "NCSA-EXT-022": [("T1070", "remote syslog keeps the record off the device an intruder controls")],
    "NCSA-EXT-017": [("T1070", "command accounting records the administrative actions an intruder takes"),
                     ("T1686.002", "firewall changes made by an intruder are recorded as commands")],
    "NCSA-CAT-001": [("T1686.002", "rule logging shows traffic through rules an intruder may have added or loosened")],

    # --- firewall policy ----------------------------------------------------
    "NCSA-CLD-001": [("T1133", "administrative services reachable from the internet are external remote services"),
                     ("T1110", "an internet-facing login is guessed continuously")],
    "NCSA-CLD-002": [("T1190", "all protocols from the internet exposes every listening service to exploitation")],
    "NCSA-CLD-003": [("T1190", "unrestricted ingress puts internal services in front of internet exploitation")],
    "NCSA-CAT-002": [("T1021", "any-to-any rules are the paths lateral movement uses")],
    "NCSA-CAT-009": [("T1071", "unrestricted egress lets command-and-control use ordinary application protocols"),
                     ("T1572", "unrestricted egress lets traffic be tunnelled out over any protocol")],
    "NCSA-EXT-039": [("T1190", "intrusion prevention inspects for exploitation of exposed services")],

    # --- layer 2 --------------------------------------------------------------
    "NCSA-EXT-034": [("T1557.003", "DHCP snooping drops offers from rogue DHCP servers")],
    "NCSA-EXT-035": [("T1557.002", "dynamic ARP inspection drops forged ARP replies")],

    # --- extended checks ------------------------------------------------------
    "NCSA-X-VPN-001": [("T1040", "without PFS, traffic captured today can be decrypted if the IKE key is ever recovered")],
    "NCSA-X-VPN-002": [("T1557", "without anti-replay an interceptor can re-inject captured packets")],
    "NCSA-X-VPN-004": [("T1021", "management over a tunnel extends the device's login surface to the peer site")],
    "NCSA-X-VPN-005": [("T1040", "weak tunnel cryptography makes captured traffic decryptable")],
    "NCSA-X-WLAN-001": [("T1669", "an open network is an initial-access path for anyone in radio range"),
                        ("T1040", "open wireless frames are readable by anyone listening")],
    "NCSA-X-WLAN-002": [("T1669", "WEP and TKIP keys are recoverable, so the network is joinable"),
                        ("T1040", "broken encryption leaves traffic readable")],
    "NCSA-X-WLAN-003": [("T1557.004", "forged deauthentication frames push clients towards an evil twin")],
    "NCSA-X-WLAN-004": [("T1210", "without isolation one guest device can attack the others")],
    "NCSA-X-WLAN-005": [("T1552.001", "a cleartext key is readable from any copy of the controller configuration")],
    "NCSA-X-CVE-001": [("T1190", "a published firmware flaw on an exposed service is the textbook initial access"),
                       ("T1210", "the same flaw is reachable from inside once an adversary has a foothold")],
}

#: Blast-radius administrative paths are lateral movement by definition.
BLAST_ADMIN_TECHNIQUE = ("T1021", "an open administrative path from a foothold is how lateral movement proceeds")


@lru_cache(maxsize=2)
def load_techniques(path: str = str(BUNDLE)) -> dict:
    """Active techniques only: id -> {name, tactics}. Empty when absent."""
    p = Path(path)
    if not p.exists():
        return {}
    data = json.loads(p.read_text(encoding="utf-8"))
    out, version = {}, None
    for o in data.get("objects", []):
        if o.get("type") == "x-mitre-collection":
            version = o.get("x_mitre_version")
        if (o.get("type") != "attack-pattern" or o.get("revoked")
                or o.get("x_mitre_deprecated")):
            continue
        tid = next((r["external_id"] for r in o.get("external_references", [])
                    if r.get("source_name") == "mitre-attack"), None)
        if tid:
            out[tid] = {"name": o.get("name"),
                        "tactics": [p["phase_name"] for p in
                                    o.get("kill_chain_phases", [])]}
    out["__version__"] = version
    return out


def tags_for(check_id: str, techniques: dict | None = None) -> list[dict]:
    """ATT&CK tags for one control, with names resolved from the bundle.

    A mapped ID the bundle does not know is DROPPED here rather than shown
    unresolved, and the test suite fails on it -- a stale tag must never reach
    a report looking authoritative.
    """
    techniques = techniques if techniques is not None else load_techniques()
    out = []
    for tid, why in ATTACK_MAP.get(check_id, []):
        t = techniques.get(tid)
        if t is None:
            continue
        out.append({"id": tid, "name": t["name"], "tactics": t["tactics"],
                    "why": why})
    return out


def coverage(control_ids: list[str], techniques: dict | None = None) -> dict:
    """Which techniques the control set stands in front of, by tactic."""
    techniques = techniques if techniques is not None else load_techniques()
    by_tactic: dict = {}
    covered = set()
    tagged = [c for c in control_ids if c in ATTACK_MAP]
    for cid in tagged:
        for tag in tags_for(cid, techniques):
            covered.add(tag["id"])
            for tac in tag["tactics"]:
                by_tactic.setdefault(tac, set()).add(tag["id"])
    return {
        "attack_version": techniques.get("__version__"),
        "techniques_covered": sorted(covered),
        "by_tactic": {k: sorted(v) for k, v in sorted(by_tactic.items())},
        "controls_tagged": len(tagged),
        "controls_untagged": len(control_ids) - len(tagged),
        "untagged_reason": "Untagged controls prevent no specific adversary "
                           "technique (banners, timezone, descriptions and the "
                           "like). Tagging them would be decoration.",
    }
