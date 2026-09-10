"""Extract interfaces and their networks -- the foundation for topology.

A device's policy says what it permits. Its INTERFACES say where it sits, and
without that a collection of assessments is a pile of unrelated reports rather
than a network.

Per-platform, like the graph builders, because this is exactly the kind of
vendor knowledge the SBM exists to absorb: SonicOS publishes interface
addresses as address objects named `X0 IP` with an owning zone, while ASA and
IOS write an `ip address` line inside an `interface` block.

Every interface carries the evidence it came from. An interface inferred rather
than read is not returned -- a topology built on guessed addressing produces
confident, wrong reachability answers, which is worse than no topology.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field


@dataclass
class Interface:
    name: str
    address: str = ""
    netmask: str = ""
    zone: str = ""
    enabled: bool = True
    description: str = ""
    evidence: str = ""

    @property
    def network(self):
        """The subnet this interface sits on, or None if undeterminable."""
        if not self.address:
            return None
        try:
            if self.netmask:
                return ipaddress.ip_network(f"{self.address}/{self.netmask}",
                                            strict=False)
            return ipaddress.ip_network(f"{self.address}/32", strict=False)
        except ValueError:
            return None

    def to_json(self) -> dict:
        n = self.network
        return {"name": self.name, "address": self.address,
                "netmask": self.netmask, "network": str(n) if n else None,
                "zone": self.zone, "enabled": self.enabled,
                "description": self.description, "evidence": self.evidence}


def _clean_ip(v: str) -> str:
    v = (v or "").strip()
    return v if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", v) else ""


def from_sonicos(doc) -> list:
    """SonicOS publishes interface addressing as `<name> IP` address objects."""
    values = getattr(doc, "values", {}) or {}
    idx: dict = {}
    for key, (val, line, raw) in values.items():
        m = re.match(r"^(addrObjId|addrObjIp1|addrObjZone|addrObjSubnetMask)_(\d+)$",
                     key)
        if m:
            idx.setdefault(int(m.group(2)), {})[m.group(1)] = (val, line, raw)

    out = []
    for i, rec in idx.items():
        name = (rec.get("addrObjId") or ("", 0, ""))[0]
        if not re.fullmatch(r"(X\d+|M\d+|W\d+|MGMT) IP", name or ""):
            continue
        addr = _clean_ip((rec.get("addrObjIp1") or ("", 0, ""))[0])
        if not addr or addr == "0.0.0.0":
            continue                      # an unconfigured port is not a link
        mask = _clean_ip((rec.get("addrObjSubnetMask") or ("", 0, ""))[0])
        out.append(Interface(
            name=name.replace(" IP", ""), address=addr,
            netmask=mask or "255.255.255.0",
            zone=(rec.get("addrObjZone") or ("", 0, ""))[0],
            evidence=f"addrObjId_{i}={name}"))
    return out


_IOS_IF = re.compile(r"^interface\s+(\S+)", re.I)
_IOS_ADDR = re.compile(r"^\s+ip address\s+(\d+\.\d+\.\d+\.\d+)\s+"
                       r"(\d+\.\d+\.\d+\.\d+)", re.I)
_ASA_NAMEIF = re.compile(r"^\s+nameif\s+(\S+)", re.I)
_SHUT = re.compile(r"^\s+shutdown\s*$", re.I)
_DESC = re.compile(r"^\s+description\s+(.+)$", re.I)


def from_indented(doc) -> list:
    """Cisco IOS and ASA: an `ip address` line inside an `interface` block."""
    lines = getattr(doc, "lines", None)
    if lines is None:
        return []
    out, cur, start = [], None, 0
    for n, raw in enumerate(lines, 1):
        m = _IOS_IF.match(raw)
        if m:
            if cur and cur.address:
                out.append(cur)
            cur = Interface(name=m.group(1), evidence=f"L{n}: {raw.strip()}")
            start = n
            continue
        if cur is None:
            continue
        if not raw.startswith((" ", "\t")) and raw.strip():
            if cur.address:
                out.append(cur)
            cur = None
            continue
        a = _IOS_ADDR.match(raw)
        if a:
            cur.address, cur.netmask = a.group(1), a.group(2)
            cur.evidence = f"L{n}: {raw.strip()}"
        elif _ASA_NAMEIF.match(raw):
            cur.zone = _ASA_NAMEIF.match(raw).group(1)
        elif _SHUT.match(raw):
            cur.enabled = False
        elif _DESC.match(raw):
            cur.description = _DESC.match(raw).group(1).strip()
    if cur and cur.address:
        out.append(cur)
    return [i for i in out if i.address]


class RedactedAddressing(RuntimeError):
    """Addresses were masked, so topology cannot be built from this assessment."""


def extract(device_assessment, *, strict=False) -> list:
    """Interfaces for whatever platform this device is.

    `strict=True` RAISES when the assessment was redacted and produced nothing.
    Redaction replaces octets with `x`, so an interface address becomes
    unparseable and this silently returned an empty list -- a device with ten
    live interfaces looked like a device with none, and the fabric built around
    it reported "no policy governs that traffic". Topology needs
    `assess(..., redact=False)`; reports do not.
    """
    doc = getattr(device_assessment, "document", None)
    if doc is None:
        return []
    plat = (device_assessment.identity.platform or "").lower()
    if "sonicwall" in plat:
        out = from_sonicos(doc)
    elif hasattr(doc, "lines"):
        out = from_indented(doc)
    else:
        out = []

    if not out and getattr(doc, "redacted", False):
        msg = (f"{device_assessment.identity.source_file}: addresses are "
               "redacted, so no interface could be read. Re-run with "
               "redact=False to build topology.")
        if strict:
            raise RedactedAddressing(msg)
    return out
