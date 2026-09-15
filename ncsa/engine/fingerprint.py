"""Step 2 -- identify the device (plan 2.1).

Scans the first ~200 lines for vendor signatures and decides:
vendor, platform, OS, version, hostname, serial.

That decision drives everything downstream: which reader, which mapping pack,
which controls apply, which fix commands get generated.

Plan 2.1's last line matters most: **if fingerprinting fails, mark the vendor
UNKNOWN and route straight to the AI path.** A wrong guess is worse than no
guess -- it would apply the wrong pack and produce confident nonsense. So every
signature carries a score, and a weak best-match is reported as UNKNOWN rather
than forced.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.parse import unquote_plus

from pydantic import BaseModel, Field

SCAN_LINES = 200


class Fingerprint(BaseModel):
    vendor: str = "UNKNOWN"
    platform: str = "UNKNOWN"
    os: str | None = None
    version: str | None = None
    hostname: str | None = None
    serial: str | None = None
    # Hardware model, e.g. "NSA 3700". Deliverable 4 asks for "serial numbers
    # and hardware details" by name, so it is a first-class field rather than
    # something a report has to dig out of `matched`.
    model: str | None = None
    reader: str | None = None
    confidence: float = 0.0
    matched: list[str] = Field(default_factory=list)

    @property
    def is_known(self) -> bool:
        return self.vendor != "UNKNOWN"


class Signature(BaseModel):
    vendor: str
    platform: str
    reader: str
    os: str | None = None
    patterns: list[str]           # regexes; each match adds to the score
    strong: list[str] = Field(default_factory=list)  # a match here is decisive
    version_re: str | None = None
    hostname_re: str | None = None
    serial_re: str | None = None


# Signatures from plan 2.1. Ordered most specific first.
SIGNATURES: list[Signature] = [
    Signature(
        vendor="cisco", platform="cisco_iosxe_router", reader="indented", os="IOS-XE",
        strong=[r"^\s*boot system .*packages\.conf", r"^\s*version 1[6-7]\.\d"],
        patterns=[r"^\s*service password-encryption", r"^\s*line vty \d",
                  r"^\s*ip ssh version", r"^\s*aaa new-model", r"^\s*interface GigabitEthernet"],
        version_re=r"^\s*version (\d+\.\d+)",
        hostname_re=r"^\s*hostname (\S+)",
        serial_re=r"[Pp]rocessor board ID (\S+)",
    ),
    Signature(
        # ASA must be matched BEFORE the IOS-XE signature. Both are indented
        # Cisco CLI and share `interface GigabitEthernet`, so an ASA file
        # scored 0.25 against IOS-XE -- below the confidence floor, which
        # correctly produced UNKNOWN rather than a wrong pack, but also meant a
        # real firewall could not be assessed at all.
        vendor="cisco", platform="cisco_asa", reader="indented", os="ASA",
        strong=[r"^\s*nameif \S+", r"^ASA Version", r"^\s*security-level \d+"],
        patterns=[r"^\s*ssh \d+\.\d+\.\d+\.\d+ ", r"^\s*telnet timeout \d+",
                  r"^\s*class-map inspection_default", r"^\s*names\s*$",
                  r"^\s*dynamic-access-policy-record"],
        version_re=r"^ASA Version ([\d.()]+)",
        hostname_re=r"^\s*hostname (\S+)",
        serial_re=r"[Ss]erial [Nn]umber:\s*(\S+)",
    ),
    Signature(
        vendor="arista", platform="arista_eos", reader="indented", os="EOS",
        strong=[r"^\s*!\s*device:.*\(.*EOS", r"^\s*transceiver qsfp default-mode"],
        patterns=[r"^\s*management api http-commands", r"^\s*spanning-tree mode mstp",
                  r"^\s*interface Ethernet\d"],
        hostname_re=r"^\s*hostname (\S+)",
    ),
    Signature(
        vendor="hpe_aruba", platform="aruba_aoscx", reader="indented", os="AOS-CX",
        strong=[r"^\s*!Version ArubaOS-CX"],
        patterns=[r"^\s*ssh server vrf", r"^\s*vlan \d+\s*$", r"^\s*aaa authentication"],
        version_re=r"!Version ArubaOS-CX \S+ ([\d.]+)",
        hostname_re=r"^\s*hostname (\S+)",
    ),
    Signature(
        vendor="juniper", platform="juniper_srx", reader="braces", os="Junos",
        strong=[r"^\s*set system host-name", r"^system\s*\{"],
        patterns=[r"^\s*set security policies", r"^\s*set interfaces \S+ unit",
                  r"protocol-version v2"],
        hostname_re=r"^\s*set system host-name (\S+)",
        version_re=r"^\s*## Last commit.*JUNOS ([\d.]+)",
    ),
    Signature(
        vendor="fortinet", platform="fortinet_fortios", reader="fortinet_block", os="FortiOS",
        strong=[r"^#config-version=FG", r"^\s*config system global"],
        patterns=[r"^\s*set admintimeout", r"^\s*config firewall policy", r"^\s*next\s*$"],
        version_re=r"^#config-version=\S+-([\d.]+)",
        hostname_re=r"^\s*set hostname \"?(\S+?)\"?\s*$",
        serial_re=r"^#.*[Ss]erial[- ]?[Nn]umber[=: ]+(\S+)",
    ),
    Signature(
        vendor="sonicwall", platform="sonicwall_sonicos", reader="fortinet_block", os="SonicOS",
        strong=[r"^\s*config sonicos", r"^#SonicOS"],
        patterns=[r"^\s*administration", r"^\s*set gui", r"^\s*end\s*$"],
    ),
    Signature(
        vendor="paloalto", platform="paloalto_panos", reader="xml", os="PAN-OS",
        strong=[r"<config[^>]*version=", r"<devices>"],
        patterns=[r"<entry name=\"localhost\.localdomain\"", r"<deviceconfig>"],
        version_re=r"<config[^>]*version=\"([\d.]+)\"",
        hostname_re=r"<hostname>([^<]+)</hostname>",
    ),
]


def fingerprint_text(text: str) -> Fingerprint:
    head = "\n".join(text.splitlines()[:SCAN_LINES])
    best: Fingerprint | None = None

    for sig in SIGNATURES:
        matched: list[str] = []
        score = 0.0
        for p in sig.strong:
            if re.search(p, head, re.M):
                score += 1.0
                matched.append(p)
        for p in sig.patterns:
            if re.search(p, head, re.M):
                score += 0.25
                matched.append(p)
        if score == 0:
            continue

        fp = Fingerprint(
            vendor=sig.vendor, platform=sig.platform, os=sig.os,
            reader=sig.reader, confidence=min(score, 1.0), matched=matched,
        )
        for attr, rx in (("version", sig.version_re), ("hostname", sig.hostname_re),
                         ("serial", sig.serial_re)):
            if rx:
                m = re.search(rx, head, re.M)
                if m:
                    setattr(fp, attr, m.group(1))
        if best is None or fp.confidence > best.confidence:
            best = fp

    # Plan 2.1: a weak match is UNKNOWN, not a guess. Applying the wrong pack
    # produces a confident, wrong report -- the worst outcome available.
    if best is None or best.confidence < 0.5:
        return Fingerprint(
            vendor="UNKNOWN", platform="UNKNOWN",
            confidence=(best.confidence if best else 0.0),
            matched=(best.matched if best else []),
        )
    return best


def fingerprint_json(data) -> Fingerprint:
    """JSON artifacts are identified structurally, not by regex."""
    if isinstance(data, list) and data and isinstance(data[0], dict):
        if "GroupId" in data[0] and "IpPermissions" in data[0]:
            return Fingerprint(vendor="aws", platform="security_groups",
                               reader="json", os="AWS EC2", confidence=1.0,
                               matched=["GroupId+IpPermissions"])
        first = data[0]
        # Azure NSGs: rules at the top level (az CLI) or under `properties`
        # (ARM/REST). The old test accepted any object with `properties`,
        # which is half the Azure resource model.
        if "securityRules" in first or "securityRules" in (first.get("properties") or {}):
            return Fingerprint(vendor="azure", platform="network_security_groups",
                               reader="json", os="Azure", confidence=1.0,
                               matched=["securityRules"])
        # GCP VPC firewall rules, from `gcloud compute firewall-rules list`.
        if first.get("kind") == "compute#firewall" or (
                "direction" in first and "network" in first
                and ("allowed" in first or "denied" in first)):
            return Fingerprint(vendor="gcp", platform="gcp_firewall",
                               reader="json", os="Google Cloud VPC",
                               confidence=1.0, matched=["compute#firewall"])
    if isinstance(data, dict):
        if "DEVICE_METADATA" in data:
            return Fingerprint(vendor="sonic", platform="sonic", reader="json",
                               os="SONiC", confidence=1.0, matched=["DEVICE_METADATA"])
        if "SecurityGroups" in data:
            return Fingerprint(vendor="aws", platform="security_groups", reader="json",
                               os="AWS EC2", confidence=1.0, matched=["SecurityGroups"])
        if "securityRules" in data or "securityRules" in (data.get("properties") or {}):
            return Fingerprint(vendor="azure", platform="network_security_groups",
                               reader="json", os="Azure", confidence=1.0,
                               matched=["securityRules"])
    return Fingerprint()


def fingerprint_xml(text: str) -> "Fingerprint | None":
    """Structured exports identify themselves; no regex sniffing needed.

    This is the accuracy tier that matters. `show configuration | display xml`
    on Junos and the PAN-OS running config are both already parsed by the
    device that wrote them, so there is no grammar left to guess -- which is
    why they are matched before any of the CLI signatures.
    """
    head = text[:4000]
    if "xml.juniper.net" in head or "<rpc-reply" in head:
        m = re.search(r"<version>([^<]+)</version>", text)
        h = re.search(r"<host-name>([^<]+)</host-name>", text)
        return Fingerprint(
            vendor="juniper", platform="juniper_srx_xml", reader="xml",
            os="Junos", confidence=1.0, matched=["junos xml rpc-reply"],
            version=m.group(1) if m else None,
            hostname=h.group(1) if h else None)
    if re.search(r"<config[^>]*(urldb|version=)", head) or "<devices>" in head:
        m = re.search(r'<config[^>]*version="([\d.]+)"', head)
        h = re.search(r"<hostname>([^<]+)</hostname>", text)
        return Fingerprint(
            vendor="paloalto", platform="paloalto_panos", reader="xml",
            os="PAN-OS", confidence=1.0, matched=["panos config xml"],
            version=m.group(1) if m else None,
            hostname=h.group(1) if h else None)
    return None


def fingerprint_file(path: str | Path) -> Fingerprint:
    p = Path(path)
    raw = p.read_bytes()

    # Try JSON first -- it is decidable, unlike regex sniffing.
    stripped = raw.lstrip()[:1]
    if stripped in (b"{", b"["):
        try:
            data = json.loads(raw.decode("utf-8", errors="replace"))
        except json.JSONDecodeError:
            data = None
        if data is not None:
            fp = fingerprint_json(data)
            if _is_unknown(fp):
                return learned_fingerprint(data=data) or fp
            return fp

    if stripped == b"<":
        xml_fp = fingerprint_xml(raw.decode("utf-8", errors="replace"))
        if xml_fp is not None:
            return xml_fp

    text = raw.decode("utf-8", errors="replace")

    # A SonicOS `.exp` export is decidable too, and it does not look like
    # anything the line-oriented signatures match: it is one enormous
    # key=value blob, so `fingerprint_text` scored it UNKNOWN and the whole
    # device fell through to "no pack" despite a pack existing for it.
    exp = fingerprint_sonicos_exp(text)
    if exp is not None:
        return exp

    # ...and a real `.exp` straight off the appliance is BASE64 of that blob,
    # which is what an administrator actually uploads. Only the already-decoded
    # form was recognised, so the genuine article -- the file the product is
    # meant to accept -- fingerprinted as UNKNOWN and was refused.
    decoded = _try_base64(raw)
    if decoded is not None:
        exp = fingerprint_sonicos_exp(decoded)
        if exp is not None:
            # Sniffing 4 KB is enough to RECOGNISE the format, but not to
            # identify the device: `serialNumber=` sits well past that offset.
            # A missing serial made two exports of the same appliance compare
            # as different devices, so the change history between them was
            # refused. Once the format is known, decode it all.
            full = _try_base64(raw, limit=None)
            if full:
                better = fingerprint_sonicos_exp(full)
                if better is not None:
                    exp = better
            exp.matched = exp.matched + ["base64-encoded export"]
            return exp

    fp = fingerprint_text(text)
    if _is_unknown(fp):
        return learned_fingerprint(text=text) or fp
    return fp


def _is_unknown(fp) -> bool:
    return not fp.platform or str(fp.platform).upper() == "UNKNOWN"


def learned_fingerprint(*, text: str | None = None, data=None,
                        packs_dir: str = "packs"):
    """Recognise a vendor the training interface taught, by its signature.

    Consulted only after every built-in signature has failed, so a taught
    signature can never capture a vendor the tool already knows. EVERY
    signature of a taught pack must match -- one loose regex must not be
    enough to hand a stranger's file to the wrong pack.
    """
    import yaml

    for p in sorted(Path(packs_dir).glob("*.learned.yaml")):
        try:
            doc = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        except Exception:                              # noqa: BLE001
            continue
        if doc.get("version") != "learned-bootstrap":
            continue
        sigs = [str(s) for s in (doc.get("fingerprint") or []) if str(s).strip()]
        if not sigs or not doc.get("platform"):
            continue
        reader = doc.get("reader")
        try:
            if reader == "json":
                if data is None:
                    continue
                from jsonpath_ng.ext import parse
                ok = all(parse(s).find(data) for s in sigs)
            else:
                if text is None:
                    continue
                head = "\n".join(text.splitlines()[:400])
                ok = all(re.search(s, head, re.M) for s in sigs)
        except Exception:                              # noqa: BLE001
            continue
        if ok:
            return Fingerprint(
                vendor=doc.get("vendor") or "learned", platform=doc["platform"],
                reader=reader, os=doc.get("vendor"), confidence=1.0,
                matched=["taught signature: " + "; ".join(sigs)])
    return None


_EXP_MARKERS = ("shortProdName=", "buildNum=", "allowHttpMgmt=", "serialNumber=")


# A serial that is all zeros, all Fs, or a word like "unknown" is a
# PLACEHOLDER the device emitted because it had nothing to report. Treating it
# as an identifier merged unrelated appliances under one key -- and here it did
# the opposite, splitting two exports of one appliance apart, because a
# sanitised export carries 000000000000 where the real one carries a serial.
_PLACEHOLDER_SERIAL = re.compile(
    r"^(0+|f+|F+|[0-]+|unknown|none|n/?a|not ?specified|default|\s*)$")


def is_real_serial(value) -> bool:
    v = (value or "").strip()
    return bool(v) and not _PLACEHOLDER_SERIAL.match(v)


def _try_base64(raw: bytes, limit: "int | None" = 4096) -> "str | None":
    """Decode a base64 body, or return None.

    Only the first block is decoded for sniffing -- a 3.5 MB export does not
    need to be fully decoded twice just to identify it, and the markers all
    appear in the first few hundred bytes.
    """
    head = (raw[:limit] if limit else raw).strip()
    if not head or len(head) < 64:
        return None
    # Base64 alphabet only; anything else is not an encoded export.
    #
    # Checked on a BOUNDED PREFIX. Running it over the whole 3.5 MB body made
    # the full-file decode fail on any stray character anywhere in the file,
    # so the serial it was fetching stayed missing and two exports of one
    # appliance compared as different devices.
    probe = re.sub(rb"\s", b"", head[:4096])
    if not re.fullmatch(rb"[A-Za-z0-9+/=]+", probe):
        return None
    import base64
    try:
        # Trim to a 4-byte boundary so a partial block does not fail the whole
        # decode; we are sniffing, not parsing.
        body = re.sub(rb"\s", b"", head)
        body = body[: len(body) // 4 * 4]
        return base64.b64decode(body, validate=False).decode(
            "utf-8", errors="replace")
    except Exception:                                  # noqa: BLE001
        return None


def fingerprint_sonicos_exp(text: str) -> "Fingerprint | None":
    """Recognise a decoded SonicOS export by its own setting names."""
    hits = [m for m in _EXP_MARKERS if m in text]
    if len(hits) < 2:
        return None

    def grab(key: str) -> str | None:
        m = re.search(rf"(?:^|[&\n]){re.escape(key)}=([^&\n]*)", text)
        if not m:
            return None
        # The export is URL-encoded: the model reads "NSA%203700" on the wire
        # and has to reach a report as "NSA 3700".
        return unquote_plus(m.group(1)).strip() or None

    return Fingerprint(
        vendor="sonicwall", platform="sonicwall_sonicos", reader="sonicos_exp",
        os="SonicOS", version=grab("buildNum"), hostname=grab("firewallName"),
        serial=(grab("serialNumber")
                if is_real_serial(grab("serialNumber")) else None),
        model=grab("shortProdName"),
        confidence=min(1.0, len(hits) / 3), matched=hits)
