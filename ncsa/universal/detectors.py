"""Vendor-agnostic security detectors -- what we can assert with NO pack.

The problem statement's hardest requirement is the one about hardware nobody
has described to us: "the application must ideally be designed to support any
network device configuration, regardless of vendor". A signature table cannot
answer that, and neither can a mapping pack, because both presuppose that
somebody already studied the vendor.

What survives that gap is VOCABULARY. `telnet` is spelled `telnet` on Cisco,
Juniper, Huawei, MikroTik and every white-box NOS ever shipped. `dh-group1`
means 768-bit Diffie-Hellman wherever it appears. `public` is the default SNMP
community on all of them. These are lexical facts about the security domain,
not about a vendor, and they are detectable in a file from a device we have
never seen.

Three rules keep this honest, because a detector that fires on every vendor is
a detector that can be wrong on every vendor:

 1. POSITIVE EVIDENCE ONLY. A universal detector may report "this file contains
    a weak cipher", never "this file lacks logging". Absence needs a grammar --
    the setting could be three lines further on in a syntax we cannot read, or
    in a section we did not receive. Every finding here cites a line.

 2. NEGATION AWARE. `no ip http server` and `set telnet disable` contain the
    insecure token and mean the opposite. A detector that ignores negation
    turns hardened devices into failing ones, which is the most expensive
    possible false positive.

 3. CONFIDENCE, NOT CERTAINTY. These findings enter the report at confidence
    0.8 and are labelled as vendor-agnostic detections, so a reader can tell
    them from a pack-derived observation at 1.0. They are a floor under an
    unknown device, not a substitute for knowing the device.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

# Confidence assigned to anything found this way. Deliberately below the 1.0 of
# a pack mapping: we matched a token, we did not parse a grammar.
UNIVERSAL_CONFIDENCE = 0.8

# A line that turns a setting OFF rather than on. Checked before every match.
NEGATION = re.compile(
    r"(^|\s)(no|delete|unset|disable[d]?|deny|off|remove)(\s|$)|"
    r"[=:]\s*(0|off|false|no|disable[d]?)\s*$", re.I)

# A value that is a stored HASH rather than a cleartext secret. Anything
# matching this is not a cleartext-credential finding.
HASHED = re.compile(
    r"^(\$\d[a-z]?\$|\{[A-Z0-9]+\}|[0-9a-f]{32,}$|[A-Za-z0-9+/]{40,}={0,2}$|"
    r"0x[0-9a-fA-F]{16,})")

# Keywords that mark an already-encrypted credential on the same line.
ENCRYPTED_MARKER = re.compile(
    r"\b(encrypted|secret|hash|hashed|pbkdf2|bcrypt|scrypt|sha256|sha512|"
    r"md5-hash|cipher|type\s*[5789])\b", re.I)


@dataclass
class UniversalFinding:
    detector: str
    title: str
    severity: str
    line: int
    raw: str
    matched: str
    confidence: float = UNIVERSAL_CONFIDENCE
    field_hint: str = ""

    def to_json(self) -> dict:
        return {"detector": self.detector, "title": self.title,
                "severity": self.severity, "line": self.line,
                "evidence": self.raw.strip()[:160], "matched": self.matched,
                "confidence": self.confidence, "field_hint": self.field_hint,
                "source": "universal"}


@dataclass
class Detector:
    name: str
    title: str
    severity: str
    pattern: re.Pattern
    field_hint: str = ""
    # Extra guard: the line must ALSO match this to count.
    requires: re.Pattern | None = None
    # ...and must NOT match this.
    excludes: re.Pattern | None = None
    honour_negation: bool = True
    findings: list = field(default_factory=list)


# --------------------------------------------------------------------- rules
DETECTORS = [
    Detector(
        name="weak_crypto",
        title="Weak or deprecated cryptographic algorithm is configured",
        severity="high",
        # Two classes of token, because they need different boundaries.
        #
        # SHORT AND AMBIGUOUS (`des`, `md5`, `sha1`) are also fragments of
        # ordinary words and names: an interface described as
        # `DES-MOINES-UPLINK` on a line that mentions `cipher` was reported as
        # a weak-cipher finding. These may not be followed by a hyphen and a
        # letter -- except for the real cipher spellings, listed explicitly.
        #
        # LONG AND UNAMBIGUOUS (`dh-group1`, `sslv3`) contain their own
        # hyphens and need no such guard.
        pattern=re.compile(
            r"(?<![a-z0-9-])(?:"
            # IPsec transform sets write the algorithm hyphen-prefixed
            # (`esp-des esp-md5-hmac`), which the leading boundary otherwise
            # blocks -- a real weak-crypto line on Cisco read as clean.
            r"(?:esp|ah)-(?:des|3des|md5|sha1|null)(?:-hmac)?"
            r"|(?:des-cbc|des-ede3|3des-cbc|rc4-md5|rc4-sha)"
            r"|(?:des|3des|rc4|md5|sha1|wep|anon)(?![a-z0-9]|-[a-z])"
            r"|(?:dh-group[12]|diffie-hellman-group1|ssl-?v?3|sslv3|"
            r"tls-?v?1\.?[01]?|null-cipher|export-grade)(?![a-z0-9])"
            r")", re.I),
        # Only in a line that is actually about crypto, otherwise `sha1` in a
        # comment or a certificate fingerprint counts as a misconfiguration.
        requires=re.compile(
            r"\b(cipher|crypto|encryption|key-exchange|kex|mac|hash|ssl|tls|"
            r"ipsec|ike|transform|proposal|algorithm|digest|auth)\b", re.I),
        field_hint="crypto.weak_ciphers",
    ),
    Detector(
        name="telnet_enabled",
        title="Telnet (cleartext remote administration) appears to be enabled",
        severity="high",
        pattern=re.compile(r"(?<![a-z-])telnet(?![a-z-])", re.I),
        # `telnet timeout 5` configures a timer and does not permit telnet --
        # the real Cisco ASA in this repo has exactly that line and no telnet
        # access. Timers and client commands are excluded.
        excludes=re.compile(
            r"\b(timeout|client|no-telnet|disable|deny|reverse)\b", re.I),
        field_hint="management.telnet.enabled",
    ),
    Detector(
        name="cleartext_http_mgmt",
        title="Unencrypted HTTP management interface appears to be enabled",
        severity="high",
        pattern=re.compile(
            r"(?<![a-z-])http(?!s)(?![a-z-])", re.I),
        requires=re.compile(
            r"\b(server|management|mgmt|admin|web|gui|enable)\b", re.I),
        # `ip http secure-server` is HTTPS -- the hardened form -- and the
        # negative lookahead on `https` does not catch it, because the "s" is
        # in the NEXT word. Flagging it inverted the meaning of the one line
        # that proves the device is configured correctly, on the fixture built
        # specifically to be correct. A URL in a call-home or update line is
        # likewise not a management listener.
        excludes=re.compile(
            r"https?://|\bsecure[- ]?server\b|\bsecure\b|\bredirect\b|"
            r"\bproxy\b|\burl\b", re.I),
        field_hint="management.http.enabled",
    ),
    Detector(
        name="snmp_v1_v2c",
        title="SNMP v1/v2c is in use (community strings are sent in cleartext)",
        severity="high",
        pattern=re.compile(r"\b(v1|v2c|version\s*1|version\s*2c)\b", re.I),
        requires=re.compile(r"\bsnmp\b", re.I),
        field_hint="snmp.version",
    ),
    Detector(
        name="default_snmp_community",
        title="Default SNMP community string is configured",
        severity="critical",
        pattern=re.compile(
            r"\b(public|private)\b", re.I),
        requires=re.compile(r"\bsnmp[-_ ]?(server|community|agent)?\b", re.I),
        excludes=re.compile(r"\b(public[-_]?(key|cert|ip|internet))\b", re.I),
        field_hint="snmp.communities",
    ),
    Detector(
        name="any_any_permit",
        title="A rule permits traffic from any source to any destination",
        severity="critical",
        pattern=re.compile(
            r"(any\s+any|0\.0\.0\.0/0|0\.0\.0\.0\s+0\.0\.0\.0|::/0)", re.I),
        requires=re.compile(
            r"\b(permit|allow|accept|pass|action)\b", re.I),
        field_hint="firewall.rules.action",
    ),
    Detector(
        name="ftp_enabled",
        title="FTP (cleartext file transfer) appears to be enabled",
        severity="medium",
        pattern=re.compile(r"(?<![a-z-])(ftp|tftp)(?![a-z-])", re.I),
        requires=re.compile(r"\b(server|enable|service|mode)\b", re.I),
        excludes=re.compile(r"\b(passive|client|timeout|inspect)\b", re.I),
        field_hint="services.unused_enabled",
    ),
]


def _cleartext_credentials(lines) -> list:
    """Credentials stored in a recoverable form.

    Kept out of the table above because the decision is about the VALUE, not
    the presence of a keyword: `enable password Marcraft1` is a finding and
    `enable password $8$xK2p... encrypted` is not, and only inspecting the
    argument can tell them apart. This detector found a real cleartext
    credential on line 4 of a production ASA.
    """
    out = []
    rx = re.compile(
        r"\b(password|passwd|pre-shared-key|psk|community|key-string|secret)\b"
        r"\s+[\"']?([^\s\"';]+)", re.I)
    for i, raw in lines:
        if NEGATION.search(raw):
            continue
        if ENCRYPTED_MARKER.search(raw):
            continue
        m = rx.search(raw)
        if not m:
            continue
        value = m.group(2)
        # A hash, a variable placeholder, or a token too short to be a secret.
        if HASHED.match(value) or value.startswith(("<", "$(", "{{")):
            continue
        if len(value) < 4 or value.lower() in ("none", "null", "disable"):
            continue
        # The hint depends on WHICH credential, not just that one was found.
        # A fixed hint of `authentication.password_encryption` made every SNMP
        # community line dispute against a pack that had correctly observed
        # `service password-encryption` -- two methods talking about different
        # settings and appearing to contradict each other. A wrong hint
        # manufactures disagreement, which is worse than no hint at all
        # because it erodes trust in the disputes that are real.
        kw = m.group(1).lower()
        hint = {"community": "snmp.communities",
                "pre-shared-key": "crypto.ipsec_proposals",
                "psk": "crypto.ipsec_proposals",
                "key-string": "crypto.ipsec_proposals",
                }.get(kw, "authentication.password_encryption")
        title = ("SNMP community string is stored and transmitted in cleartext"
                 if kw == "community"
                 else "Credential appears to be stored in a recoverable form")
        out.append(UniversalFinding(
            detector="cleartext_credential",
            title=title,
            severity="critical", line=i, raw=raw,
            matched=f"{m.group(1)} <redacted:{len(value)} chars>",
            field_hint=hint))
    return out


def scan(text: str, *, max_findings_per_detector: int = 25) -> list:
    """Run every vendor-agnostic detector over raw configuration text."""
    lines = [(i + 1, l) for i, l in enumerate(text.splitlines())
             if l.strip() and not l.strip().startswith(("!", "#", "//", ";"))]

    out: list = []
    for d in DETECTORS:
        hits = 0
        for i, raw in lines:
            if hits >= max_findings_per_detector:
                break
            if d.honour_negation and NEGATION.search(raw):
                continue
            if d.requires is not None and not d.requires.search(raw):
                continue
            if d.excludes is not None and d.excludes.search(raw):
                continue
            m = d.pattern.search(raw)
            if not m:
                continue
            out.append(UniversalFinding(
                detector=d.name, title=d.title, severity=d.severity,
                line=i, raw=raw, matched=m.group(0), field_hint=d.field_hint))
            hits += 1

    out += _cleartext_credentials(lines)

    # One line, one finding. `snmp-server community public RO` legitimately
    # trips both the default-community and the cleartext-credential detector,
    # and reporting it twice inflates the count of a device's problems with a
    # detail about our implementation. The more specific detector wins.
    _SPECIFICITY = {"default_snmp_community": 0, "weak_crypto": 1,
                    "cleartext_credential": 2}
    best: dict = {}
    for f in out:
        prev = best.get(f.line)
        if prev is None or _SPECIFICITY.get(f.detector, 9) < \
                _SPECIFICITY.get(prev.detector, 9):
            best[f.line] = f
    out = list(best.values())

    out.sort(key=lambda f: ({"critical": 0, "high": 1, "medium": 2,
                             "low": 3}.get(f.severity, 4), f.line))
    return out


def summarise(findings) -> dict:
    by_det: dict = {}
    for f in findings:
        by_det.setdefault(f.detector, 0)
        by_det[f.detector] += 1
    sev: dict = {}
    for f in findings:
        sev.setdefault(f.severity, 0)
        sev[f.severity] += 1
    return {"total": len(findings), "by_detector": by_det, "by_severity": sev}
