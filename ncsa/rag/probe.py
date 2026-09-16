"""The interface between a parsed configuration and the framework index.

THE FORMAT QUESTION, answered concretely
----------------------------------------
Raw configuration text is never sent to retrieval. Three reasons, in order of
how badly each one bites:

 1. A config line is vendor dialect. `allowHttpMgmt=off` shares no vocabulary
    with "the web-based administrative interface must be disabled", so lexical
    retrieval scores zero and dense retrieval is guessing from four tokens.
 2. It is per-device. Retrieving per line means re-retrieving 92,635 times for
    one SonicWall, and getting a different mapping for the next SonicWall.
 3. It is production data -- addresses, hashes, userIV. That belongs in an
    index even less than it belongs in a report.

What is sent instead is the SBM FIELD, the vendor-neutral unit we already went
to the trouble of building, enriched with the vendor syntax that every pack
already declares. So one probe carries the neutral intent AND the literal
`ip http server` / `allowHttpMgmt` strings -- and those strings are exactly what
appears in a CIS `Audit:` section or a STIG check. Lexical and dense retrieval
each get the half they are good at.

WHEN this runs matters as much as what it sends:

    authoring   fields --> probes --> RAG --> proposals --> HUMAN --> rules/*.yaml
    assessment  config --> readers --> SBM --> engine(rules) --> findings

Retrieval sits entirely in the top line. It runs once per field, not once per
device, and a person approves its output before any device is judged. The
bottom line is deterministic YAML evaluation: same config in, same findings out,
every time. That is what makes a report defensible.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field as dc_field
from pathlib import Path

from ..schema.sbm import FIELD_TYPES

# Vocabulary that turns a dotted path into something a framework would say.
_EXPAND = {
    "http": "http web browser administrative interface plaintext unencrypted",
    "https": "https tls encrypted web administrative interface",
    "ssh": "ssh secure shell remote administrative access",
    "telnet": "telnet plaintext unencrypted remote access protocol",
    "snmp": "snmp simple network management protocol community string monitoring",
    "aaa": "aaa authentication authorization accounting centralised identity",
    "mfa": "multi-factor two-factor authentication token",
    "vty": "vty virtual terminal line remote console session",
    "banner": "banner login message legal notice warning consent",
    "ntp": "ntp network time protocol clock synchronisation timestamp",
    "syslog": "syslog remote logging collector audit record",
    "logging": "logging audit records event log retention",
    "lockout": "account lockout failed login attempts threshold",
    "timeout": "idle session timeout automatic disconnect inactivity",
    "crypto": "cryptography cipher algorithm key exchange encryption strength",
    "ciphers": "weak deprecated cipher algorithm des md5 sha1 rc4",
    "exposure": "exposed reachable from the internet public network untrusted",
    "firewall": "firewall access control list rule policy permit deny",
    "enabled": "enabled disabled turned on off configured",
    "version": "protocol version supported deprecated",
    "password": "password credential complexity minimum length policy",
    "accounts": "user account emergency break glass credential",
    "role": "role based access control least privilege separation of duties",
}


@dataclass
class Probe:
    """One retrieval unit: an SBM field, expressed so a framework can match it."""

    field: str
    domain: str
    value_type: str
    vendor_syntax: list = dc_field(default_factory=list)
    observed_values: list = dc_field(default_factory=list)

    @property
    def intent(self) -> str:
        return " ".join(p.replace("_", " ") for p in self.field.split("."))

    def query_text(self, *, with_syntax: bool = True) -> str:
        """What actually goes to BM25 and to the embedder."""
        parts = [self.intent]
        for tok in self.field.replace(".", "_").split("_"):
            if tok in _EXPAND:
                parts.append(_EXPAND[tok])
        if with_syntax:
            parts += [v["raw"] for v in self.vendor_syntax if v.get("raw")]
        return " ".join(parts)

    def to_json(self) -> dict:
        return {"field": self.field, "domain": self.domain,
                "value_type": self.value_type, "intent": self.intent,
                "vendor_syntax": self.vendor_syntax,
                "observed_values": self.observed_values,
                "query_text": self.query_text()}


@dataclass
class MappingProposal:
    """A candidate framework label for one SBM field. NOT yet a mapping.

    ``status`` starts PROPOSED and only a human moves it to APPROVED, at which
    point it is written into rules/*.yaml and retrieval is out of the loop
    forever. Plan 10.2: an approval is scoped and recorded, never implicit.
    """

    field: str
    framework: str
    control_id: str
    source_document: str
    score: float
    retrieval: dict
    title: str = None
    platform: str = None
    automatable: str = "unknown"
    status: str = "PROPOSED"
    approved_by: str = None

    def to_json(self, *, licensed_ok: bool = False) -> dict:
        d = {"field": self.field, "framework": self.framework,
             "control_id": self.control_id,
             "source_document": self.source_document,
             "citation": f"{self.source_document} - {self.control_id}",
             "score": round(self.score, 5), "retrieval": self.retrieval,
             "platform": self.platform, "automatable": self.automatable,
             "status": self.status, "approved_by": self.approved_by}
        # CIS/ISO titles are copyrighted: they help a local reviewer and must
        # not travel. guard.py enforces this on the file sinks.
        d["title"] = self.title if licensed_ok else None
        return d


def _literalise(rx):
    """Recover the literal command from a pack regex.

    `^(no )?ip http server\s*$` -> `no ip http server`. This matters more than
    it looks: that exact string is what a CIS `Audit:` section and a STIG check
    text contain, so it is the highest-precision term we can put in a query.
    Dropping it -- which the first version did, by reading only `path` -- left
    every Cisco field retrieving on generic words alone.

    Scanned character by character rather than with a regex-over-regexes: the
    escaping needed to match a literal backslash-s inside a pattern is exactly
    the kind of thing that silently half-works and leaves a stray "s" behind.
    """
    out, i, n = [], 0, len(rx)
    while i < n:
        c = rx[i]
        if c == "\\":                       # an escape: drop it and its letter
            i += 2
            if i < n and rx[i] in "*+?":     # ...and any quantifier
                i += 1
            continue
        if c == "[":                        # a character class: drop entirely
            j = rx.find("]", i + 1)
            i = n if j < 0 else j + 1
            if i < n and rx[i] in "*+?":
                i += 1
            continue
        if c in "^$*+?(){}|":
            i += 1
            continue
        out.append(c)
        i += 1
    return " ".join("".join(out).replace("?:", " ").split())


def probes_from_packs(packs_dir="packs", sbm=None):
    """Build one probe per SBM field, pooling vendor syntax across all packs."""
    from ..paths import resolve_packs_dir
    from ..readers.pack import load_pack

    by_field = {}
    for p in sorted(resolve_packs_dir(packs_dir).glob("*.yaml")):
        try:
            pack = load_pack(p)
        except Exception:                              # noqa: BLE001
            continue
        for m in pack.mappings:
            if m.path:
                raw = m.path
            elif m.regex:
                raw = _literalise(m.regex)
                if m.parent:                 # `transport input` under `line vty`
                    raw = f"{_literalise(m.parent)} {raw}".strip()
            elif m.jsonpath:
                raw = m.jsonpath.replace("$.", "").replace("[*]", " ")
            elif m.const is not None:
                raw = f"const:{m.const}"
            else:
                continue
            if not raw.strip():
                continue
            base = m.field.split("[")[0]
            pr = by_field.get(base)
            if pr is None:
                pr = by_field[base] = Probe(
                    field=base, domain=base.split(".")[0],
                    value_type=FIELD_TYPES.get(base, "str"))
            pr.vendor_syntax.append(
                {"vendor": pack.vendor, "platform": pack.platform, "raw": raw})

    if sbm is not None:
        for pr in by_field.values():
            try:
                obs = sbm.get(pr.field)
            except Exception:                          # noqa: BLE001
                obs = None
            if obs is not None and getattr(obs, "value", None) is not None:
                pr.observed_values = [obs.value]
    return sorted(by_field.values(), key=lambda p: p.field)
