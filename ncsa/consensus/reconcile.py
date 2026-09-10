"""Reconcile universal detections against pack observations."""
from __future__ import annotations

from dataclasses import dataclass, field

from ..schema.enums import ResultState

CONFIRMED = "CONFIRMED"
DISPUTED = "DISPUTED"
UNCORROBORATED = "UNCORROBORATED"

# What a pack observation must look like for it to CONFIRM a universal
# detection of insecurity, per detector. Written as a predicate on the
# observed value, because "insecure" is spelled differently per field: a bool
# false for password encryption, a non-empty list for weak ciphers.
_CONFIRMS = {
    "cleartext_credential": lambda v: v is False,
    "telnet_enabled": lambda v: v is True,
    "cleartext_http_mgmt": lambda v: v is True,
    "weak_crypto": lambda v: bool(v) if isinstance(v, list) else v is True,
    "snmp_v1_v2c": lambda v: str(v).lower() in ("1", "v1", "2c", "v2c", "2"),
    "default_snmp_community": lambda v: bool(v) if isinstance(v, list) else bool(v),
    "any_any_permit": lambda v: str(v).lower() in ("permit", "allow", "accept"),
    "ftp_enabled": lambda v: bool(v),
}

# Field-specific, and checked first. The presence of ANY v1/v2c community
# confirms "a community string traverses the network in cleartext" -- which is
# a different question from whether its NAME is a default one, and the pack can
# legitimately pass the second while the detector correctly flags the first.
_CONFIRMS_BY_FIELD = {
    "snmp.communities": lambda v: bool(v),
    "crypto.ipsec_proposals": lambda v: bool(v),
    "crypto.weak_ciphers": lambda v: bool(v),
}


@dataclass
class Consensus:
    """One security fact, as seen by every method that could see it."""

    verdict: str
    detector: str
    field: str
    line: int
    evidence: str
    universal_says: str
    pack_says: str = "(no mapping for this field)"
    pack_state: str = ""
    confidence: float = 0.8
    note: str = ""

    def to_json(self) -> dict:
        return {"verdict": self.verdict, "detector": self.detector,
                "field": self.field, "line": self.line,
                "evidence": self.evidence, "universal": self.universal_says,
                "pack": self.pack_says, "pack_state": self.pack_state,
                "confidence": self.confidence, "note": self.note}


@dataclass
class ConsensusReport:
    items: list = field(default_factory=list)
    pack_only: int = 0
    coverage_gaps: list = field(default_factory=list)

    def by_verdict(self, verdict: str) -> list:
        return [i for i in self.items if i.verdict == verdict]

    @property
    def dispute_rate(self) -> float:
        """Rising disputes mean a layer has drifted. Visible before a customer
        sees a report, which is the point of measuring it."""
        n = len(self.items)
        return round(100 * len(self.by_verdict(DISPUTED)) / n, 1) if n else 0.0

    def summary(self) -> dict:
        return {"total": len(self.items),
                "confirmed": len(self.by_verdict(CONFIRMED)),
                "disputed": len(self.by_verdict(DISPUTED)),
                "uncorroborated": len(self.by_verdict(UNCORROBORATED)),
                "dispute_rate_pct": self.dispute_rate,
                "pack_coverage_gaps": len(self.coverage_gaps)}

    def explain(self) -> str:
        out = []
        for i in self.items:
            out.append(f"[{i.verdict}] L{i.line} {i.detector} ({i.confidence:.2f})")
            out.append(f"    evidence : {i.evidence[:70]}")
            out.append(f"    universal: {i.universal_says}")
            out.append(f"    pack     : {i.pack_says}")
            if i.note:
                out.append(f"    note     : {i.note}")
        return "\n".join(out)


def _pack_view(device_assessment, field_path: str):
    """What the pack concluded about one SBM field, if anything."""
    a = device_assessment.assessment
    if a is None or not field_path:
        return None
    for f in a.findings:
        if f.field == field_path:
            return f
    return None


def reconcile(device_assessment, universal_findings) -> ConsensusReport:
    """Cross-check every universal detection against the pack's own answer."""
    report = ConsensusReport()

    for u in universal_findings:
        pack = _pack_view(device_assessment, u.field_hint)
        item = Consensus(
            verdict=UNCORROBORATED, detector=u.detector, field=u.field_hint,
            line=u.line, evidence=u.raw.strip(),
            universal_says=f"{u.title} (matched {u.matched!r})",
            confidence=u.confidence)

        if pack is None:
            item.note = (
                "no pack mapping covers this field, so nothing could confirm "
                "or refute it. This is a pack coverage gap with a line number.")
            report.coverage_gaps.append(
                f"L{u.line} {u.detector}: {u.raw.strip()[:60]}")
            report.items.append(item)
            continue

        item.pack_state = pack.state.value
        item.pack_says = f"{pack.field} = {pack.observed!r} [{pack.state.value}]"

        # A pack that could not decide is not a contradiction.
        if pack.state in (ResultState.UNKNOWN, ResultState.NOT_APPLICABLE,
                          ResultState.MANUAL_REVIEW):
            item.note = ("the pack could not decide this field, so the "
                         "detection stands uncorroborated rather than disputed")
            report.items.append(item)
            continue

        # Keyed on the FIELD first, then the detector. `cleartext_credential`
        # emits different hints depending on which credential it matched, and
        # "insecure" is spelled differently per field: false for password
        # encryption, but a NON-EMPTY LIST for snmp.communities. Keying on the
        # detector alone applied `v is False` to a list of community strings,
        # which never matches -- so a correctly detected cleartext community
        # was reported as a dispute with a pack that agreed with it.
        confirms = _CONFIRMS_BY_FIELD.get(u.field_hint) or _CONFIRMS.get(u.detector)
        agrees = bool(confirms(pack.observed)) if confirms else \
            pack.state is ResultState.FAIL

        if agrees:
            item.verdict = CONFIRMED
            item.confidence = 1.0
            item.note = ("two independent methods agree; the pack read the "
                         "grammar and the detector read the vocabulary")
        else:
            item.verdict = DISPUTED
            # Deliberately NOT resolved here. In this project's own data the
            # dispute went both ways inside one run: once the detector's field
            # hint was wrong (an SNMP community is not a stored password), and
            # once the PACK was blind (it read SSH ciphers only, and missed
            # `auth md5 ... priv 3des` on an SNMPv3 user). A rule that
            # suppressed either side would have hidden a real weakness.
            item.confidence = 0.5
            item.note = ("the pack and the detector disagree -- either the "
                         "detector matched the wrong context, or the pack is "
                         "blind to this setting. Both are worth a look; "
                         "neither is suppressed.")
        report.items.append(item)

    # Findings the pack raised that no detector has vocabulary for. Normal, and
    # counted so the ratio between the layers is visible.
    a = device_assessment.assessment
    if a is not None:
        seen = {i.field for i in report.items}
        report.pack_only = sum(
            1 for f in a.findings
            if f.state is ResultState.FAIL and f.field not in seen)
    return report
