"""Risk severity for a finding -- deliverable 4, "risk severity assessments".

A framework severity alone is not risk. CIS rates "administrative interface
uses HTTP" the same on every device in the world, because a benchmark cannot
know your topology. On the SonicWall in this repo that difference is not
academic: the same control is a genuine internet-facing exposure on six WAN
interfaces and an irrelevance on the unconfigured M0 management port.

So risk here is the framework severity ADJUSTED by what the object graph
proves about this specific device:

    risk = base(severity) x exposure x confidence

  base        the control's own severity  (10 / 6 / 3 / 1)
  exposure    1.5 if the affected service is reachable from an untrusted zone,
              1.0 if it is internal, 0.6 if the graph shows it unreachable
  confidence  1.0 for a value we parsed, 0.7 for one we inferred

Two properties are deliberate:

  * Exposure can only be applied when the graph actually proves it. With no
    graph the multiplier is 1.0 -- absence of evidence never becomes a
    discount, or a device we could not model would score safer than one we
    could.
  * A finding whose evidence is weak is scored DOWN, not up. A tool that
    inflates uncertain findings trains its users to ignore it.
"""
from __future__ import annotations

from dataclasses import dataclass

from ..schema.enums import ResultState, Severity

# Framework severity -> base points. Matches Severity's own weights.
BASE = {Severity.CRITICAL: 10.0, Severity.HIGH: 6.0,
        Severity.MEDIUM: 3.0, Severity.LOW: 1.0}

EXPOSURE_INTERNET = 1.5
EXPOSURE_INTERNAL = 1.0
EXPOSURE_UNREACHABLE = 0.6

CONF_OBSERVED = 1.0
CONF_INFERRED = 0.7


@dataclass
class Risk:
    score: float
    band: str
    base: float
    exposure: float
    confidence: float
    rationale: list

    def to_json(self) -> dict:
        return {"score": round(self.score, 1), "band": self.band,
                "base": self.base, "exposure": self.exposure,
                "confidence": self.confidence, "rationale": self.rationale}


def band_of(score: float) -> str:
    if score >= 12:
        return "CRITICAL"
    if score >= 7:
        return "HIGH"
    if score >= 3:
        return "MEDIUM"
    return "LOW"


def _exposure_for(finding, graph) -> tuple[float, str]:
    """What the graph proves about reachability of this finding's subject."""
    if graph is None:
        return EXPOSURE_INTERNAL, "no object graph for this platform; exposure not adjusted"

    untrusted = {z.lower() for z in getattr(graph, "untrusted_zones", set())}
    if not untrusted:
        return EXPOSURE_INTERNAL, "graph declares no untrusted zones"

    # A finding about the firewall policy itself is judged by whether any
    # enabled allow rule reaches it from an untrusted zone.
    fields = getattr(finding, "field", "") or (finding.control_id or "")
    if "exposure" in fields or "firewall" in fields:
        for rule in getattr(graph, "rules", []):
            if not rule.enabled or rule.action.lower() not in ("allow", "accept", "permit"):
                continue
            if any(z.lower() in untrusted for z in (rule.source_zones or [])):
                return EXPOSURE_INTERNET, "reachable from an untrusted zone in the policy"
        return EXPOSURE_UNREACHABLE, "no enabled allow rule from an untrusted zone"

    # Management-plane findings: exposed if management is permitted inbound.
    if "management" in fields or "snmp" in fields or "banner" in fields:
        for rule in getattr(graph, "rules", []):
            if rule.enabled and any(z.lower() in untrusted
                                    for z in (rule.source_zones or [])):
                return EXPOSURE_INTERNET, "management plane sits behind an untrusted-zone rule"
    return EXPOSURE_INTERNAL, "no untrusted-zone path proven for this control"


def _confidence_for(finding) -> tuple[float, str]:
    """The engine already carries a confidence; risk inherits it rather than
    recomputing. A finding with no evidence attached was not read off the
    device, so it is scored down."""
    conf = float(getattr(finding, "confidence", 1.0) or 1.0)
    if not getattr(finding, "evidence", None):
        return min(conf, CONF_INFERRED), "no evidence anchor; value not directly observed"
    if conf < CONF_OBSERVED:
        return conf, f"engine confidence {conf:.2f}"
    return CONF_OBSERVED, "value observed in the configuration"


def score_finding(finding, *, graph=None) -> Risk | None:
    """Risk for one FAIL. Returns None for anything that is not a failure.

    Only a FAIL carries risk. A PARTIAL is scored at half base -- it is a real
    but incomplete deviation. UNKNOWN deliberately carries NO risk score: we do
    not know whether it is a problem, and a number would imply we did.
    """
    state = getattr(finding, "state", None)
    if state not in (ResultState.FAIL, ResultState.PARTIAL):
        return None

    sev = getattr(finding, "severity", None) or Severity.MEDIUM
    base = BASE.get(sev, 3.0)
    if state is ResultState.PARTIAL:
        base /= 2

    exposure, why_exp = _exposure_for(finding, graph)
    conf, why_conf = _confidence_for(finding)
    score = base * exposure * conf
    return Risk(score=score, band=band_of(score), base=base, exposure=exposure,
                confidence=conf,
                rationale=[f"severity {getattr(sev, 'value', sev)} -> base {base}",
                           f"exposure x{exposure}: {why_exp}",
                           f"confidence x{conf}: {why_conf}"])


def score_assessment(device_assessment) -> dict:
    """Risk-rank every failure on a device, worst first."""
    graph = getattr(device_assessment, "graph", None)
    scored = []
    for f in device_assessment.failures():
        r = score_finding(f, graph=graph)
        if r is not None:
            scored.append((f, r))
    scored.sort(key=lambda fr: -fr[1].score)

    bands: dict[str, int] = {}
    for _f, r in scored:
        bands[r.band] = bands.get(r.band, 0) + 1
    return {
        "findings": scored,
        "bands": bands,
        "total_risk": round(sum(r.score for _f, r in scored), 1),
        "worst": scored[0][1].band if scored else None,
    }
