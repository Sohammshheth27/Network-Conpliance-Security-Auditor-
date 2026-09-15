"""Compare two assessments of the same device over time.

A one-shot audit answers "is this device compliant". Every commercial product
in this space sells the other question -- "what changed since Tuesday" -- and
that is the one an operations team actually acts on.

THE TRAP THIS AVOIDS, and it is the whole reason this module is careful:

    findings changed  !=  the device changed

If a pack gained a mapping between the two runs, or a control was corrected,
the findings move while the configuration is untouched. Reporting that as
"3 new violations" would be a lie the operator cannot detect, and it would
happen constantly here -- this project changed the Cisco pack twice and a
control's operator once in a single day.

So a comparison records the ANALYSIS VERSION on both sides and separates:

    device_changed    the configuration hash differs
    analysis_changed  the packs or rules differ
    both              a change of each kind; deltas are advisory only

and every finding delta is labelled with which of those it can be attributed
to. Where it cannot be attributed, it says so rather than guessing.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

STORE = Path("corpus/history")


# --------------------------------------------------------------- versioning
def analysis_fingerprint(packs_dir="packs", rules_dir="rules") -> str:
    """A hash of everything that decides an outcome besides the device.

    Packs and rules only. Including the whole source tree would make every
    unrelated edit look like an analysis change, and then nobody would trust
    the distinction that makes this module worth having.
    """
    from ..paths import resolve_packs_dir

    h = hashlib.sha256()
    for d in (resolve_packs_dir(packs_dir), Path(rules_dir)):
        for f in sorted(d.rglob("*.yaml")):
            if f.name.endswith(".learned.yaml"):
                # Learned mappings DO change outcomes, so they are included --
                # an approval is exactly the kind of analysis change an
                # operator needs to see attributed.
                pass
            h.update(f.name.encode())
            h.update(f.read_bytes())
    return h.hexdigest()[:16]


@dataclass
class Snapshot:
    """One assessment, reduced to what a comparison needs."""

    taken_at: str
    device_key: str
    config_sha256: str
    analysis_version: str
    device_keys: list = field(default_factory=list)
    identity: dict = field(default_factory=dict)
    coverage: dict = field(default_factory=dict)
    states: dict = field(default_factory=dict)       # control_id -> state
    observed: dict = field(default_factory=dict)     # control_id -> value
    rules: dict = field(default_factory=dict)        # rule id -> signature
    # framework key -> that framework's own score (average requirement
    # satisfaction). Empty in snapshots taken before this was recorded.
    frameworks: dict = field(default_factory=dict)

    def to_json(self) -> dict:
        return {"taken_at": self.taken_at, "device_key": self.device_key,
                "device_keys": list(self.device_keys),
                "config_sha256": self.config_sha256,
                "analysis_version": self.analysis_version,
                "identity": self.identity, "coverage": self.coverage,
                "states": self.states, "observed": self.observed,
                "rules": self.rules, "frameworks": self.frameworks}

    @staticmethod
    def from_json(d) -> "Snapshot":
        return Snapshot(**d)


def device_identifiers(identity) -> list:
    """EVERY identifier a device exposes, strongest first.

    Not one key. Two exports of a single appliance frequently expose different
    identifiers -- the sanitised SonicWall export in this repo carries the same
    hostname as the original but a zeroed serial, so keying on "serial, else
    hostname" gave them different keys and the change history between them was
    refused.

    Two snapshots are the same device if they share ANY STRONG identifier.
    Filename is recorded but never strong: renaming a file is not a new
    device, and two devices exported to the same name are not one.
    """
    out = []
    if identity.serial:
        out.append(f"serial:{identity.serial}")
    if identity.hostname:
        out.append(f"host:{identity.hostname}")
    out.append(f"file:{identity.source_file}")
    return out


def _device_key(identity) -> str:
    """The strongest single identifier, used for grouping history on disk."""
    return device_identifiers(identity)[0]


def snapshot(device_assessment, *, taken_at=None) -> Snapshot:
    da = device_assessment
    states, observed = {}, {}
    if da.assessment is not None:
        for f in da.assessment.findings:
            states[f.control_id] = f.state.value
            if f.observed is not None:
                observed[f.control_id] = _stable(f.observed)

    rules = {}
    if da.graph is not None:
        for r in getattr(da.graph, "rules", []):
            rules[r.id] = _rule_signature(r)

    frameworks = {}
    if da.assessment is not None:
        from ..frameworks.selection import framework_coverage
        frameworks = {r["framework"]: r["framework_score_pct"]
                      for r in framework_coverage(da.assessment.findings)}

    return Snapshot(
        frameworks=frameworks,
        taken_at=taken_at or datetime.now().replace(microsecond=0).isoformat(),
        device_key=_device_key(da.identity),
        device_keys=device_identifiers(da.identity),
        config_sha256=da.identity.sha256,
        analysis_version=analysis_fingerprint(),
        identity={"vendor": da.identity.vendor, "platform": da.identity.platform,
                  "hostname": da.identity.hostname, "serial": da.identity.serial,
                  "version": da.identity.version},
        coverage=da.coverage(), states=states, observed=observed, rules=rules)


def _rule_signature(r) -> str:
    """Everything about a rule that changes what it permits.

    Hit count is deliberately EXCLUDED: it moves on every packet, and a diff
    that reports 329 changed rules because traffic flowed is a diff nobody
    reads twice.
    """
    return "|".join([
        r.action, str(r.enabled), str(r.order),
        ",".join(sorted(r.source)), ",".join(sorted(r.destination)),
        ",".join(sorted(r.services)),
        ",".join(sorted(r.source_zones or [])),
        ",".join(sorted(r.destination_zones or [])),
    ])


def _stable(v):
    return sorted(str(x) for x in v) if isinstance(v, list) else v


# ---------------------------------------------------------------- the diff
IMPROVED = "improved"
REGRESSED = "regressed"
COVERAGE = "coverage_change"

_RANK = {"FAIL": 0, "PARTIAL": 1, "UNKNOWN": 2, "ERROR": 2,
         "MANUAL_REVIEW": 2, "NOT_APPLICABLE": 3, "PASS": 4}


def _direction(before: str, after: str) -> str:
    """Did a control get better, worse, or merely become knowable?

    UNKNOWN -> PASS is NOT an improvement. The device may be unchanged and our
    coverage simply grew, so calling it a fix would credit the tool for work
    the operator did not do -- and hide the case where coverage grew and
    revealed a genuine failure.
    """
    if before in ("UNKNOWN", "ERROR", "MANUAL_REVIEW") or \
            after in ("UNKNOWN", "ERROR", "MANUAL_REVIEW"):
        return COVERAGE
    return IMPROVED if _RANK[after] > _RANK[before] else REGRESSED


@dataclass
class ControlChange:
    control_id: str
    before: str
    after: str
    direction: str
    observed_before=None
    observed_after=None
    attributable_to: str = "unknown"


@dataclass
class DiffReport:
    device_key: str = ""
    same_device: bool = True
    device_changed: bool = False
    analysis_changed: bool = False
    before_at: str = ""
    after_at: str = ""
    score_before: float | None = None
    score_after: float | None = None
    control_changes: list = field(default_factory=list)
    rules_added: list = field(default_factory=list)
    rules_removed: list = field(default_factory=list)
    rules_modified: list = field(default_factory=list)
    notes: list = field(default_factory=list)
    # framework key -> [score before, score after]
    framework_scores: dict = field(default_factory=dict)

    def by_direction(self, d) -> list:
        return [c for c in self.control_changes if c.direction == d]

    def summary(self) -> dict:
        return {"device_changed": self.device_changed,
                "analysis_changed": self.analysis_changed,
                "score": [self.score_before, self.score_after],
                "frameworks": self.framework_scores,
                "improved": len(self.by_direction(IMPROVED)),
                "regressed": len(self.by_direction(REGRESSED)),
                "coverage_changes": len(self.by_direction(COVERAGE)),
                "rules": {"added": len(self.rules_added),
                          "removed": len(self.rules_removed),
                          "modified": len(self.rules_modified)}}

    def explain(self) -> str:
        out = [f"{self.before_at}  ->  {self.after_at}"]
        if not self.same_device:
            return "\n".join(out + ["REFUSED: these are different devices."])
        if self.device_changed and self.analysis_changed:
            out.append("BOTH the configuration and the analysis changed. "
                       "Control deltas below cannot be attributed to either "
                       "and are ADVISORY -- re-run the older config against "
                       "the current analysis to separate them.")
        elif self.analysis_changed and not self.device_changed:
            out.append("The configuration is IDENTICAL. Every change below is "
                       "ours -- a pack, rule or approval changed what we can "
                       "see, not what the device does.")
        elif self.device_changed:
            out.append("The configuration changed; the analysis did not. "
                       "Every change below is the device.")
        else:
            out.append("Nothing changed: same configuration, same analysis.")

        if self.score_before is not None and self.score_after is not None:
            out.append(f"score {self.score_before}% -> {self.score_after}%")
        for fw, (b, a) in sorted(self.framework_scores.items()):
            if b != a and b is not None and a is not None:
                out.append(f"  {fw} score {b}% -> {a}%")
        for c in self.by_direction(REGRESSED):
            out.append(f"  WORSE  {c.control_id}: {c.before} -> {c.after}")
        for c in self.by_direction(IMPROVED):
            out.append(f"  better {c.control_id}: {c.before} -> {c.after}")
        for c in self.by_direction(COVERAGE)[:5]:
            out.append(f"  coverage {c.control_id}: {c.before} -> {c.after}")
        for r in self.rules_added[:5]:
            out.append(f"  RULE ADDED    {r}")
        for r in self.rules_removed[:5]:
            out.append(f"  RULE REMOVED  {r}")
        for r in self.rules_modified[:5]:
            out.append(f"  RULE CHANGED  {r}")
        return "\n".join(out)


def compare(before: Snapshot, after: Snapshot) -> DiffReport:
    # Any shared STRONG identifier means one device. Filename is excluded:
    # a rename is not a new device, and a shared name is not one device.
    strong_b = {k for k in (before.device_keys or [before.device_key])
                if not k.startswith("file:")}
    strong_a = {k for k in (after.device_keys or [after.device_key])
                if not k.startswith("file:")}
    rep = DiffReport(
        device_key=after.device_key,
        same_device=bool(strong_b & strong_a)
        or before.device_key == after.device_key,
        device_changed=before.config_sha256 != after.config_sha256,
        analysis_changed=before.analysis_version != after.analysis_version,
        before_at=before.taken_at, after_at=after.taken_at,
        score_before=before.coverage.get("score_pct"),
        score_after=after.coverage.get("score_pct"),
        # Only frameworks recorded on BOTH sides: a snapshot from before
        # framework scores were kept has none, and a missing value is not 0.
        framework_scores={k: [before.frameworks.get(k), after.frameworks.get(k)]
                          for k in sorted(set(before.frameworks or {})
                                          & set(after.frameworks or {}))})

    if not rep.same_device:
        rep.notes.append(
            f"different devices: {before.device_key} vs {after.device_key}. "
            "A diff between two devices is not a change history.")
        return rep

    attribution = ("device" if rep.device_changed and not rep.analysis_changed
                   else "analysis" if rep.analysis_changed and not rep.device_changed
                   else "ambiguous" if rep.device_changed
                   else "neither")

    for cid in sorted(set(before.states) | set(after.states)):
        b, a = before.states.get(cid), after.states.get(cid)
        if b == a or b is None or a is None:
            continue
        c = ControlChange(control_id=cid, before=b, after=a,
                          direction=_direction(b, a),
                          attributable_to=attribution)
        c.observed_before = before.observed.get(cid)
        c.observed_after = after.observed.get(cid)
        rep.control_changes.append(c)

    for rid in sorted(set(before.rules) | set(after.rules)):
        b, a = before.rules.get(rid), after.rules.get(rid)
        if b is None:
            rep.rules_added.append(rid)
        elif a is None:
            rep.rules_removed.append(rid)
        elif b != a:
            rep.rules_modified.append(rid)
    return rep


# -------------------------------------------------------------- persistence
def save(snap: Snapshot, store=STORE) -> Path:
    d = Path(store) / _safe(snap.device_key)
    d.mkdir(parents=True, exist_ok=True)
    p = d / f"{snap.taken_at.replace(':', '-')}.json"
    p.write_text(json.dumps(snap.to_json(), indent=1), encoding="utf-8")
    return p


def history(device_key: str, store=STORE) -> list:
    d = Path(store) / _safe(device_key)
    if not d.is_dir():
        return []
    out = []
    for f in sorted(d.glob("*.json")):
        try:
            out.append(Snapshot.from_json(json.loads(f.read_text(encoding="utf-8"))))
        except Exception:                              # noqa: BLE001
            continue
    return out


def _safe(key: str) -> str:
    import re
    return re.sub(r"[^A-Za-z0-9._-]", "_", key)


def compare_latest(device_assessment, *, store=STORE) -> DiffReport | None:
    """Snapshot this assessment and diff it against the previous one."""
    snap = snapshot(device_assessment)
    prior = history(snap.device_key, store)
    save(snap, store)
    if not prior:
        return None
    return compare(prior[-1], snap)
