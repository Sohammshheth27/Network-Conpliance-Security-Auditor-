"""Apply an approved mapping -- and refuse it if it breaks what already worked.

THE GAP THIS CLOSES. `MappingRegistry.approve()` hash-chains a decision and
`RegressionGuard` re-runs a corpus, but an entry in the registry changed
nothing about how a device was parsed: no reader consulted it. The guard would
therefore have compared identical before/after snapshots and allowed anything.
A gate that cannot fail is not a gate.

So an approval WRITES. It appends to `packs/<platform>.learned.yaml`, a file
the pipeline merges into the hand-authored pack at load time. Three properties
follow, and each was chosen over an easier alternative:

  * LEARNED MAPPINGS ARE SEPARATE from hand-authored ones. Appending to
    `cisco.yaml` would mix machine proposals into a file a human owns, and
    reverting would mean editing around them.
  * THE WRITE HAPPENS BEFORE THE CHECK, and is reverted if the check fails.
    Evaluating a hypothetical is not possible here: the only honest way to
    know what a mapping does to 35 verified results is to run them with it.
  * A BLOCKED APPROVAL LEAVES NOTHING BEHIND -- no file change, no registry
    entry. Otherwise the gate itself becomes a way to poison the tool.

Poisoning always makes things look BETTER, so a rise in the corpus pass rate is
reported even when nothing broke.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field as dc_field
from pathlib import Path

import yaml

from ..schema.sbm import FIELD_TYPES

PACKS_DIR = Path("packs")
LEARNED_SUFFIX = ".learned.yaml"

HEADER = (
    "# LEARNED MAPPINGS -- written by approvals in the training interface.\n"
    "# Not hand-authored. Every entry passed the golden corpus at the moment\n"
    "# it was approved, and carries who approved it and when.\n"
    "# Safe to delete: the device simply returns to its pre-approval coverage.\n"
)


@dataclass
class ApprovalResult:
    accepted: bool
    reason: str = ""
    broken: list = dc_field(default_factory=list)
    detail: list = dc_field(default_factory=list)
    pass_rate_before: float = 0.0
    pass_rate_after: float = 0.0
    direction_alert: bool = False
    registry_version: str = ""

    def to_json(self) -> dict:
        return {"accepted": self.accepted, "reason": self.reason,
                "broken": self.broken, "detail": self.detail,
                "pass_rate_before": round(self.pass_rate_before, 2),
                "pass_rate_after": round(self.pass_rate_after, 2),
                "direction_alert": self.direction_alert}


def learned_path(platform: str) -> Path:
    return PACKS_DIR / f"{platform}{LEARNED_SUFFIX}"


def _mapping_entry(setting_name: str, field: str, reader: str,
                   value_hint=None) -> dict:
    """Express one approval in the pack's own dialect.

    A path reader addresses a setting by name; an indented reader matches a
    line. Writing the wrong dialect produces a mapping that silently never
    matches -- which would look exactly like an approval that did nothing.
    """
    entry: dict = {"field": field}
    target = FIELD_TYPES.get(field, "str")

    if reader in ("sonicos_exp", "json", "braces", "fortinet_block", "block",
                  "xml"):
        # Path readers address a setting by name; the value arrives with it.
        entry["path"] = setting_name
        if target != "str":
            entry["value"] = {"as": target}
        return entry

    # A LINE reader must CAPTURE the value it claims to coerce. The first
    # version emitted `^console timeout\b` with `as: int` and no capture
    # group, so the extractor fell back to the whole line and tried to coerce
    # "console timeout 0" to an integer -- UNPARSED, on the very setting the
    # approval had just claimed to teach.
    if target == "bool":
        # For a flag, the PRESENCE of the directive is the whole signal.
        entry["regex"] = f"^{re.escape(setting_name)}\\b"
        entry["value"] = {"const": True}
    else:
        entry["regex"] = f"^{re.escape(setting_name)}\\s+(\\S+)"
        entry["value"] = {"group": 1, "as": target}
    return entry


def write_learned(platform: str, setting_name: str, field: str, reader: str,
                  approved_by: str, value_hint=None) -> dict:
    """Append one learned mapping. Returns the file's previous text for revert."""
    p = learned_path(platform)
    before = p.read_text(encoding="utf-8") if p.exists() else None

    doc = yaml.safe_load(before) if before else None
    if not doc:
        doc = {"vendor": "learned", "platform": platform, "reader": reader,
               "version": "learned", "mappings": []}
    doc.setdefault("mappings", [])

    entry = _mapping_entry(setting_name, field, reader, value_hint)
    entry["_approved_by"] = approved_by
    entry["_setting"] = setting_name
    doc["mappings"] = [m for m in doc["mappings"]
                       if m.get("_setting") != setting_name] + [entry]

    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(HEADER + yaml.safe_dump(doc, sort_keys=False,
                                         allow_unicode=True),
                 encoding="utf-8")
    return {"path": p, "before": before}


def revert_learned(snapshot) -> None:
    p, before = snapshot["path"], snapshot["before"]
    if before is None:
        p.unlink(missing_ok=True)
    else:
        p.write_text(before, encoding="utf-8")


def corpus_snapshot() -> dict:
    """{case: {control_id: state}} for every golden case on this machine."""
    from ..corpus.golden import load_golden, run_case

    out = {}
    for case in load_golden():
        if not Path(case["config"]).exists():
            continue
        out[case["name"]] = {cid: st for cid, (st, _ev)
                             in run_case(case).items()}
    return out


def _verified_expectations() -> dict:
    from ..corpus.golden import load_golden

    out = {}
    for case in load_golden():
        exp = {}
        for cid, spec in (case.get("controls") or {}).items():
            exp[cid] = spec["expect"] if isinstance(spec, dict) else spec
        out[case["name"]] = exp
    return out


def _pass_rate(snapshot: dict) -> float:
    total = passed = 0
    for results in snapshot.values():
        for state in results.values():
            if state in ("PASS", "FAIL", "PARTIAL"):
                total += 1
                passed += state == "PASS"
    return 100.0 * passed / total if total else 0.0


def approve(setting_name: str, field: str, platform: str, approved_by: str,
            *, value_hint=None, registry=None, force=False) -> ApprovalResult:
    """The gate. Nothing commits unless the golden corpus still holds."""
    if field not in FIELD_TYPES:
        return ApprovalResult(
            False, f"{field!r} is not in the schema whitelist")
    if not setting_name.strip():
        return ApprovalResult(False, "no setting name given")
    if not approved_by.strip():
        return ApprovalResult(
            False, "an approval must record who made it")

    from ..pipeline import load_packs

    base = next((p for p in load_packs() if p.platform == platform), None)
    if base is None:
        return ApprovalResult(
            False, f"no pack for platform {platform!r}; a learned mapping "
                   "needs a base pack to attach to")

    before = corpus_snapshot()
    snap = write_learned(platform, setting_name, field, base.reader or "indented",
                         approved_by, value_hint)
    try:
        after = corpus_snapshot()
    except Exception as exc:                           # noqa: BLE001
        revert_learned(snap)
        return ApprovalResult(
            False, f"corpus could not be re-run after the change: {exc}")

    expected = _verified_expectations()
    broken, detail = [], []
    for case, exp in expected.items():
        b, a = before.get(case, {}), after.get(case, {})
        for cid, want in exp.items():
            if a.get(cid) != want and b.get(cid) == want:
                broken.append(f"{case}:{cid}")
                detail.append(
                    f"{case} / {cid}: {want} -> {a.get(cid, 'MISSING')}"
                    + ("   <-- a verified FAIL became a PASS"
                       if want == "FAIL" and a.get(cid) == "PASS" else ""))

    pr_b, pr_a = _pass_rate(before), _pass_rate(after)
    result = ApprovalResult(
        accepted=not broken, broken=broken, detail=detail,
        pass_rate_before=pr_b, pass_rate_after=pr_a,
        # Poisoning always makes things look better, so a rise is reported
        # even when no individual expectation broke.
        direction_alert=pr_a > pr_b + 0.01)

    if broken and not force:
        revert_learned(snap)
        result.reason = (f"blocked: {len(broken)} verified result(s) would "
                         "change. Nothing was written.")
        return result

    if registry is not None:
        try:
            from ..ai.guardrails import Proposal
            ok, problems = registry.approve(
                Proposal(line=setting_name, field=field, value=value_hint,
                         evidence=setting_name, confidence=1.0, tier="human"),
                approved_by=approved_by, platform=platform, force=force)
            if not ok and not force:
                revert_learned(snap)
                result.accepted = False
                result.reason = "; ".join(problems) or "registry refused"
                return result
            result.registry_version = registry.version
        except Exception as exc:                       # noqa: BLE001
            result.reason = f"written, but not hash-chained: {exc}"

    result.reason = result.reason or (
        "approved; the golden corpus still holds"
        + (" (pass rate rose -- worth a look)" if result.direction_alert else ""))
    return result
