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
    from ..paths import resolve_packs_dir

    return resolve_packs_dir(PACKS_DIR) / f"{platform}{LEARNED_SUFFIX}"


#: A pack taught entirely through the training interface, with no authored
#: pack beneath it. The loader treats it as a pack in its own right.
BOOTSTRAP_VERSION = "learned-bootstrap"
BOOTSTRAP_READERS = ("json", "xml", "braces", "indented", "block", "fortinet_block")
DECISIONS_PATH = Path("reference/training_decisions.jsonl")
_SLUG = re.compile(r"^[a-z][a-z0-9_]{1,40}$")
_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _jsonpath(setting_name: str) -> str:
    """`DEVICE_METADATA.*.hostname` -> `$.DEVICE_METADATA.*.hostname`.

    Segments that are not plain identifiers are quoted, so a table named
    `MY-TABLE` addresses correctly instead of silently matching nothing.
    """
    parts = []
    for seg in setting_name.split("."):
        parts.append(seg if seg == "*" or _IDENT.match(seg) else f"'{seg}'")
    return "$." + ".".join(parts)


def validate_bootstrap(platform: str, vendor, reader, signature) -> str | None:
    """Why a new-vendor pack cannot be created, or None if it can."""
    if not (vendor and str(vendor).strip()):
        return ("no pack exists for this platform yet. Teaching a NEW vendor "
                "needs its vendor name, a platform id, the file format and a "
                "signature that recognises its files")
    if not _SLUG.match(platform or "") or platform.lower() == "unknown":
        return ("platform id must be lower-case letters, digits and "
                "underscores, e.g. acme_os -- and cannot be 'unknown'")
    if reader not in BOOTSTRAP_READERS:
        return f"file format must be one of {', '.join(BOOTSTRAP_READERS)}"
    sig = [str(s) for s in (signature or []) if str(s).strip()]
    if not sig:
        return ("a signature is required: without one, the next upload of "
                "this vendor would not be recognised and would be refused again")
    for s in sig:
        if reader == "json":
            if not s.startswith("$."):
                return f"JSON signature {s!r} must be a JSONPath, e.g. $.DEVICE_METADATA"
        else:
            try:
                re.compile(s)
            except re.error as exc:
                return f"signature {s!r} is not a valid regular expression: {exc}"
            if len(s.strip("^$ \\b")) < 6:
                return f"signature {s!r} is too short to identify one vendor safely"
    return None


def _mapping_entry(setting_name: str, field: str, reader: str,
                   value_hint=None, kind: str = "value") -> dict:
    """Express one approval in the pack's own dialect.

    A path reader addresses a setting by name; an indented reader matches a
    line. Writing the wrong dialect produces a mapping that silently never
    matches -- which would look exactly like an approval that did nothing.
    """
    entry: dict = {"field": field}
    target = FIELD_TYPES.get(field, "str")

    if reader == "json":
        # The JSON reader reads `jsonpath:`. Writing `path:` here -- which the
        # first version did for every path-style reader -- produced a mapping
        # the JSON reader ignores: an approval that reported success and
        # changed nothing, on every AWS, Azure and GCP device.
        entry["jsonpath"] = _jsonpath(setting_name)
        if kind == "keys":
            entry["value"] = {"from": "keys"}
        return entry

    if reader in ("sonicos_exp", "braces", "fortinet_block", "block", "xml"):
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
                  approved_by: str, value_hint=None, *, kind: str = "value",
                  bootstrap: dict | None = None) -> dict:
    """Append one learned mapping. Returns the file's previous text for revert.

    With `bootstrap` ({vendor, signature}) and no file yet, the file is
    created as a standalone pack: the vendor's first pack, taught entirely
    through the training interface.
    """
    p = learned_path(platform)
    before = p.read_text(encoding="utf-8") if p.exists() else None

    doc = yaml.safe_load(before) if before else None
    if not doc:
        if bootstrap:
            doc = {"vendor": bootstrap["vendor"], "platform": platform,
                   "reader": reader, "version": BOOTSTRAP_VERSION,
                   "fingerprint": list(bootstrap["signature"]),
                   "mappings": []}
        else:
            doc = {"vendor": "learned", "platform": platform, "reader": reader,
                   "version": "learned", "mappings": []}
    doc.setdefault("mappings", [])

    entry = _mapping_entry(setting_name, field, reader, value_hint, kind=kind)
    entry["_approved_by"] = approved_by
    entry["_setting"] = setting_name
    doc["mappings"] = [m for m in doc["mappings"]
                       if m.get("_setting") != setting_name] + [entry]
    if doc.get("version") == BOOTSTRAP_VERSION:
        # Documentary: the domains this taught pack now speaks for. Every
        # other domain stays UNKNOWN -- we have not been taught it.
        doc["supported_domains"] = sorted({m["field"].split(".")[0]
                                           for m in doc["mappings"]})

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
            *, value_hint=None, registry=None, force=False,
            vendor: str | None = None, reader: str | None = None,
            signature: list | None = None, kind: str = "value") -> ApprovalResult:
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
    bootstrap = None
    if base is None:
        # A vendor the tool has never seen. The approval creates its first
        # pack -- but only with enough to recognise the NEXT file from this
        # vendor, or the device would simply be refused again.
        problem = validate_bootstrap(platform, vendor, reader, signature)
        if problem:
            return ApprovalResult(False, problem)
        bootstrap = {"vendor": str(vendor).strip(),
                     "signature": [str(s) for s in signature if str(s).strip()]}
        reader_used = reader
    else:
        reader_used = base.reader or "indented"

    before = corpus_snapshot()
    snap = write_learned(platform, setting_name, field, reader_used,
                         approved_by, value_hint, kind=kind, bootstrap=bootstrap)
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


# ------------------------------------------------------------ decisions

def reject(setting_name: str, platform: str, rejected_by: str,
           reason: str = "") -> dict:
    """Record that a person looked at a setting and declined to map it.

    Kept apart from the mapping registry: a rejection changes no pack and no
    result, so it needs no regression gate -- but it must be attributable,
    and it takes the setting out of the queue for good.
    """
    import json
    from datetime import datetime, timezone

    if not setting_name.strip() or not rejected_by.strip():
        raise ValueError("a rejection needs the setting and who rejected it")
    rec = {"setting": setting_name, "platform": platform,
           "decision": "REJECTED", "by": rejected_by, "reason": reason,
           "at": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    DECISIONS_PATH.parent.mkdir(parents=True, exist_ok=True)
    with DECISIONS_PATH.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(rec) + "\n")
    return rec


def decisions() -> dict:
    """{platform: {setting names rejected}}."""
    import json

    out: dict = {}
    if not DECISIONS_PATH.exists():
        return out
    for line in DECISIONS_PATH.read_text(encoding="utf-8").splitlines():
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        if rec.get("decision") == "REJECTED":
            out.setdefault(rec.get("platform", ""), set()).add(rec.get("setting", ""))
    return out


def learned_settings(platform: str) -> set:
    p = learned_path(platform)
    if not p.exists():
        return set()
    doc = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    return {m.get("_setting") for m in doc.get("mappings", []) if m.get("_setting")}


def learned_summary() -> dict:
    """Everything the training interface has taught, per platform."""
    out, total = [], 0
    from ..paths import resolve_packs_dir

    for p in sorted(resolve_packs_dir(PACKS_DIR).glob(f"*{LEARNED_SUFFIX}")):
        try:
            doc = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        except Exception:                              # noqa: BLE001
            continue
        maps = doc.get("mappings", []) or []
        total += len(maps)
        out.append({
            "platform": doc.get("platform", p.name[: -len(LEARNED_SUFFIX)]),
            "vendor": doc.get("vendor", ""),
            "new_vendor": doc.get("version") == BOOTSTRAP_VERSION,
            "reader": doc.get("reader", ""),
            "signature": doc.get("fingerprint", []),
            "count": len(maps),
            "mappings": [{"setting": m.get("_setting"), "field": m.get("field"),
                          "approved_by": m.get("_approved_by")} for m in maps],
        })
    return {"total": total, "platforms": out}
