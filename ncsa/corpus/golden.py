"""Load, run and verify the golden corpus.

A golden case is a configuration plus a set of control outcomes a human has
verified by hand, each carrying the evidence that justifies it:

    controls:
      NCSA-TEL-001:
        expect: FAIL
        because: "line 59 -- `transport input telnet ssh` permits telnet"

`because` is not decoration. An expectation without a stated reason cannot be
re-checked by anyone but its author, and an unre-checkable expectation is
indistinguishable from a snapshot of whatever the tool happened to print that
day -- which is exactly the failure this corpus exists to prevent.
"""
from __future__ import annotations

import json
from pathlib import Path

import yaml

GOLDEN_DIR = Path("corpus/golden")
SNAPSHOT_PATH = Path("corpus/mapping_snapshots.json")


def load_golden(directory=GOLDEN_DIR) -> list:
    """Every golden case on disk."""
    d = Path(directory)
    out = []
    for f in sorted(d.glob("*.yaml")):
        # Multi-document, so a hardened/vulnerable PAIR lives in one file.
        # The pair is the unit that carries meaning: a positive case with no
        # negative twin only proves the tool agrees with its author.
        for case in yaml.safe_load_all(f.read_text(encoding="utf-8")):
            if not case:
                continue
            case["_file"] = str(f)
            out.append(case)
    return out


def run_case(case) -> dict:
    """Assess a golden case's config. Returns {control_id: (state, evidence)}."""
    from ..pipeline import assess

    path = case["config"]
    if not Path(path).exists():
        return {}
    r = assess(path, **(case.get("assess_kwargs") or {}))
    if r.assessment is None:
        return {}
    out = {}
    for f in r.assessment.findings:
        ev = f.evidence[0] if f.evidence else None
        out[f.control_id] = (
            f.state.value,
            f"L{ev.line}: {ev.raw[:70]}" if ev else "(no evidence)")
    return out


def verify_corpus(directory=GOLDEN_DIR) -> dict:
    """Run every golden case and compare against its verified expectations.

    Reports three kinds of problem separately, because they mean different
    things:

      mismatch   the tool's answer changed -- a regression, or a fix that
                 needs the expectation updated deliberately
      missing    the control no longer produces a finding at all -- usually a
                 rule that stopped applying to the platform
      no_config  the case's config file is not on this machine
    """
    results = {"cases": 0, "checked": 0, "mismatch": [], "missing": [],
               "no_config": [], "ok": 0}
    for case in load_golden(directory):
        results["cases"] += 1
        if not Path(case["config"]).exists():
            results["no_config"].append(case["name"])
            continue
        actual = run_case(case)
        for cid, spec in (case.get("controls") or {}).items():
            want = spec["expect"] if isinstance(spec, dict) else spec
            results["checked"] += 1
            if cid not in actual:
                results["missing"].append(f"{case['name']}: {cid} produced no finding")
                continue
            got, ev = actual[cid]
            if got != want:
                because = spec.get("because", "") if isinstance(spec, dict) else ""
                results["mismatch"].append(
                    f"{case['name']}: {cid} expected {want}, got {got}"
                    + (f"\n      verified because: {because}" if because else "")
                    + f"\n      tool now cites:   {ev}")
            else:
                results["ok"] += 1
    return results


# --------------------------------------------------------------- snapshots
def snapshot_mappings(packs_dir="packs", samples=None) -> dict:
    """What every pack mapping currently produces against the sample set.

    CHANGE DETECTION ONLY -- see the package docstring. This cannot tell a
    right mapping from a wrong one; it can only tell a changed one from an
    unchanged one, which is what stops a pack edit from silently altering
    findings on a customer's device.
    """
    from ..pipeline import assess, load_packs

    samples = samples or _default_samples()
    out: dict = {}
    for path in samples:
        if not Path(path).exists():
            continue
        try:
            r = assess(path)
        except Exception as exc:                       # noqa: BLE001
            out[Path(path).name] = {"_error": f"{type(exc).__name__}: {exc}"}
            continue
        if not r.supported or r.assessment is None:
            out[Path(path).name] = {"_unsupported": r.identity.vendor}
            continue
        fields = {}
        for f in r.assessment.findings:
            if f.observed is not None:
                fields[f.field] = _stable(f.observed)
        out[Path(path).name] = {
            "platform": r.identity.platform,
            "records": r.records,
            "counts": r.counts(),
            "fields": dict(sorted(fields.items())),
        }
    return out


def _stable(v):
    """A comparable, order-independent form. A list whose order changes between
    runs would otherwise show as a diff every time."""
    if isinstance(v, list):
        return sorted(str(x) for x in v)
    return v


def _default_samples() -> list:
    out = []
    for pat in ("samples/**/*.cfg", "samples/**/*.conf", "samples/**/*.json",
                "samples/**/*.xml", "samples/**/*.txt"):
        out += [str(p) for p in Path().glob(pat)]
    return sorted(out)


def write_snapshot(path=SNAPSHOT_PATH, **kw) -> dict:
    snap = snapshot_mappings(**kw)
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(snap, indent=1, sort_keys=True, default=str),
                 encoding="utf-8")
    return snap


def load_snapshot(path=SNAPSHOT_PATH) -> dict:
    p = Path(path)
    if not p.exists():
        return {}
    return json.loads(p.read_text(encoding="utf-8"))


def diff_snapshot(path=SNAPSHOT_PATH, **kw) -> list:
    """Human-readable differences between stored and current behaviour."""
    old, new = load_snapshot(path), snapshot_mappings(**kw)
    diffs = []
    for name in sorted(set(old) | set(new)):
        if name not in old:
            diffs.append(f"NEW sample: {name}")
            continue
        if name not in new:
            diffs.append(f"REMOVED sample: {name}")
            continue
        o, n = old[name], new[name]
        if o.get("counts") != n.get("counts"):
            diffs.append(f"{name}: control counts {o.get('counts')} -> {n.get('counts')}")
        of, nf = o.get("fields", {}), n.get("fields", {})
        for f in sorted(set(of) | set(nf)):
            if of.get(f) != nf.get(f):
                diffs.append(f"{name}: {f} {of.get(f)!r} -> {nf.get(f)!r}")
    return diffs
