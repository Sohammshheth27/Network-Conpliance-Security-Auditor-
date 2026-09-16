"""Known-vulnerability lookup: the device's firmware against NVD, offline.

HOW A MATCH IS DECIDED
----------------------
NVD describes affected products as configurations of CPE matches, and for
SonicOS most of them read "this OS version range AND one of these hardware
models". Both halves are evaluated. A version match alone is NOT enough: many
SonicOS advisories cover only TZ models, and reporting one of those against an
NSA would be a false finding with a CVE number on it.

Evaluation is three-valued -- affected, not affected, cannot tell -- and
"cannot tell" is reported as such. It is never folded into "not affected",
because that is the direction in which a vulnerability lookup does harm.

VERSION COMPARISON
------------------
SonicOS versions arrive in several spellings: `7.3.0-7012-R8150` on the
device, `7.3.0-7012`, `7.0.1-r1036`, `6.5.4.4-44n` and `5.9.1.0.` in NVD. They
are compared on the dotted release plus the build number after the first dash.
The trailing tag (`-R8150`, `-44n`) is a release label, not an ordering, and is
ignored. A bound with no build number covers the whole release. Anything that
still cannot be ordered makes the match indeterminate.

WHAT A RESULT IS, AND IS NOT
----------------------------
The data is a dated snapshot (tools/fetch_cve.py) -- every result states its
date, because a snapshot misses everything published after it. NVD is
sometimes late and occasionally wrong; the vendor's PSIRT advisory is
authoritative. And no match is not proof of no vulnerability: it means only
that this snapshot lists none for this version and model.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path

from .model import CLOUD_PLATFORMS, DomainResult, ExtendedFinding

SNAPSHOT_DIR = Path(__file__).resolve().parents[2] / "reference" / "cve"

#: platform -> (cpe part, vendor, product). Only platforms whose configuration
#: states a version precise enough to order belong here.
PLATFORM_CPE = {
    "sonicwall_sonicos": ("o", "sonicwall", "sonicos"),
}

STALE_AFTER_DAYS = 30
NIST = ["SI-2", "RA-5"]
CHECK_ID = "NCSA-X-CVE-001"
TITLE = "Firmware must not be affected by known vulnerabilities"
RATIONALE = ("A published vulnerability in the running firmware is exposure "
             "that exists regardless of configuration, and the fix is an "
             "upgrade rather than a setting.")


# ------------------------------------------------------------------ versions

def version_key(v) -> tuple | None:
    """`7.3.0-7012-R8150` -> ((7, 3, 0), 7012). None when unparseable."""
    s = str(v or "").strip().strip(".")
    if not s or s in ("*", "-"):
        return None
    head, _, tail = s.partition("-")
    nums = []
    for part in head.split("."):
        m = re.match(r"\d+", part)
        if not m:
            break
        nums.append(int(m.group()))
        if m.group() != part:
            break                      # `4v` -- numeric prefix, then stop
    if not nums:
        return None
    m = re.match(r"\d+", tail)
    return tuple(nums), (int(m.group()) if m else None)


def compare(device: tuple, bound: tuple) -> int | None:
    """Sign of (device - bound), or None when they cannot be ordered."""
    a, b = list(device[0]), list(bound[0])
    width = max(len(a), len(b))
    a += [0] * (width - len(a))
    b += [0] * (width - len(b))
    if a != b:
        return (a > b) - (a < b)
    if bound[1] is None:
        return 0                       # the bound names the whole release
    if device[1] is None:
        return None
    return (device[1] > bound[1]) - (device[1] < bound[1])


def _fold(values: list, op: str):
    """Three-valued OR / AND."""
    if op == "AND":
        if any(v is False for v in values):
            return False
        return None if any(v is None for v in values) else True
    if any(v is True for v in values):
        return True
    return None if any(v is None for v in values) else False


# ------------------------------------------------------------------ matching

_BOUNDS = (("versionStartIncluding", lambda c: c >= 0, ">="),
           ("versionStartExcluding", lambda c: c > 0, ">"),
           ("versionEndIncluding", lambda c: c <= 0, "<="),
           ("versionEndExcluding", lambda c: c < 0, "<"))


def _match_cpe(m: dict, target: tuple, device_key, model_slug):
    """(True | False | None, explanation)."""
    parts = m["criteria"].split(":")
    part, vendor, product, version = parts[2], parts[3], parts[4], parts[5]

    if part == "h":
        if vendor != target[1]:
            return False, ""
        if model_slug is None:
            return None, "the device model is not stated"
        return product == model_slug, f"hardware {product}"

    if (part, vendor, product) != target:
        return False, ""
    if device_key is None:
        return None, "the device version could not be parsed"

    if version not in ("*", "-"):
        k = version_key(version)
        if k is None:
            return None, f"NVD version {version!r} could not be parsed"
        c = compare(device_key, k)
        if c is None:
            return None, f"version {version!r} cannot be ordered against the device"
        return c == 0, f"exact version {version}"
    if version == "-":
        return None, "NVD marks the version as not applicable"

    results, said = [], []
    for key, pred, sym in _BOUNDS:
        if key not in m:
            continue
        k = version_key(m[key])
        if k is None:
            results.append(None)
            said.append(f"bound {m[key]!r} unparseable")
            continue
        c = compare(device_key, k)
        results.append(None if c is None else pred(c))
        said.append(f"{sym} {m[key]}")
    if not results:
        return True, f"all {product} versions"
    return _fold(results, "AND"), f"{product} {' and '.join(said)}"


def _match_node(node: dict, target, device_key, model_slug):
    hits = [_match_cpe(m, target, device_key, model_slug)
            for m in node.get("cpeMatch", [])]
    v = _fold([h[0] for h in hits], node.get("operator", "OR"))
    if node.get("negate") and v is not None:
        v = not v
    if v is True:
        why = [h[1] for h in hits if h[0] is True]
    else:
        why = [h[1] for h in hits if h[0] is None]
    return v, why[:2]


def match_cve(cve: dict, target, device_key, model_slug):
    """(True | False | None, explanation) for one CVE record."""
    verdicts, reasons = [], []
    for cfg in cve.get("configurations", []):
        node_results = [_match_node(n, target, device_key, model_slug)
                        for n in cfg.get("nodes", [])]
        v = _fold([r[0] for r in node_results], cfg.get("operator", "OR"))
        if cfg.get("negate") and v is not None:
            v = not v
        verdicts.append(v)
        if v is True:
            return True, "; ".join(w for r in node_results for w in r[1] if w)
        if v is None:
            reasons.append("; ".join(w for r in node_results for w in r[1] if w))
    if not verdicts:
        return None, "NVD has not published machine-readable affected versions"
    folded = _fold(verdicts, "OR")
    return folded, (reasons[0] if folded is None and reasons else "")


# ------------------------------------------------------------------ the domain

def _severity(metric: dict | None) -> str:
    sev = str((metric or {}).get("base_severity") or "").lower()
    return sev if sev in ("critical", "high", "medium", "low") else "medium"


def _load(platform: str, snapshot_dir: Path):
    nvd = snapshot_dir / f"nvd-{platform}.json"
    if not nvd.exists():
        return None, None
    data = json.loads(nvd.read_text(encoding="utf-8"))
    kev_path = snapshot_dir / "kev.json"
    kev = {}
    kev_meta = {}
    if kev_path.exists():
        k = json.loads(kev_path.read_text(encoding="utf-8"))
        kev = {v["cveID"]: v for v in k.get("vulnerabilities", [])}
        kev_meta = {"catalog_version": k.get("catalogVersion"),
                    "released": k.get("dateReleased")}
    data["_kev"], data["_kev_meta"] = kev, kev_meta
    return data, kev


def _version_evidence(da) -> list:
    sbm = getattr(da, "sbm", None)
    if sbm is None:
        return []
    for path in ("device.version", "platform.firmware.version"):
        obs = sbm.observations.get(path)
        if obs is not None and obs.evidence:
            return list(obs.evidence[:1])
    return []


def assess_cve(da, snapshot_dir: Path | None = None) -> DomainResult:
    snapshot_dir = snapshot_dir or SNAPSHOT_DIR
    platform = (da.identity.platform or "").lower()

    if platform in CLOUD_PLATFORMS:
        return DomainResult("cve", False,
                            "A cloud firewall runs no customer firmware; the "
                            "provider patches the underlying platform.",
                            validated_on="n/a")
    target = PLATFORM_CPE.get(platform)
    if target is None:
        return DomainResult("cve", None,
                            f"No CVE mapping is built for "
                            f"{platform or 'this platform'} yet, so its "
                            "firmware was not checked. That is a gap in the "
                            "tool, not a finding about the device.",
                            validated_on="n/a")

    version = da.identity.version
    if not version:
        return DomainResult("cve", None,
                            "The configuration does not state its software "
                            "version, so it cannot be matched against known "
                            "vulnerabilities.", validated_on="n/a")

    data, kev = _load(platform, snapshot_dir)
    if data is None:
        return DomainResult("cve", None,
                            "No local CVE snapshot is present. Run "
                            "`python -m tools.fetch_cve` to create one.",
                            validated_on="n/a")

    device_key = version_key(version)
    model = da.identity.model
    model_slug = (re.sub(r"[^a-z0-9]+", "_", model.lower()).strip("_")
                  if model else None)
    ev = _version_evidence(da)

    affected, unknown, no_data, rejected = [], [], 0, 0
    for cve in data["cves"]:
        if str(cve.get("status", "")).lower() == "rejected":
            rejected += 1
            continue
        if not cve.get("configurations"):
            no_data += 1
            continue
        verdict, why = match_cve(cve, target, device_key, model_slug)
        if verdict is True:
            affected.append((cve, why))
        elif verdict is None:
            unknown.append((cve, why))

    findings, inventory = [], []
    affected.sort(key=lambda t: (t[0]["id"] not in kev,
                                 -float((t[0].get("metric") or {}).get("base_score") or 0)))
    for cve, why in affected:
        k = kev.get(cve["id"])
        m = cve.get("metric") or {}
        kev_text = (f" CISA lists it as KNOWN EXPLOITED (added "
                    f"{k.get('dateAdded')}, remediation due {k.get('dueDate')}).")\
            if k else ""
        findings.append(ExtendedFinding(
            CHECK_ID, TITLE, "cve", "FAIL", _severity(m), cve["id"],
            f"{version} on {model or 'this device'} matches NVD's affected "
            f"configuration ({why}).{kev_text} {cve['description'][:300]}",
            observed={"version": version, "model": model,
                      "cvss": m.get("base_score"),
                      "cvss_version": m.get("cvss_version"),
                      "known_exploited": bool(k)},
            expected="a firmware release outside the affected range",
            evidence=ev, nist_800_53=NIST, rationale=RATIONALE))
        inventory.append({"id": cve["id"], "cvss": m.get("base_score"),
                          "severity": _severity(m),
                          "known_exploited": bool(k),
                          "kev_due": k.get("dueDate") if k else None,
                          "published": cve.get("published"),
                          "matched_on": why,
                          "summary": cve["description"][:240],
                          "references": cve.get("references", [])[:3]})
    for cve, why in unknown:
        findings.append(ExtendedFinding(
            CHECK_ID, TITLE, "cve", "UNKNOWN", _severity(cve.get("metric")),
            cve["id"],
            f"could not decide whether {version} is affected: {why or 'the affected range could not be ordered against this version'}",
            observed={"version": version, "model": model},
            nist_800_53=NIST, rationale=RATIONALE))

    fetched = data.get("fetched_at", "")
    notes = [f"Matched against the NVD snapshot fetched {fetched[:10] or 'at an unknown date'} "
             f"({data.get('total', len(data['cves']))} records for this product) "
             f"and CISA KEV {data['_kev_meta'].get('catalog_version') or 'not loaded'}. "
             "Anything published after the snapshot is not reflected.",
             "NVD is sometimes late or wrong; the vendor's PSIRT advisory is "
             "authoritative. No match is not proof of no vulnerability.",
             "A CVE is matched only when BOTH the firmware version and the "
             "hardware model fall inside NVD's affected configuration."]
    if no_data:
        notes.append(f"{no_data} record(s) have no machine-readable affected "
                     "versions yet (awaiting NVD analysis) and were not matched.")
    if rejected:
        notes.append(f"{rejected} rejected record(s) were ignored.")
    try:
        age = (datetime.now(timezone.utc)
               - datetime.fromisoformat(fetched)).days
        if age > STALE_AFTER_DAYS:
            notes.insert(0, f"The snapshot is {age} days old. Refresh it with "
                            "`python -m tools.fetch_cve` before relying on it.")
    except (TypeError, ValueError):
        pass

    n_kev = sum(1 for i in inventory if i["known_exploited"])
    summary = (f"{len(affected)} known vulnerabilit"
               f"{'y' if len(affected) == 1 else 'ies'} match {version} on "
               f"{model or 'this device'}"
               + (f", {n_kev} of them on CISA's known-exploited list" if n_kev else "")
               + (f"; {len(unknown)} could not be decided" if unknown else "")
               + f" (NVD snapshot {fetched[:10]}).")
    return DomainResult("cve", True, summary, findings=findings,
                        inventory=inventory, notes=notes,
                        validated_on=f"real device ({model or platform})")
