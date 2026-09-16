"""Export a device's Security Baseline Model as JSON.

WHAT THIS IS
------------
The vendor-neutral view of one device: every security-relevant setting the
engine understood, in a flat dotted namespace that means the same thing on a
SonicWall, a FortiGate and an AWS security group. `management.ssh.enabled` is
one field with one meaning; which vendor key produced it is recorded as
evidence, not as structure.

That makes this the machine-readable counterpart to the PDF report -- the same
assessment, shaped for a pipeline rather than a reader.

WHAT IT IS NOT
--------------
It is not the configuration file. On the reference NSA 3700, 92,635 records
collapse to 2,851 entries -- 56 device-wide fields plus 2,795 SCOPED
instances, because a firewall has many rules and each is a separate object:

    management.ssh.enabled                              device-wide
    firewall.rules[Cloud Backup [IPv4#61]].action       one rule
    interfaces[X2].zone                                 one interface

Everything else in the export is signature databases, object-table
bookkeeping and counters that no security control reads.

Nor is it a HARDENING baseline -- it says what the device IS, not what it
should be. What it should be lives in `rules/`, and the comparison between the
two is the assessment.

EVERY FIELD CARRIES ITS OBSERVATION STATE
-----------------------------------------
A value alone would be a lie by omission. `management.telnet.enabled: false`
is a very different fact depending on whether we READ it off the device, or
assumed it from a platform default, or never found it at all. The state is
therefore mandatory on every entry, and consumers that ignore it will draw
conclusions the engine refused to draw.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

#: What each observation state licenses a consumer to conclude. Shipped inside
#: the document so it does not depend on a reader having seen the docs.
STATE_MEANING = {
    "OBSERVED": "Read directly from the configuration. The evidence names the "
                "line it came from.",
    "DEFAULT_ASSUMED": "Not present in the configuration; this is the "
                       "platform's documented default. It cannot support a "
                       "finding on its own.",
    "NOT_OBSERVED": "The field is mapped for this platform but the "
                    "configuration is silent. Not a value.",
    "UNPARSED": "Present but not interpretable -- most often a reference to "
                "an object this export does not contain.",
}


def _evidence(obs) -> list[dict]:
    out = []
    for e in getattr(obs, "evidence", []) or []:
        out.append({
            "file": e.file,
            # `line` is null where the source has no meaningful line: the
            # decoded SonicOS backup is one physical line of &-separated
            # settings, so `record` carries the position instead.
            "line": e.line,
            "record": e.record_id,
            "raw": e.raw,
        })
    return out


def baseline(da, assessment_id: str = "") -> dict:
    """The SBM as a plain dict, ready for json.dump."""
    sbm = getattr(da, "sbm", None)
    identity = da.identity

    fields: dict = {}
    if sbm is not None:
        for path, obs in sorted((sbm.observations or {}).items()):
            state = getattr(obs.state, "value", str(obs.state))
            entry = {
                "value": obs.value,
                "state": state,
                "source": getattr(obs.source, "value", str(obs.source)),
                "confidence": obs.confidence,
                "evidence": _evidence(obs),
            }
            fields[path] = entry

    by_state: dict = {}
    for entry in fields.values():
        by_state[entry["state"]] = by_state.get(entry["state"], 0) + 1

    findings = []
    if da.assessment is not None:
        for f in da.assessment.findings:
            findings.append({
                "control_id": f.control_id,
                "title": f.title,
                "field": f.field,
                "state": f.state.value,
                "severity": f.severity.value,
                "observed": f.observed,
                "expected": f.expected,
                "reason": f.reason,
                "confidence": f.confidence,
                "frameworks": {
                    "nist_800_53": f.frameworks.nist_800_53,
                    "iso_27001": f.frameworks.iso_27001,
                    "stig": f.frameworks.stig_ids,
                    "cis": f.frameworks.cis_ids,
                },
                "evidence": _evidence(f),
            })

    return {
        "schema": {
            "name": "NCSA Security Baseline Model",
            "version": "1.0",
            "description": "Vendor-neutral security settings for one device. "
                           "Field names mean the same thing on every platform; "
                           "the vendor key that produced each one is recorded "
                           "as evidence.",
            "observation_states": STATE_MEANING,
        },
        "assessment": {
            "id": assessment_id or "unspecified",
            "generated_at": datetime.now(timezone.utc).isoformat(
                timespec="seconds"),
            "supported": da.supported,
            "notes": list(da.notes or []),
        },
        "device": {
            "hostname": identity.hostname,
            "vendor": identity.vendor,
            "model": identity.model,
            "os": identity.os,
            "version": identity.version,
            "serial": identity.serial,
            "platform": identity.platform,
        },
        "source": {
            "file": identity.source_file,
            "sha256": identity.sha256,
            "records": da.total_records,
            # Records greatly outnumber fields: one setting recurs per rule,
            # per interface, per zone, and most of an export is not security
            # configuration at all.
            "record_accounting": da.records,
        },
        "coverage": da.coverage() if da.assessment is not None else None,
        "baseline": {
            "fields_populated": len(fields),
            "by_state": by_state,
            "fields": fields,
        },
        "findings": findings,
    }


def write_baseline(da, path, assessment_id: str = "", indent: int = 1) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(
        json.dumps(baseline(da, assessment_id), indent=indent, default=str),
        encoding="utf-8")
    return p
