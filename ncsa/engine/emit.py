"""Emit a hardened configuration: the device's own file, with what is provably
wrong corrected and nothing else touched.

WHY A FILE AND NOT A COMMAND SCRIPT
-----------------------------------
For SonicOS we hold no CLI grammar. `packs/sonicwall_exp.yaml` says so in its
own header: "SonicWall publishes no CLI grammar in the vendor-doc set we hold,
so the device itself is the authority." A command sequence written without a
grammar is plausible text, not verified syntax -- `login-banner` is a guess,
while `cli_loginBanner` is a key read from a real export.

What we DO hold is 92,635 settings from the appliance, each with its exact name
and its exact value spelling. So the configuration file is not the risky
artefact here; it is the only grounded one.

THE FOUR RULES
--------------
1. ANCHOR ON EVIDENCE. A record is rewritten only when a FAIL finding cites it.
   The engine can change what it can prove is wrong, and nothing else.
2. FALL BACK TO THE MAPPING, ONLY FOR AN EMPTY RECORD. `cli_loginBanner` is
   present with value "" -- a provable absence, and a real finding -- but an
   empty record carries no evidence, so anchoring on evidence alone silently
   skipped two legitimate fixes.
3. COPY THE DEVICE'S OWN FORMAT. `encUsernamePassword=off` takes `on`;
   `adminLoginOtpRequire=0` takes `1`. Which spelling a key wants is read from
   the key, never assumed.
4. REFUSE RATHER THAN GUESS. A boolean control over a string-valued record is
   not a single-record change. An earlier version wrote
   `syslogServerName=on` -- a boolean word into a server ADDRESS field --
   because the control says `equals True` and the record was empty. That is the
   invented value this project forbids everywhere else, and it would have put
   nonsense into a production firewall.

WHAT IS NEVER TOUCHED
---------------------
PASS settings (minimal diff: a passing setting has nothing to correct) and
UNKNOWN (the setting was never read, so a change is unverifiable and cannot be
rolled back meaningfully). Measured on the reference NSA 3700: hardening moved
FAIL by 15 and PASS by 16 while UNKNOWN moved by 0. You cannot harden a blind
spot.
"""
from __future__ import annotations

import fnmatch
import re
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path

from ..schema.enums import ResultState

#: Set when a control only requires that a banner exist. The wording is
#: deliberately generic: a legal notice is an organisational decision, and a
#: tool inventing one that reads as a company's own policy would be overstating
#: what it knows.
DEFAULT_BANNER = "Authorised access only. Activity is monitored and logged."

#: Value spellings a device may use for a boolean, in pairs of (true, false).
_BOOL_PAIRS = (("on", "off"), ("1", "0"), ("enable", "disable"),
               ("enabled", "disabled"), ("true", "false"), ("yes", "no"))

_RECORD = re.compile(r"setting\[(\d+)\]")

#: Operators that describe a POLICY, not a setting. `max_count 0` on
#: "administrative ports open to the internet" is satisfied by editing firewall
#: rules, and there is no single record to write.
_POLICY_OPERATORS = {"max_count", "min_count", "contains_none", "contains_any",
                     "not_in", "in"}


@dataclass
class Change:
    """One record rewritten, and the finding that justified it."""

    control_id: str
    title: str
    key: str
    before: str
    after: str
    record: int
    anchored_by: str          # "evidence" | "mapping"

    def to_json(self) -> dict:
        return {"control_id": self.control_id, "title": self.title,
                "key": self.key, "before": self.before, "after": self.after,
                "record": f"setting[{self.record}]",
                "anchored_by": self.anchored_by}


@dataclass
class Refusal:
    """A failing control the emitter would not act on, and why.

    Named, never silently dropped: an unlisted gap reads as a solved one.
    """

    control_id: str
    field: str
    reason: str

    def to_json(self) -> dict:
        return {"control_id": self.control_id, "field": self.field,
                "reason": self.reason}


@dataclass
class Emission:
    text: str = ""
    changes: list = field(default_factory=list)
    refused: list = field(default_factory=list)
    supported: bool = True
    note: str = ""

    def to_json(self) -> dict:
        return {"supported": self.supported, "note": self.note,
                "changes": [c.to_json() for c in self.changes],
                "refused": [r.to_json() for r in self.refused]}


def _bool_like(current: str, want: bool) -> str | None:
    """The spelling THIS key already uses, or None if it is not boolean-shaped."""
    c = (current or "").strip().lower()
    for yes, no in _BOOL_PAIRS:
        if c in (yes, no):
            return yes if want else no
    return None


def _target(control, current: str, mapping) -> tuple[str | None, str]:
    """The value this record should hold, or None with the reason it cannot."""
    op, expected = control.operator, control.expected

    if op in _POLICY_OPERATORS:
        return None, (f"`{op}` describes a policy, not a setting: it is "
                      "satisfied by editing rules, not by writing one record")

    if op == "equals" and isinstance(expected, bool):
        spelled = _bool_like(current, expected)
        if spelled is not None:
            return spelled, ""
        # RULE 4. No existing boolean spelling to copy. Is the record even a
        # boolean? The pack declares how it is read; anything else gets refused.
        declared = (getattr(mapping, "value", None) or {}).get("as") if mapping else None
        if declared == "bool":
            return ("on" if expected else "off"), ""
        return None, (f"{control.field} is a boolean control but the record is "
                      f"{declared or 'untyped'} and empty; the fix needs a value "
                      "this configuration does not contain")

    if op in ("lte", "gte"):
        try:
            now, limit = int(current), int(expected)
        except (TypeError, ValueError):
            return None, f"`{op}` against a non-numeric record ({current!r})"
        if (op == "lte" and now > limit) or (op == "gte" and now < limit):
            return str(limit), ""
        return None, "already within bounds"

    if op == "is_set":
        if (current or "").strip():
            return None, "already set"
        return DEFAULT_BANNER if "banner" in control.field else None, (
            "" if "banner" in control.field
            else f"{control.field} must be set, but its value is specific to "
                 "this organisation and is not derivable from the configuration")

    return None, f"`{op}` is not a single-record change"


def emit_sonicos(device_assessment, source: str | Path, *, controls_by_id,
                 pack) -> Emission:
    """Rewrite the records that FAIL findings prove wrong. Nothing else."""
    src = Path(source)
    if getattr(pack, "reader", None) != "sonicos_exp":
        return Emission(
            supported=False,
            note=(f"hardened-configuration emission is implemented for the "
                  f"SonicOS settings export; this device parsed with the "
                  f"{getattr(pack, 'reader', 'unknown')!r} reader. The findings "
                  "and the remediation steps are unaffected."))

    text = src.read_text(encoding="utf-8", errors="replace")
    pairs = text.split("&")

    # key -> index, for RULE 2. First occurrence wins, matching the reader.
    index: dict[str, int] = {}
    for i, pair in enumerate(pairs):
        k, _, _v = pair.partition("=")
        index.setdefault(urllib.parse.unquote_plus(k), i)

    by_field = {m.field: m for m in pack.mappings
                if getattr(m, "path", None) and m.const is None}

    out = Emission()
    for finding in device_assessment.assessment.findings:
        # PARTIAL is excluded with PASS and UNKNOWN: "some conditions met" does
        # not say WHICH, so there is no single record to correct.
        if finding.state is not ResultState.FAIL:
            continue
        control = (controls_by_id or {}).get(finding.control_id)
        if control is None:
            continue
        mapping = by_field.get(control.field)

        idx, anchored = None, ""
        ev = finding.evidence[0] if finding.evidence else None
        m = _RECORD.match((ev.record_id or "") if ev else "")
        if m:
            idx, anchored = int(m.group(1)) - 1, "evidence"
        elif mapping is not None and "*" not in mapping.path:
            if mapping.path in index:
                idx, anchored = index[mapping.path], "mapping"
            else:
                # The pack declares this key and the device does not have it.
                # That is OUR blind spot, exactly as much as a glob matching
                # nothing, and it must read as one: `uuidIpsObjEnable` occurs
                # in none of the 92,635 records, so there is no evidence IPS is
                # off and a "fix" would toggle a security service on a device
                # whose state was never read. The generic "no single record
                # maps to this field" sounded like a structural limit instead.
                out.refused.append(Refusal(
                    finding.control_id, control.field,
                    f"mapping `{mapping.path}` matched no record in this "
                    "configuration, so the engine never read this setting and "
                    "has no evidence it is wrong"))
                continue
        elif mapping is not None:
            hits = sum(1 for k in index if fnmatch.fnmatch(k, mapping.path))
            # A glob that matches NOTHING is a dead mapping, not a per-instance
            # setting. Calling it per-instance would describe our own blind spot
            # as a property of the device -- the same overstatement, inverted.
            reason = (
                f"per-instance setting: {hits} records match `{mapping.path}`, "
                "so the fix targets named instances rather than one record"
                if hits else
                f"mapping `{mapping.path}` matched no record in this "
                "configuration, so the engine never read this setting and has "
                "no evidence it is wrong")
            out.refused.append(Refusal(finding.control_id, control.field, reason))
            continue

        if idx is None or not (0 <= idx < len(pairs)):
            out.refused.append(Refusal(
                finding.control_id, control.field,
                "no single record maps to this field (derived or policy-level)"))
            continue

        key_raw, _, cur_raw = pairs[idx].partition("=")
        key = urllib.parse.unquote_plus(key_raw)
        current = urllib.parse.unquote_plus(cur_raw)

        value, reason = _target(control, current, mapping)
        if value is None:
            out.refused.append(Refusal(finding.control_id, control.field, reason))
            continue

        pairs[idx] = f"{key_raw}={urllib.parse.quote_plus(value)}"
        out.changes.append(Change(
            control_id=finding.control_id, title=finding.title, key=key,
            before=current, after=value, record=idx + 1, anchored_by=anchored))

    out.text = "&".join(pairs)
    return out


def as_exp(text: str) -> bytes:
    """The IMPORTABLE form of an emitted configuration.

    SonicOS ingests a `.exp`, which is base64 of the URL-encoded `key=value`
    blob -- exactly what `readers.sonicos_exp.decode` undoes. The emitter works
    on the decoded text, so handing an operator that text would hand them a
    file the appliance does not accept: the right settings in the wrong
    envelope. This is the inverse of `decode`, and nothing else.

    It does NOT make the file importable in the sense that matters. The export
    carries `checksumVersion=1` with no checksum field we can identify, so
    whether the appliance accepts an edited settings file is unverified and
    can only be settled on a sandbox device. Encoding is necessary; it is not
    sufficient.
    """
    import base64

    return base64.b64encode(text.encode("utf-8"))


def roundtrip_ok(text: str) -> bool:
    """Does the emitted configuration survive encode -> decode unchanged?

    A cheap structural check, and the only import-shaped assurance available
    without the hardware: if our own reader cannot read back what we wrote, no
    appliance will either.
    """
    import base64

    try:
        return base64.b64decode(as_exp(text), validate=True).decode("utf-8") == text
    except Exception:                                  # noqa: BLE001
        return False


def verify(emission: Emission, device_assessment, source: str | Path,
           *, assessment_id: str = "hardened") -> dict:
    """Re-assess the emitted configuration and report the measured delta.

    The compliance gain is MEASURED, not predicted: the emitted file is written
    and run through the same engine. A regression estimate would be strictly
    weaker than a number we can simply compute.
    """
    import tempfile

    from ..pipeline import assess

    if not emission.supported or not emission.changes:
        return {}

    src = Path(source)
    with tempfile.TemporaryDirectory() as d:
        out = Path(d) / f"hardened-{src.name}"
        out.write_text(emission.text, encoding="utf-8")
        after = assess(out, redact=False, assessment_id=assessment_id)

    b, a = device_assessment.coverage(), after.coverage()
    states = lambda da: {s: sum(1 for f in da.assessment.findings          # noqa: E731
                                if f.state.value == s)
                         for s in ("PASS", "FAIL", "PARTIAL", "UNKNOWN",
                                   "NOT_APPLICABLE")}
    return {
        "before": {"score_pct": b["score_pct"], "assessed_pct": b["assessed_pct"],
                   "states": states(device_assessment)},
        "after": {"score_pct": a["score_pct"], "assessed_pct": a["assessed_pct"],
                  "states": states(after)},
        "score_delta": round(a["score_pct"] - b["score_pct"], 1),
    }
