"""Apply a mapping pack to an indented (Reader 1) configuration.

Same pack contract as the JSON path (plan 13.6): declarative rules plus
allow-listed derivations. Only the matching primitive differs -- regex against
lines instead of JSONPath against nodes.

The scoping rule from plan 2.3.1 is enforced here: a mapping that declares a
``parent`` produces a SCOPED field path, so `line vty 0 4` and `line vty 5 15`
land in separate observations. Two vty ranges with different transport settings
is a real configuration and a flat model would silently keep only one of them.
"""
from __future__ import annotations

import re
from typing import Any

from ..schema.enums import ObservationState, RecordState
from ..schema.normalise import normalise
from ..schema.observation import Observation
from ..schema.sbm import FIELD_TYPES, SecurityBaselineModel, _unscope
from .indented import IndentedConfig
from .pack import Pack, _scope_field


def _extract(mo, spec: dict, text: str) -> Any:
    """Pull the requested group out of a match.

    Uses ``mo.re.groups``, NOT ``mo.lastindex``. lastindex is None whenever an
    optional group did not participate, so `^(no )?ip http server` matching
    "ip http server" fell through to the whole line -- and with invert that
    turned "HTTP is ON" into "HTTP is off": a false PASS on a high-severity
    control, which plan 10.5 calls the metric that matters most.
    """
    if mo is None:
        return text.strip()
    g = spec.get("group", 1)
    if mo.re.groups >= g:
        return mo.group(g)          # may legitimately be None
    return text.strip()


def _coerce(raw: Any, spec: dict, target_type: str) -> Any:
    """Apply a mapping's ``value:`` spec."""
    if spec.get("const") is not None:
        return spec["const"]
    out = normalise(raw, spec.get("as", target_type))
    if spec.get("invert"):
        # `^(no )?ip http server` -- group 1 is "no " when disabled, so a match
        # on the negation means the feature is OFF. Modelling this as a real
        # OBSERVED false matters: an admin who explicitly disabled HTTP is a
        # provable PASS, which an absence could never be (plan 2.3).
        return not bool(raw)
    if spec.get("scale") and isinstance(out, (int, float)) and not isinstance(out, bool):
        # Unit normalisation. ASA `ssh timeout` is minutes; the SBM field is
        # seconds. Comparing 5 (minutes) against a 120-second threshold passed
        # every ASA ever configured.
        out = out * spec["scale"]
    return out


def apply_indented_pack(
    cfg: IndentedConfig, pack: Pack, *, assessment_id: str, sha256: str
) -> SecurityBaselineModel:
    sbm = SecurityBaselineModel(
        assessment_id=assessment_id, source_file=cfg.source_file, source_sha256=sha256
    )

    for m in pack.mappings:
        field = m.field
        target_type = m.as_type or FIELD_TYPES.get(_unscope(field), "str")
        spec = m.value or {}

        # ---------- constant ------------------------------------------------
        if m.const is not None:
            sbm.set(field, Observation.default_assumed(m.const, field_path=field))
            continue

        # ---------- scoped child match --------------------------------------
        if m.parent:
            hits = cfg.find_children(m.parent, m.regex)
            if not hits:
                sbm.set(field, Observation.not_observed(field_path=field))
                continue
            grouped: dict[str, list[tuple[int, str]]] = {}
            for parent_text, lineno, text in hits:
                grouped.setdefault(parent_text, []).append((lineno, text))
            for parent_text, items in grouped.items():
                scoped = _scope_field(field, parent_text)
                vals, ev = [], []
                for lineno, text in items:
                    mo = re.search(m.regex, text)
                    raw = _extract(mo, spec, text)
                    vals.append(_coerce(raw, spec, target_type))
                    ev.append(cfg.evidence(lineno, text))
                value = vals if target_type == "list" and len(vals) == 1 and isinstance(vals[0], list) else (
                    vals[0] if len(vals) == 1 else vals
                )
                if isinstance(value, list) and len(value) == 1 and isinstance(value[0], list):
                    value = value[0]
                sbm.set(scoped, Observation.observed(value, ev, field_path=scoped))
            continue

        # ---------- top-level match -----------------------------------------
        hits = cfg.find(m.regex)
        if not hits:
            # A field may have SEVERAL mappings -- alternative spellings of the
            # same setting, e.g. `enable password X` (weak) and `enable password
            # X encrypted` (strong), which are mutually exclusive by design.
            # Exactly one can match, and the others must not erase its result.
            # Without this guard the non-matching alternative overwrote a real
            # OBSERVED value with NOT_OBSERVED, and a cleartext password read
            # straight off the device reported as "not configured".
            existing = sbm.get(field)
            if existing is not None and existing.state is ObservationState.OBSERVED:
                continue
            if m.if_absent is not None:
                sbm.set(field, Observation.default_assumed(m.if_absent, field_path=field))
            else:
                sbm.set(field, Observation.not_observed(field_path=field))
            continue

        if m.collect or target_type == "list":
            vals, ev = [], []
            for lineno, text in hits:
                mo = re.search(m.regex, text)
                raw = _extract(mo, spec, text)
                v = _coerce(raw, spec, "str" if m.collect else target_type)
                (vals.extend(v) if isinstance(v, list) else vals.append(v))
                ev.append(cfg.evidence(lineno, text))
            sbm.set(field, Observation.observed(vals, ev, field_path=field))
            continue

        lineno, text = hits[0]
        mo = re.search(m.regex, text)
        raw = _extract(mo, spec, text)
        value = _coerce(raw, spec, target_type)
        obs = (
            Observation.observed(value, [cfg.evidence(lineno, text)], field_path=field)
            if value is not None
            else Observation.unparsed([cfg.evidence(lineno, text)], field_path=field)
        )
        sbm.set(field, obs)

    # ---------- derivations -------------------------------------------------
    for d in pack.derivations:
        fn = INDENTED_DERIVATIONS.get(d.op)
        if fn is None:
            continue
        value, ev = fn(cfg, d.params)
        sbm.set(
            d.field,
            Observation.observed(value, ev, field_path=d.field)
            if ev else Observation.default_assumed(value, field_path=d.field),
        )

    snap = cfg.accounting_snapshot()
    sbm.accounting.total = cfg.total_records
    sbm.accounting.record(RecordState.PARSED, snap[RecordState.PARSED.value])
    sbm.accounting.record(RecordState.UNKNOWN, snap[RecordState.UNKNOWN.value])
    sbm.unrecognised = cfg.unrecognised()
    return sbm


# ---------------------------------------------------------------------------
# Allow-listed derivations for indented configs (plan 13.2).
# ---------------------------------------------------------------------------

def derive_ios_telnet_reachable(cfg: IndentedConfig, params: dict):
    """Is telnet actually reachable on this device?

    IOS has no `ip telnet server` line to look for -- the answer is a property
    of the vty set. A device is telnet-reachable if ANY vty line permits telnet
    transport, so checking one line, or checking the file globally, both give
    wrong answers on a device whose vty ranges differ.
    """
    reachable, evidence = False, []
    for parent_text, lineno, text in cfg.find_children(r"^line vty", r"transport input"):
        tokens = text.split("transport input", 1)[1].split()
        if "telnet" in tokens or "all" in tokens:
            reachable = True
            evidence.append(cfg.evidence(lineno, f"{parent_text} / {text.strip()}"))
    return reachable, evidence


def derive_ios_weak_ssh_crypto(cfg, params: dict):
    """Cisco `ip ssh server algorithm ...` -- keep only the WEAK entries.

    Without this, crypto.weak_ciphers meant "every algorithm" on Cisco and
    "only the weak ones" on SonicWall. One field, two meanings, and a control
    that could not be correct on both.
    """
    WEAK = ("sha1", "-cbc", "3des", "arcfour", "md5", "group1",
            "diffie-hellman-group14-sha1")
    found, ev = [], []
    for lineno, text in cfg.find(r"^ip ssh server algorithm"):
        for tok in text.split()[4:]:
            if any(w in tok.lower() for w in WEAK):
                found.append(tok)
                ev.append(cfg.evidence(lineno, text))

    # SNMPv3 user crypto. Added because the consensus layer DISPUTED a finding
    # on the hardened fixture: the universal detector flagged `auth md5 ...
    # priv 3des` on an SNMPv3 user and the pack said `crypto.weak_ciphers = []`
    # -- because it read `ip ssh server algorithm` and nothing else. The
    # detector was right and the pack was blind, on the very file built to
    # demonstrate correct configuration. v3 with MD5 authentication and 3DES
    # privacy is weak whatever the version number suggests.
    for lineno, text in cfg.find(r"^snmp-server user \S+ \S+ v3"):
        low = text.lower()
        for kw, tok in (("auth md5", "snmpv3-auth-md5"),
                        ("auth sha ", "snmpv3-auth-sha1"),
                        ("priv des", "snmpv3-priv-des"),
                        ("priv 3des", "snmpv3-priv-3des")):
            if kw in low:
                found.append(tok)
                ev.append(cfg.evidence(lineno, text))

    # IPsec transform sets: `esp-des esp-md5-hmac` is weak whatever the
    # surrounding policy says.
    for lineno, text in cfg.find(r"^crypto ipsec transform-set"):
        for tok in text.split()[3:]:
            t = tok.lower()
            if t in ("esp-des", "esp-3des", "esp-md5-hmac", "esp-sha-hmac",
                     "ah-md5-hmac", "esp-null"):
                found.append(tok)
                ev.append(cfg.evidence(lineno, text))
    return found, ev


INDENTED_DERIVATIONS = {
    "ios_weak_ssh_crypto": derive_ios_weak_ssh_crypto,
    "ios_telnet_reachable": derive_ios_telnet_reachable,
}
