"""Apply a mapping pack to any PATH-based reader (2 and 3).

The Fortinet block reader and the braces reader both produce ``path -> value``,
so one applier covers both -- and, importantly, one PACK FORMAT covers both.
That is what lets a SonicWall pack and a Junos pack look like siblings despite
completely unrelated syntax.

Pack mappings for these readers use ``path:`` instead of ``regex:``/``jsonpath:``:

    - field: management.ssh.version
      path: "system/services/ssh/protocol-version"
      value: {as: int}

    - field: firewall.rules.action
      path: "firewall policy/*/action"      # wildcard -> scoped per entry
      scope_from: 1                          # which path segment names the scope
"""
from __future__ import annotations

import re

from typing import Any

from ..schema.enums import ObservationState, RecordState
from ..schema.normalise import normalise
from ..schema.observation import Observation
from ..schema.sbm import FIELD_TYPES, SecurityBaselineModel, _unscope
from .pack import Pack, _scope_field


def apply_path_pack(
    cfg, pack: Pack, *, assessment_id: str, sha256: str
) -> SecurityBaselineModel:
    """``cfg`` is a BlockConfig or BracesConfig -- both expose get/glob."""
    sbm = SecurityBaselineModel(
        assessment_id=assessment_id, source_file=cfg.source_file, source_sha256=sha256
    )

    for m in pack.mappings:
        field = m.field
        target = m.as_type or FIELD_TYPES.get(_unscope(field), "str")
        spec = m.value or {}

        if m.const is not None:
            sbm.set(field, Observation.default_assumed(m.const, field_path=field))
            continue

        path = m.path
        if not path:
            continue

        # ---------- wildcard: scoped per matching entry ----------------------
        if "*" in path:
            hits = cfg.glob(path)
            if not hits:
                sbm.set(field, Observation.not_observed(field_path=field))
                continue
            seg = m.scope_from if m.scope_from is not None else _wildcard_index(path)
            grouped: dict[str, list] = {}
            for p, val, ln, raw in hits:
                parts = p.split("/")
                sid = parts[seg] if 0 <= seg < len(parts) else p
                sid = _readable_scope(sid)
                grouped.setdefault(sid, []).append((val, ln, raw))
            for sid, items in grouped.items():
                scoped = _scope_field(field, sid)
                if target == "list":
                    sbm.set(scoped, Observation.observed(
                        [v for v, _, _ in items],
                        [cfg.evidence(ln, raw) for _, ln, raw in items],
                        field_path=scoped))
                else:
                    val, ln, raw = items[0]
                    sbm.set(scoped, _obs(val, spec, target, cfg, ln, raw, scoped))
            continue

        # ---------- exact path, list-valued ----------------------------------
        # A list field on a repeated path must collect EVERY match. `cfg.get`
        # returns only the first, so a Junos config with two syslog servers
        # reported one -- and NCSA-LOG-002 ("at least two remote syslog
        # servers") returned PARTIAL on a device that fully complied. The
        # wildcard branch above already collects; the exact-path branch did
        # not, so whether a correct device passed depended on whether the pack
        # author happened to write a `*` in the path.
        if target == "list" and hasattr(cfg, "get_all"):
            hits = cfg.get_all(path)
            if hits:
                for _v, ln, _r in hits:            # mark every one consumed
                    cfg._consumed.add(ln - 1)
                sbm.set(field, Observation.observed(
                    [v for v, _l, _r in hits],
                    [cfg.evidence(ln, raw) for _v, ln, raw in hits],
                    field_path=field))
                continue

        # ---------- exact path ----------------------------------------------
        hit = cfg.get(path)
        if hit is None:
            # A field may have several mappings -- mutually exclusive spellings
            # of one setting, e.g. Junos `<deny-all/>` vs `<permit-all/>`.
            # Exactly one can match and the others must not erase it. The same
            # defect existed in indented_pack.py and was fixed there first; a
            # non-matching alternative was overwriting a real OBSERVED value
            # with NOT_OBSERVED, so a device with an explicit default-deny
            # policy reported that no default policy was configured.
            existing = sbm.get(field)
            if existing is not None and existing.state is ObservationState.OBSERVED:
                continue
            if m.if_absent is not None:
                sbm.set(field, Observation.default_assumed(m.if_absent, field_path=field))
            else:
                sbm.set(field, Observation.not_observed(field_path=field))
            continue

        val, ln, raw = hit
        sbm.set(field, _obs(val, spec, target, cfg, ln, raw, field))

    for d in pack.derivations:
        fn = PATH_DERIVATIONS.get(d.op)
        if fn is None:
            continue
        value, ev = fn(cfg, d.params)
        if value is None and not ev:
            sbm.set(d.field, Observation.not_observed(field_path=d.field))
        elif ev:
            sbm.set(d.field, Observation.observed(value, ev, field_path=d.field))
        else:
            sbm.set(d.field, Observation.default_assumed(value, field_path=d.field))

    snap = cfg.accounting_snapshot()
    sbm.accounting.total = cfg.total_records
    sbm.accounting.record(RecordState.PARSED, snap[RecordState.PARSED.value])
    sbm.accounting.record(RecordState.UNKNOWN, snap[RecordState.UNKNOWN.value])
    sbm.unrecognised = cfg.unrecognised()
    return sbm


def _readable_scope(segment: str) -> str:
    """`entry[ethernet1%2F1]` -> `ethernet1/1`.

    The XML reader wraps a list element's name as `entry[name]` and encodes any
    `/` inside it so the segment survives path splitting. Neither detail should
    reach a finding: a report saying "interfaces[entry[ethernet1%2F1]].address"
    is unreadable, and the operator needs the name their device uses.
    """
    from urllib.parse import unquote

    m = re.fullmatch(r"[A-Za-z0-9_.-]+\[(.*)\]", segment)
    return unquote(m.group(1)) if m else unquote(segment)


def _obs(val: Any, spec: dict, target: str, cfg, ln: int, raw: str, field: str):
    if spec.get("const") is not None:
        return Observation.observed(spec["const"], [cfg.evidence(ln, raw)], field_path=field)
    if spec.get("invert"):
        # `set admin-ssh-v1 disable` -- presence of a disabling token means the
        # feature is OFF, and that is an OBSERVED false, not an absence.
        return Observation.observed(
            normalise(val, "bool") is False, [cfg.evidence(ln, raw)], field_path=field)
    if val == "":
        # An EMPTY value is not True. Junos writes valueless flags (`telnet;`)
        # where presence means enabled, but a key=value export writes
        # `syslogServerName=` to mean NOT CONFIGURED. Coercing that to True
        # produced PASS on an absent banner and an absent syslog collector --
        # a false PASS manufactured from an empty string (plan 10.5).
        if spec.get("empty_is_true"):
            return Observation.observed(True, [cfg.evidence(ln, raw)], field_path=field)
        return Observation.not_observed(field_path=field)

    coerced = normalise(val, spec.get("as", target))
    return (Observation.observed(coerced, [cfg.evidence(ln, raw)], field_path=field)
            if coerced is not None
            else Observation.unparsed([cfg.evidence(ln, raw)], field_path=field))


def _wildcard_index(path: str) -> int:
    return path.split("/").index("*") if "*" in path.split("/") else 0


# ---------------------------------------------------------------------------
# Allow-listed derivations for path readers (plan 13.2).
# ---------------------------------------------------------------------------

def derive_junos_telnet_enabled(cfg, params: dict):
    """Junos enables telnet by declaring the service; absence means off."""
    hit = cfg.get("system/services/telnet")
    if hit is None:
        for p, val, ln, raw in cfg.glob("system/services/telnet/*"):
            return True, [cfg.evidence(ln, raw)]
        return False, []
    return True, [cfg.evidence(hit[1], hit[2])]


def derive_junos_ssh_enabled(cfg, params: dict):
    hit = cfg.get("system/services/ssh")
    if hit is not None:
        return True, [cfg.evidence(hit[1], hit[2])]
    hits = cfg.glob("system/services/ssh/*")
    if hits:
        p, val, ln, raw = hits[0]
        return True, [cfg.evidence(ln, raw)]
    return False, []


def derive_sonicos_admin_ports(cfg, params: dict):
    """SonicWall management exposure -- HTTP/HTTPS/SSH bound to a WAN zone."""
    hits, ev = [], []
    for p, val, ln, raw in cfg.glob("administration/*"):
        key = p.split("/")[-1]
        if key in ("http-port", "https-port", "ssh-port") and val:
            hits.append(f"{key}={val}")
            ev.append(cfg.evidence(ln, raw))
    return hits, ev


def derive_sonicos_weak_ssh_crypto(cfg, params: dict):
    """Parse SonicOS `sshCipherControlConfig` and report ENABLED weak algorithms.

    The value is a JSON policy listing every kex/cipher/MAC with 1=enabled.
    A keyword match on the key name would say "SSH crypto is configured" and
    miss the point entirely -- the finding is WHICH algorithms are permitted.
    SHA-1 key exchange and CBC ciphers are the ones that matter.
    """
    import json as _json

    WEAK = ("sha1", "-cbc", "3des", "arcfour", "md5", "group1-", "diffie-hellman-group1")
    hit = cfg.get("sshCipherControlConfig")
    if hit is None:
        return [], []
    raw = hit[0]
    try:
        doc = _json.loads(raw)
    except Exception:
        return [], []
    enabled_weak = []
    for section, entries in doc.items():
        if not isinstance(entries, list):
            continue
        for ent in entries:
            if not isinstance(ent, dict):
                continue
            for alg, on in ent.items():
                if on and any(w in alg.lower() for w in WEAK):
                    enabled_weak.append(f"{section}:{alg}")
    return enabled_weak, ([cfg.evidence(hit[1], hit[2])] if enabled_weak else [])


def derive_sonicos_snmp_version(cfg, params: dict):
    """Effective SNMP version on SonicOS.

    There is no `snmpVersion` key. v3-only is expressed as
    `Snmp3_Mand_Required=on`; if that is off and a GetCommunity string exists,
    v1/v2c is accepted. Mapping the raw flag to snmp.version yielded "off",
    which no forbidden-version list matches -- so a device accepting v2c passed.
    """
    mand = cfg.get("Snmp3_Mand_Required")
    comm = cfg.get("snmp_GetCommunity")
    enabled = cfg.get("snmp_Enable")
    if enabled and str(enabled[0]).lower() in ("off", "0", "false"):
        return "disabled", [cfg.evidence(enabled[1], enabled[2])]
    if mand and str(mand[0]).lower() in ("on", "1", "true"):
        return "3", [cfg.evidence(mand[1], mand[2])]
    if comm and comm[0]:
        return "2c", [cfg.evidence(comm[1], comm[2])]
    return None, []


def derive_path_glob_contains(cfg, params: dict):
    """Is `token` present in the value of ANY path matching `path`?

    Deliberately GENERIC rather than vendor-specific. Several block/braces
    platforms express "is this service reachable" as a whitespace-separated
    allow-list on each interface rather than as a global toggle -- FortiOS
    `set allowaccess ping https ssh`, and the same shape appears elsewhere.
    Writing `fortios_telnet_enabled` would have meant new Python for the next
    vendor with the same idiom; this one is reusable from YAML alone, which is
    what keeps "adding a vendor is a data file" true.

    Absence is a real observation, not a missing one: if every interface
    declares an allow-list and none of them names telnet, telnet is off and we
    can cite the lines that prove it.
    """
    path = params.get("path")
    token = str(params.get("token", "")).lower()
    if not path or not token:
        return None, []

    hits = cfg.glob(path)
    if not hits:
        return None, []

    evidence, present = [], False
    for _p, val, ln, raw in hits:
        tokens = str(val).lower().split()
        if token in tokens:
            present = True
            evidence.append(cfg.evidence(ln, raw))
    if not present:
        # cite every allow-list we checked -- that is what makes "off" evidenced
        evidence = [cfg.evidence(ln, raw) for _p, _v, ln, raw in hits]
    return present, evidence


def derive_path_non_empty(cfg, params: dict):
    """True when a key exists AND carries a value; False when it is blank.

    Vendors distinguish "not configured" from "absent" by writing the key with
    an empty value. A blind bool cast cannot express that: to_bool("") is None,
    which the engine correctly reports as UNKNOWN -- we read the key but could
    not interpret it.

    That is the wrong answer here. `syslogServerName=` on a real SonicWall is
    not an unreadable setting; it is the device stating that NO remote syslog
    server is configured, which is a FAIL on a high-severity control. Left as
    UNKNOWN the finding disappears entirely, so an unconfigured log destination
    looks the same as one we failed to parse.

    Params:
        path  -- the key to read (required)
        blank -- extra values that count as empty, e.g. ["0.0.0.0", "none"]
    """
    key = params.get("path")
    if not key:
        return None, []
    blank = {str(b).strip().lower() for b in (params.get("blank") or [])}
    blank.add("")

    hit = cfg.get(key)
    if hit is None:
        # The key is genuinely absent. That is not the same as present-and-
        # blank, and we must not claim a reading we did not make.
        return None, []
    val, ln, raw = hit
    return str(val).strip().lower() not in blank, [cfg.evidence(ln, raw)]


def derive_path_any_true(cfg, params: dict):
    """True when ANY of several keys is on. For a field with several sources.

    "Is external authentication in use?" is answered by RADIUS *or* LDAP *or*
    TACACS, and a device may run one without the others. Expressed as separate
    mappings onto one boolean field they conflict: whichever is applied last
    wins, so a box running LDAP with RADIUS switched off reported
    `aaa_enabled = false` -- the opposite of the truth -- purely on pack order.

    Every matching key is cited, so the evidence shows which source answered.

    Params:
        paths -- key names or globs to test (required)
    """
    paths = params.get("paths") or []
    if isinstance(paths, str):
        paths = [paths]
    evidence, seen_any = [], False
    result = False
    for pattern in paths:
        hits = (cfg.glob(pattern) if "*" in pattern else
                [(pattern, *cfg.get(pattern))] if cfg.get(pattern) else [])
        for _p, val, ln, raw in hits:
            seen_any = True
            if str(val).strip().lower() in ("on", "1", "true", "yes", "enable",
                                            "enabled"):
                result = True
                evidence.append(cfg.evidence(ln, raw))
    if not seen_any:
        # None of the sources is present. That is not "false" -- it is a
        # question this configuration does not answer.
        return None, []
    return result, evidence


PATH_DERIVATIONS = {
    "sonicos_snmp_version": derive_sonicos_snmp_version,
    "path_non_empty": derive_path_non_empty,
    "path_any_true": derive_path_any_true,
    "sonicos_weak_ssh_crypto": derive_sonicos_weak_ssh_crypto,
    "junos_telnet_enabled": derive_junos_telnet_enabled,
    "junos_ssh_enabled": derive_junos_ssh_enabled,
    "sonicos_admin_ports": derive_sonicos_admin_ports,
    "path_glob_contains": derive_path_glob_contains,
}
