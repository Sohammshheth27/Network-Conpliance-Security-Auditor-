"""Vendor mapping packs -- the executable artifact for a vendor.

Plan 3.3 / 13.6: adding a vendor is a YAML file, not a code change. The pack IS
the Parser Specification of plan 13.3, restricted to field mappings and
*interpreted* rather than compiled. Same architecture, one box simplified.

Safety (plan 13.2/13.4): a pack never contains executable code. It declares
JSONPath expressions and named ``derivations`` chosen from an ALLOW-LIST
implemented here. A pack author cannot introduce new behaviour, only new
mappings -- which is what makes accepting a community-authored or AI-generated
pack safe.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

import yaml
from pydantic import BaseModel, Field

from ..schema.enums import RecordState
from ..schema.normalise import normalise
from ..schema.observation import Observation
from ..schema.sbm import FIELD_TYPES, SecurityBaselineModel, _unscope
from .json_reader import JsonDocument


def _scope_field(field: str, scope_id: str) -> str:
    """cloud.security_groups.id + sg-001 -> cloud.security_groups[sg-001].id"""
    parts = field.rsplit(".", 1)
    return f"{parts[0]}[{scope_id}].{parts[1]}" if len(parts) == 2 else f"{field}[{scope_id}]"


def _scope_index(doc: "JsonDocument", scope_expr: str) -> list[tuple[str, str]]:
    """[(container_path, scope_id), ...] sorted longest-first.

    ``$[*].GroupId`` yields ``[0].GroupId`` -> container ``[0]`` holds id
    ``sg-...0001``. Longest-first so a nested scope wins over its parent.
    """
    out: list[tuple[str, str]] = []
    for path, value in doc.query(scope_expr, count=False):
        container = path.rsplit(".", 1)[0] if "." in path else ""
        out.append((container, str(value)))
    return sorted(out, key=lambda t: len(t[0]), reverse=True)


def _scope_for(path: str, scope_map: list[tuple[str, str]]) -> str | None:
    """Which scope container owns this hit path?"""
    for container, sid in scope_map:
        if container == "" or path == container or path.startswith(container + ".") or path.startswith(container + "["):
            return sid
    return None


class Mapping(BaseModel):
    field: str
    # --- JSON reader ---
    jsonpath: str | None = None
    # --- path readers (Fortinet block, braces) ---
    path: str | None = None
    scope_from: int | None = Field(
        default=None,
        description="Which '/'-separated segment of a wildcard path names the "
                    "scope, e.g. 'firewall policy/*/action' -> 1",
    )
    # --- indented / regex readers ---
    regex: str | None = None
    parent: str | None = Field(
        default=None,
        description="Parent-line regex. Its presence makes the field SCOPED by "
                    "that parent -- plan 2.3.1, `transport input ssh` under "
                    "`line vty` differs from the same line under `line con`.",
    )
    value: dict = Field(default_factory=dict, description="{group, as, const, invert}")
    collect: bool = Field(default=False, description="Gather every match into a list")
    scope_by: str | None = None
    # --- common ---
    const: Any = None
    as_type: str | None = None
    scope: str | None = Field(
        default=None,
        description="JSONPath to an id used to scope this field, e.g. per security group",
    )
    if_absent: Any = Field(
        default=None,
        description="Value to record when the expression matches nothing. "
                    "Omit to record NOT_OBSERVED instead of inventing a value.",
    )


class Derivation(BaseModel):
    """A computed security fact -- plan 15.2, facts are computed, not matched."""

    field: str
    op: str
    params: dict = Field(default_factory=dict)


class Pack(BaseModel):
    vendor: str
    platform: str
    reader: str
    supported_domains: list[str] = Field(
        default_factory=list,
        description=(
            "SBM top-level domains THIS PACK MODELS. Empty means 'all'. "
            "Listing a domain is a statement about our coverage, not about the "
            "device -- see not_applicable_domains for the other claim."
        ),
    )
    not_applicable_domains: dict[str, str] = Field(
        default_factory=dict,
        description=(
            "Domains the PLATFORM GENUINELY DOES NOT HAVE, mapped to the reason. "
            "The reason is published as the finding's justification."
        ),
    )
    not_applicable_fields: list[str] | dict[str, str] = Field(
        default_factory=list,
        description=(
            "Fields whose CONCEPT this platform does not have. Verified absent, "
            "not merely unmapped -- a control on one of these is NOT_APPLICABLE, "
            "never UNKNOWN. Prefer the mapping form {field: reason}: an auditor "
            "asked to accept an exclusion needs the reason, and 'verified "
            "against the setting inventory' asserts the check without stating "
            "what was checked. The bare list form is still accepted."
        ),
    )

    def na_field_reason(self, field: str) -> str | None:
        """The stated reason this field is not applicable, if it is one."""
        naf = self.not_applicable_fields
        if isinstance(naf, dict):
            return naf.get(field)
        return "" if field in (naf or []) else None
    fingerprint: list[str] = Field(default_factory=list)
    mappings: list[Mapping] = Field(default_factory=list)
    derivations: list[Derivation] = Field(default_factory=list)
    version: str = "1.0"
    verified_versions: list[str] = Field(
        default_factory=list,
        description=(
            "OS releases this pack's mappings were checked against, taken from "
            "the version line of a real configuration in the corpus. A device "
            "outside them is still assessed, with a note saying so. Empty means "
            "no release was verified and nothing is claimed."
        ),
    )

    def validate_fields(self) -> list[str]:
        problems = []
        for m in self.mappings:
            if _unscope(m.field) not in FIELD_TYPES:
                problems.append(f"{self.vendor}: mapping field {m.field!r} not in SBM whitelist")
        for d in self.derivations:
            if _unscope(d.field) not in FIELD_TYPES:
                problems.append(f"{self.vendor}: derivation field {d.field!r} not in SBM whitelist")
            from .indented_pack import INDENTED_DERIVATIONS
            from .path_pack import PATH_DERIVATIONS
            if (d.op not in DERIVATIONS and d.op not in INDENTED_DERIVATIONS
                    and d.op not in PATH_DERIVATIONS):
                problems.append(
                    f"{self.vendor}: derivation op {d.op!r} is not allow-listed "
                    f"(available: {sorted(DERIVATIONS)})"
                )
        return problems


def load_pack(path: str | Path) -> Pack:
    with Path(path).open(encoding="utf-8") as fh:
        return Pack.model_validate(yaml.safe_load(fh))


# ---------------------------------------------------------------------------
# Allow-listed derivations (plan 13.2, 15.2)
#
# These are the only computations a pack may invoke. Each takes the parsed
# document and returns (value, evidence_list).
# ---------------------------------------------------------------------------

_WORLD_CIDRS = {"0.0.0.0/0", "::/0"}


def _sg_ingress_rules(doc: JsonDocument):
    """Yield (group_id, group_name, permission_dict, path) for every ingress rule."""
    groups = doc.query("$[*]", count=False) or doc.query("$.SecurityGroups[*]", count=False)
    for gpath, g in groups:
        if not isinstance(g, dict):
            continue
        gid = g.get("GroupId", "?")
        gname = g.get("GroupName", "?")
        for i, perm in enumerate(g.get("IpPermissions", []) or []):
            yield gid, gname, perm, f"{gpath}.IpPermissions[{i}]"


def _ports_of(perm: dict) -> tuple[int | None, int | None, str]:
    proto = str(perm.get("IpProtocol", "?"))
    if proto == "-1":
        return None, None, "all"
    return perm.get("FromPort"), perm.get("ToPort"), proto


def _world_sources(perm: dict) -> list[str]:
    out = []
    for r in perm.get("IpRanges", []) or []:
        if r.get("CidrIp") in _WORLD_CIDRS:
            out.append(r["CidrIp"])
    for r in perm.get("Ipv6Ranges", []) or []:
        if r.get("CidrIpv6") in _WORLD_CIDRS:
            out.append(r["CidrIpv6"])
    return out


def derive_admin_ports_open_to_world(doc: JsonDocument, params: dict):
    """Plan 15.2 -- fact.admin_mgmt_public_exposure() for cloud.

    The single most common real cloud finding: an administrative port reachable
    from the entire internet. Severity alone would call this "medium"; exposure
    is what makes it critical, and exposure is computed from the config itself
    (plan 7.2) rather than asked of the user.
    """
    ports = set(params.get("ports", [22, 3389, 23, 21, 3306, 5432, 1433, 27017]))
    hits, evidence = [], []
    for gid, gname, perm, path in _sg_ingress_rules(doc):
        world = _world_sources(perm)
        if not world:
            continue
        frm, to, proto = _ports_of(perm)
        if proto == "all":
            matched = sorted(ports)
        elif frm is None:
            continue
        else:
            matched = sorted(p for p in ports if frm <= p <= to)
        for p in matched:
            hits.append(f"{gid}:{proto}/{p} from {world[0]}")
            evidence.append(doc.evidence(path, perm))
    return hits, evidence


def derive_any_any_rules(doc: JsonDocument, params: dict):
    """Rules permitting all protocols from anywhere -- plan 6.6 category tier."""
    hits, evidence = [], []
    for gid, gname, perm, path in _sg_ingress_rules(doc):
        world = _world_sources(perm)
        if world and str(perm.get("IpProtocol")) == "-1":
            hits.append(f"{gid} ({gname}): all protocols from {world[0]}")
            evidence.append(doc.evidence(path, perm))
    return hits, evidence


def derive_unrestricted_ingress(doc: JsonDocument, params: dict):
    """Any ingress rule sourced from the whole internet, admin port or not."""
    hits, evidence = [], []
    for gid, gname, perm, path in _sg_ingress_rules(doc):
        world = _world_sources(perm)
        if not world:
            continue
        frm, to, proto = _ports_of(perm)
        rng = "all" if proto == "all" else (f"{frm}" if frm == to else f"{frm}-{to}")
        hits.append(f"{gid}:{proto}/{rng} from {world[0]}")
        evidence.append(doc.evidence(path, perm))
    return hits, evidence


def derive_default_sg_in_use(doc: JsonDocument, params: dict):
    """A default security group carrying rules -- AWS ships one per VPC."""
    hits, evidence = [], []
    for gpath, g in doc.query("$[*]", count=False):
        if isinstance(g, dict) and g.get("GroupName") == "default":
            if g.get("IpPermissions"):
                hits.append(g.get("GroupId", "?"))
                evidence.append(doc.evidence(gpath, g.get("IpPermissions")))
    return hits, evidence


DERIVATIONS: dict[str, Callable[[JsonDocument, dict], tuple[Any, list]]] = {
    "admin_ports_open_to_world": derive_admin_ports_open_to_world,
    "any_any_rules": derive_any_any_rules,
    "unrestricted_ingress": derive_unrestricted_ingress,
    "default_sg_in_use": derive_default_sg_in_use,
}


# ---------------------------------------------------------------------------
def apply_json_pack(
    doc: JsonDocument, pack: Pack, *, assessment_id: str, sha256: str
) -> SecurityBaselineModel:
    """Run a pack over a JSON document and build the SBM."""
    sbm = SecurityBaselineModel(
        assessment_id=assessment_id, source_file=doc.source_file, source_sha256=sha256
    )

    for m in pack.mappings:
        target_type = m.as_type or FIELD_TYPES.get(_unscope(m.field), "str")

        if m.const is not None:
            sbm.set(m.field, Observation.default_assumed(m.const, field_path=m.field))
            continue

        hits = doc.query(m.jsonpath) if m.jsonpath else []
        if hits and (m.value or {}).get("from") == "keys":
            # The table's KEYS are the values. SONiC writes NTP and syslog
            # servers, and SNMP communities, as the keys of a table:
            # "NTP_SERVER": {"0.pool.ntp.org": {}}. Reading the value would
            # yield a list of empty objects and report "no servers".
            hits = [(f"{p}.{k}", k) for p, v in hits
                    if isinstance(v, dict) for k in v.keys()]
        if not hits:
            if m.if_absent is not None:
                sbm.set(m.field, Observation.default_assumed(m.if_absent, field_path=m.field))
            else:
                sbm.set(m.field, Observation.not_observed(field_path=m.field))
            continue

        if m.scope:
            # Plan 2.3.1: every field is scoped. Three security groups have
            # three ids; collapsing them to hits[0] would silently hide two
            # thirds of the estate and make per-group findings impossible.
            #
            # Scope is resolved by PATH CONTAINMENT, not by list position.
            # Index alignment breaks the moment a scope contains a variable
            # number of children: 3 groups holding 1+3+2 ingress rules gave
            # 6 hits against 3 ids, and the overflow silently invented scope
            # ids "3", "4", "5" -- three security groups that do not exist.
            scope_map = _scope_index(doc, m.scope)
            # Collect first, write once per scope. Writing per hit made each
            # later rule overwrite the previous one, so a group with three
            # ingress rules reported one -- silently dropping two real rules
            # from the assessment.
            grouped: dict[str, list[tuple[str, Any]]] = {}
            for path, value in hits:
                sid = _scope_for(path, scope_map) or "unscoped"
                grouped.setdefault(str(sid), []).append((path, value))

            for sid, items in grouped.items():
                scoped = _scope_field(m.field, sid)
                if target_type == "list":
                    values = [v for _, v in items]
                    ev = [doc.evidence(p, v) for p, v in items]
                    sbm.set(scoped, Observation.observed(values, ev, field_path=scoped))
                else:
                    path, value = items[0]
                    coerced = normalise(value, target_type)
                    sbm.set(
                        scoped,
                        Observation.observed(coerced, [doc.evidence(path, value)], field_path=scoped)
                        if coerced is not None
                        else Observation.unparsed([doc.evidence(path, value)], field_path=scoped),
                    )
            continue

        if target_type == "list":
            values = [v for _, v in hits]
            ev = [doc.evidence(p, v) for p, v in hits]
            sbm.set(m.field, Observation.observed(values, ev, field_path=m.field))
        else:
            path, value = hits[0]
            coerced = normalise(value, target_type)
            obs = (
                Observation.observed(coerced, [doc.evidence(path, value)], field_path=m.field)
                if coerced is not None
                # Plan 6.5: a value we could not coerce is UNPARSED -> UNKNOWN,
                # never a guess.
                else Observation.unparsed([doc.evidence(path, value)], field_path=m.field)
            )
            sbm.set(m.field, obs)

    for d in pack.derivations:
        fn = DERIVATIONS.get(d.op)
        if fn is None:
            continue  # validate_fields() reports this; do not fail the scan
        value, ev = fn(doc, d.params)
        sbm.set(
            d.field,
            Observation.observed(value, ev, field_path=d.field)
            if ev
            # No hits is a real, provable observation: nothing matched. But with
            # no evidence to cite we record it as an empty observed list via the
            # registry source, so it can still satisfy a contains_none control.
            else Observation.default_assumed(value, field_path=d.field),
        )

    snap = doc.accounting_snapshot()
    sbm.accounting.total = doc.total_records
    sbm.accounting.record(RecordState.PARSED, snap[RecordState.PARSED.value])
    sbm.accounting.record(RecordState.UNKNOWN, snap[RecordState.UNKNOWN.value])
    return sbm
