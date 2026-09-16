"""The training queue -- what a human is asked to teach the system next.

This is the input side of the "Dynamic Adaptation" loop the problem statement
describes: raw unrecognised settings, presented for an administrator to map to
a security category. Until now nothing collected them, so `TierRouter` -- the
component that consults approved mappings and escalates the rest -- was never
called by anything.

The queue is deduplicated by SETTING NAME and ranked, because the useful unit
of work is "teach it what `IdleVpnDpdInterval` means", not "review 9,711
records". One approval covers every instance of that name on every device.

Ranking is by how much evidence there is for the setting mattering:
occurrences first (a setting present on 36 interfaces is load-bearing), then
whether an existing vendor pack already has a field for the same concept --
because that is a mapping we can propose rather than ask about.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from .classify import CAT_SECURITY, base_name, classify


@dataclass
class TrainingCandidate:
    """One setting name awaiting a meaning."""

    name: str
    occurrences: int = 0
    sample_values: list = field(default_factory=list)
    evidence_line: int = 0
    evidence_raw: str = ""
    vendor: str = ""
    platform: str = ""
    #: "value" -- the setting carries a value; "keys" -- the setting is a
    #: table whose KEYS are the values (SONiC's NTP_SERVER, SYSLOG_SERVER).
    kind: str = "value"
    # Filled by the NLP matcher when a known vendor expresses the same idea.
    suggested_field: str | None = None
    suggestion_score: float = 0.0
    suggested_from: str = ""

    def to_json(self) -> dict:
        return {"name": self.name, "occurrences": self.occurrences,
                "sample_values": self.sample_values[:5],
                "evidence": {"line": self.evidence_line, "raw": self.evidence_raw},
                "vendor": self.vendor, "platform": self.platform,
                "suggested_field": self.suggested_field,
                "suggestion_score": round(self.suggestion_score, 3),
                "suggested_from": self.suggested_from,
                "status": "PENDING"}


def build_queue(device_assessment, doc=None, *, only_security=True,
                with_suggestions=False, limit=None) -> list:
    """Collect unmapped settings from a parsed device into a ranked queue.

    ``doc`` is the parsed document (the reader object). When omitted, the
    assessment's carried `unrecognised` lines are used, which is all that is
    available for an unknown vendor with no pack at all.
    """
    ident = device_assessment.identity
    cands: dict[str, TrainingCandidate] = {}

    # Prefer the document the pipeline actually used: it carries pack AND
    # graph consumption. A freshly parsed copy knows only what the graph read.
    doc = doc or getattr(device_assessment, "document", None)
    records = _unmapped_records(device_assessment, doc)
    # A vendor with no pack at all has NOTHING mapped, identity included, so
    # the security filter would hide the very settings (hostname, servers)
    # that make its first pack useful. Everything is shown for such a device.
    security_only = only_security and device_assessment.supported
    for rec in records:
        key, value, line, raw = rec[:4]
        kind = rec[4] if len(rec) > 4 else "value"
        if security_only and classify(key, value) != CAT_SECURITY:
            continue
        name = base_name(key) if kind == "value" and "." not in key else key
        c = cands.get(name)
        if c is None:
            c = cands[name] = TrainingCandidate(
                name=name, evidence_line=line, evidence_raw=raw,
                vendor=ident.vendor, platform=ident.platform, kind=kind)
        c.occurrences += 1
        if value not in c.sample_values and len(c.sample_values) < 5:
            c.sample_values.append(value)

    out = sorted(cands.values(), key=lambda c: -c.occurrences)
    if with_suggestions:
        _suggest(out)
        # A proposable mapping outranks one we would have to ask about.
        out.sort(key=lambda c: (-c.suggestion_score, -c.occurrences))
    out = _apply_decisions(out, ident.platform)
    return out[:limit] if limit else out


def _apply_decisions(cands: list, platform: str) -> list:
    """Mark what a human already decided, and drop what they rejected.

    APPROVED stays visible until the device is re-assessed -- the mapping is
    written, but this assessment was produced before it existed. A REJECTED
    setting leaves the queue for good: asking again is how reviewers learn to
    click without reading.
    """
    try:
        from .apply import decisions, learned_settings
        rejected = decisions().get(platform, set())
        approved = learned_settings(platform)
    except Exception:                                  # noqa: BLE001
        return cands
    out = []
    for c in cands:
        if c.name in rejected:
            continue
        if c.name in approved:
            c.status = "APPROVED"
        out.append(c)
    return out


def _unmapped_records(device_assessment, doc):
    """(key, value, line, raw) for every parsed-but-unmapped record."""
    if doc is not None and hasattr(doc, "values") and hasattr(doc, "_consumed"):
        consumed = doc._consumed
        return [(k, v[0], v[1], v[2]) for k, v in doc.values.items()
                if v[1] - 1 not in consumed]
    if (doc is not None and hasattr(doc, "data") and hasattr(doc, "unread_paths")
            and not device_assessment.supported):
        return json_table_records(doc.data)
    if doc is not None and hasattr(doc, "unrecognised"):
        out = []
        for e in doc.unrecognised():
            raw = str(getattr(e, "raw", e))
            name, value = split_cli_line(raw)
            out.append((name, value if value else "<present>",
                        int(getattr(e, "line", 0) or 0), raw))
        return out
    # Unknown vendor: only the raw lines survived.
    out = []
    for i, l in enumerate(device_assessment.unrecognised):
        name, value = split_cli_line(l)
        if not name:
            continue
        # A CLI command with no argument is still a setting: the PRESENCE of
        # `service password-encryption` is the whole signal. Marking it empty
        # would drop exactly the directives that matter most.
        out.append((name, value if value else "<present>", i + 1, l))
    return out


def json_table_records(data) -> list:
    """(name, value, line, raw, kind) for a JSON config no pack covers.

    Walked as TABLES, not dotted leaf paths. SONiC writes NTP and syslog
    servers as the KEYS of a table -- "NTP_SERVER": {"0.pool.ntp.org": {}} --
    and a key containing dots turned the dotted path into nonsense. So:

      * a table of objects contributes one "keys" record per key, and
      * each field inside its objects becomes `TABLE.*.field`, with the
        instance key generalised to `*` so one approval covers every
        instance (every server, every port).

    Keys beginning with `_` are comments by convention and are skipped.
    """
    out: list = []
    if not isinstance(data, dict):
        return out
    for table, body in data.items():
        if str(table).startswith("_"):
            continue
        if isinstance(body, dict) and body and all(isinstance(v, dict) for v in body.values()):
            for key, child in body.items():
                out.append((table, str(key), 0,
                            f'"{table}": {{"{key}": ...}}', "keys"))
                for f, v in child.items():
                    if isinstance(v, (str, int, float, bool)):
                        out.append((f"{table}.*.{f}", v, 0,
                                    f'"{table}" / "{key}" / "{f}": {json.dumps(v)}',
                                    "value"))
        elif isinstance(body, dict):
            for f, v in body.items():
                if isinstance(v, (str, int, float, bool)):
                    out.append((f"{table}.{f}", v, 0,
                                f'"{table}" / "{f}": {json.dumps(v)}', "value"))
        elif isinstance(body, (str, int, float, bool)):
            out.append((str(table), body, 0, f'"{table}": {json.dumps(body)}', "value"))
    return out


# A token that is an ARGUMENT rather than part of the command name: numbers,
# addresses, times, and quoted strings.
_ARG = re.compile(r"^(\d+([.:/]\d+)*|\"[^\"]*\"|'[^']*'|\d+:\d+:\d+)$")


def split_cli_line(raw: str) -> tuple:
    """`ssh key-exchange group dh-group1-sha1` -> (name, value).

    The first version split every record on "=", which is the `.exp` shape and
    NOT the shape of any CLI. Every line of a Cisco ASA config therefore parsed
    as name=<whole line>, value=<empty>, and an empty value is classified as
    "nothing to map" -- so 113 unrecognised lines produced 0 training
    candidates. The training loop was silently dead for every CLI vendor, which
    is most of the ones the brief names.

    CLI has no separator, so the split is positional: leading keyword tokens
    are the setting name, and trailing argument-shaped tokens are its value.
    `no` is kept in the name because `no ip http server` is a different setting
    state from `ip http server`, not the same setting with a different value.
    """
    if "=" in raw:
        k, v = raw.split("=", 1)
        return k.strip(), v.strip()

    toks = raw.strip().split()
    if not toks:
        return "", ""
    # Walk back from the end while tokens look like arguments.
    cut = len(toks)
    while cut > 1 and _ARG.match(toks[cut - 1]):
        cut -= 1
    # A trailing bare word after >=2 keyword tokens is a value too
    # (`ssh key-exchange group dh-group1-sha1`).
    if cut == len(toks) and len(toks) >= 3:
        cut -= 1
    return " ".join(toks[:cut]), " ".join(toks[cut:])


def _val(raw: str):
    return split_cli_line(raw)[1]


def _suggest(candidates) -> None:
    """Ask what each unknown setting probably means.

    Measured on held-out vendors (tools/eval_matching.py, 233 labeled pairs):

        lexical only          top-1 33.9%   top-5 54.1%
        + type prior          top-1 49.4%   top-5 58.4%
        dense + type prior    top-1 51.1%   top-5 63.9%   <- used here
        hybrid + type prior   top-1 45.5%   top-5 64.8%

    Two results decided this. The VALUE's type is worth more than the
    similarity function -- 214 of 400 real settings are integers and only 8 of
    119 schema fields are integer-typed, so typing the value alone adds 15.5
    points. And fusing lexical with dense HURT top-1 (30.0%): reciprocal-rank
    fusion dilutes a strong ranking with a weak one, so the two are not
    combined for the top pick even though the fusion has the best top-5.

    A proposal is never applied. It is what the administrator is shown.
    """
    try:
        from ..nlp.matcher import NlpMatcher, corpus_from_packs
        from ..nlp.semantic import SemanticMatcher
        from ..paths import resolve_packs_dir
        lex = NlpMatcher(corpus_from_packs(str(resolve_packs_dir()), "samples")).fit()
        sem = SemanticMatcher(lexical=lex).fit()
    except Exception:                                  # noqa: BLE001
        return

    # One embedding round-trip for the whole queue, not one per candidate.
    try:
        from ..nlp.signals import expand
        sem.warm([expand(c.name) for c in candidates])
    except Exception:                                  # noqa: BLE001
        pass

    for c in candidates:
        value = c.sample_values[0] if c.sample_values else None
        try:
            hits = sem.match(c.name, value, k=1, use_lexical=False)
        except Exception:                              # noqa: BLE001
            continue
        if hits:
            field, score, why = hits[0]
            c.suggested_field = field
            # Already 0-100. The old x100 existed because the score was the
            # reciprocal-rank constant 0.01639 -- which also meant every
            # accepted suggestion reported an identical 1.639 and the queue
            # could not be ranked by likelihood at all. Multiplying the new
            # confidence would put it in the thousands.
            c.suggestion_score = float(score)
            c.suggested_from = why


def _humanise(name: str) -> str:
    """`IdleVpnDpdInterval` -> `Idle Vpn Dpd Interval`.

    Vendor setting names are glued camel case; the corpus is real CLI lines.
    Splitting the words is what lets them share any vocabulary at all.
    """
    import re
    s = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", name)
    s = re.sub(r"[_\-.]+", " ", s)
    return " ".join(s.split())


def save_queue(candidates, path="reference/training_queue.jsonl") -> dict:
    p = Path(path)
    with p.open("w", encoding="utf-8") as fh:
        for c in candidates:
            fh.write(json.dumps(c.to_json(), ensure_ascii=False) + "\n")
    return {"written": len(candidates), "path": str(p)}


def load_queue(path="reference/training_queue.jsonl") -> list:
    p = Path(path)
    if not p.exists():
        return []
    return [json.loads(l) for l in p.open(encoding="utf-8") if l.strip()]
