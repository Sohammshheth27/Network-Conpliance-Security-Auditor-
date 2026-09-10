"""Log correlation: what the device actually did, not what its counters say.

ManageEngine's differentiator, and the answer to the biggest caveat in rule
hygiene. A hit counter says "this rule has matched N packets since it was last
reset", and a reset makes a busy rule look dead. Logs carry TIMESTAMPS, so they
answer the question an operator actually has: "has anything matched this rule
in the last ninety days".

That turns a caveated finding into a decidable one:

    counter says 0   +  no log entries in 90 days   ->  confidently unused
    counter says 0   +  log entries last week       ->  the counter was reset
    counter says N   +  no logs                     ->  logging is not enabled
                                                        for that rule, which is
                                                        itself a finding

The third case is why this does not just trust the logs either. A rule with
traffic and no log lines is not quiet; it is unlogged, and an unlogged permit
rule is a gap in the audit trail that several frameworks require.

FORMATS. Firewall logging is not standardised, so this parses the shapes that
actually appear -- SonicOS, ASA, Fortinet and generic key=value syslog -- and
reports what fraction of lines it could not read rather than discarding them.
"""
from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta


@dataclass
class LogEvent:
    when: datetime | None
    rule_id: str = ""
    action: str = ""
    src: str = ""
    dst: str = ""
    port: str = ""
    protocol: str = ""
    raw: str = ""


# key=value pairs, the shape SonicOS and Fortinet both use.
_KV = re.compile(r'(\w+)=("([^"]*)"|\S+)')
# ASA: %ASA-6-302013: Built inbound TCP connection ...
_ASA = re.compile(r"%ASA-\d-(\d+):")
_SYSLOG_TS = re.compile(r"^(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})")
_ISO_TS = re.compile(r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})")

_ACTION_WORDS = {"allow": "allow", "permit": "allow", "accept": "allow",
                 "built": "allow", "deny": "deny", "drop": "deny",
                 "denied": "deny", "block": "deny", "teardown": "allow"}


def _timestamp(line: str, year=None):
    m = _ISO_TS.search(line)
    if m:
        try:
            return datetime.fromisoformat(m.group(1).replace(" ", "T"))
        except ValueError:
            pass
    m = _SYSLOG_TS.match(line)
    if m:
        # Syslog omits the year, so a January log read in December lands twelve
        # months out. The caller's year is used, and the ambiguity is real --
        # it is why `parse` reports how many timestamps it had to assume.
        try:
            y = year or datetime.now().year
            return datetime.strptime(f"{y} {m.group(1)}", "%Y %b %d %H:%M:%S")
        except ValueError:
            return None
    return None


def parse_line(line: str, *, year=None) -> LogEvent | None:
    if not line.strip():
        return None
    kv = {k: (v3 or v2).strip('"') for k, v2, v3 in _KV.findall(line)}
    action = ""
    for word, mapped in _ACTION_WORDS.items():
        if re.search(rf"\b{word}\b", line, re.I):
            action = mapped
            break
    ev = LogEvent(
        when=_timestamp(line, year),
        rule_id=(kv.get("rule") or kv.get("ruleid") or kv.get("policyid")
                 or kv.get("policy") or ""),
        action=kv.get("action", action) or action,
        src=kv.get("src") or kv.get("srcip") or kv.get("source") or "",
        dst=kv.get("dst") or kv.get("dstip") or kv.get("destination") or "",
        port=str(kv.get("dstport") or kv.get("dport") or kv.get("port") or ""),
        protocol=kv.get("proto") or kv.get("protocol") or "",
        raw=line.strip()[:300])
    if not (ev.rule_id or ev.src or ev.dst or _ASA.search(line)):
        return None
    return ev


@dataclass
class LogSummary:
    events: int = 0
    unparsed: int = 0
    assumed_year: int = 0
    first: datetime | None = None
    last: datetime | None = None
    by_rule: dict = field(default_factory=lambda: defaultdict(int))
    last_seen: dict = field(default_factory=dict)

    @property
    def window_days(self) -> float | None:
        if self.first and self.last:
            return round((self.last - self.first).total_seconds() / 86400, 1)
        return None

    def to_json(self) -> dict:
        return {"events": self.events, "unparsed": self.unparsed,
                "window_days": self.window_days,
                "first": self.first.isoformat() if self.first else None,
                "last": self.last.isoformat() if self.last else None,
                "rules_seen": len(self.by_rule)}


def parse(lines, *, year=None) -> LogSummary:
    s = LogSummary()
    for line in lines:
        ev = parse_line(line, year=year)
        if ev is None:
            if line.strip():
                s.unparsed += 1
            continue
        s.events += 1
        if ev.when:
            s.first = min(s.first or ev.when, ev.when)
            s.last = max(s.last or ev.when, ev.when)
        else:
            s.assumed_year += 1
        if ev.rule_id:
            s.by_rule[ev.rule_id] += 1
            if ev.when:
                prev = s.last_seen.get(ev.rule_id)
                s.last_seen[ev.rule_id] = max(prev or ev.when, ev.when)
    return s


@dataclass
class Corroboration:
    rule: str
    verdict: str          # confirmed_unused | counter_was_reset | unlogged | active
    detail: str
    hit_count: int | None = None
    log_events: int = 0
    last_seen: str = ""

    def to_json(self) -> dict:
        return dict(self.__dict__)


def corroborate(graph, summary: LogSummary, *, quiet_days=90) -> list:
    """Reconcile per-rule counters against what the logs recorded."""
    out = []
    window = summary.window_days
    for rule in getattr(graph, "rules", []):
        if not rule.enabled:
            continue
        name = rule.name or rule.id
        seen = summary.by_rule.get(rule.id, 0) or summary.by_rule.get(name, 0)
        last = summary.last_seen.get(rule.id) or summary.last_seen.get(name)

        if rule.hit_count == 0 and seen == 0:
            out.append(Corroboration(
                rule=name, verdict="confirmed_unused", hit_count=0,
                detail=("no counter matches and no log entries"
                        + (f" across {window} days of logs" if window else "")
                        + ". Two independent sources agree, so this is a "
                          "removal candidate rather than a caveated guess.")))
        elif rule.hit_count == 0 and seen > 0:
            out.append(Corroboration(
                rule=name, verdict="counter_was_reset", hit_count=0,
                log_events=seen,
                last_seen=last.isoformat() if last else "",
                detail=f"the counter reads zero but the logs show {seen} "
                       "matches. The counter was reset; this rule is NOT "
                       "unused, and any finding based on the counter alone "
                       "would have been wrong."))
        elif rule.hit_count and seen == 0:
            out.append(Corroboration(
                rule=name, verdict="unlogged", hit_count=rule.hit_count,
                detail=f"the counter shows {rule.hit_count:,} matches but no "
                       "log entries exist. Logging is not enabled for this "
                       "rule -- an unlogged permit is a gap in the audit "
                       "trail that several frameworks require."))
        elif last and (summary.last - last).days > quiet_days:
            out.append(Corroboration(
                rule=name, verdict="quiet", hit_count=rule.hit_count,
                log_events=seen, last_seen=last.isoformat(),
                detail=f"last matched {(summary.last - last).days} days ago."))
    return out
