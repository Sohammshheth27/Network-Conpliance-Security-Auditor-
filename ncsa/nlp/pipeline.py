"""The NLP interpretation pipeline -- plan section 12.

The problem statement asks for "Pattern Recognition and Natural Language
Processing (NLP)". It does NOT ask for an LLM. We implement both, and the LLM
only sees what this pipeline cannot resolve.

A config line is not natural language: `ip ssh version 2` has no grammar and no
ambiguity. So we apply NLP to the VOCABULARY, not to the sentences. The real
problem is that vendors use different words for the same concept:

    ssh        protocol-version   admin-ssh       SSH_SERVER
    timeout    admintimeout       idle-timeout    exec-timeout

Recognising that `admintimeout`, `exec-timeout` and `idle-timeout` mean the same
thing is semantic similarity over a technical vocabulary -- a legitimate NLP
task, and the one that actually matters here.

Why this tier exists at all (plan 12.7/12.8):
  * It answers the PS's real complaint -- brittleness. When a vendor renames
    `ip ssh version` in new firmware, TF-IDF still matches on `ssh` + `version`.
  * It is DEMO INSURANCE. If Ollama stalls on stage with a cold model, tier 2
    still answers in ~50 ms and the demo survives.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# 12.2 -- Tokenisation
# ---------------------------------------------------------------------------

_CAMEL = re.compile(r"([a-z])([A-Z])")
_SPLIT = re.compile(r"[\s\-_./,:;=\"'()\[\]]+")


def tokenize(line: str) -> list[str]:
    """Split a config line into comparable tokens.

    Three unrelated vendor lines become comparable because they end up sharing
    the tokens `ssh` and `version`. Tokenisation is what makes cross-vendor
    matching possible at all.
    """
    line = _CAMEL.sub(r"\1 \2", line)            # adminTimeout -> admin Timeout
    tokens = _SPLIT.split(line.lower())
    return [t for t in tokens if t and not t.isdigit()]


# ---------------------------------------------------------------------------
# 12.3 -- Domain normalisation
#
# Plan 12.3 calls this "the highest-value NLP asset in the project", and it is:
# genuinely vendor-neutral knowledge, about two hours to write, and it is what
# lets a vendor we have never seen resolve against vendors we have.
# ---------------------------------------------------------------------------

SYNONYMS: dict[str, list[str]] = {
    "ssh":        ["ssh", "sshv1", "sshv2", "sshd", "secure-shell", "secureshell"],
    "telnet":     ["telnet", "tty"],
    "http":       ["http", "web", "webui", "www", "http-server", "webaccess"],
    "https":      ["https", "ssl", "secure-server", "tls"],
    "version":    ["version", "protocol-version", "proto", "ver", "v"],
    "timeout":    ["timeout", "admintimeout", "idle", "idletimeout", "exec-timeout",
                   "session-timeout", "sessiontimeout", "time-out", "inactivity"],
    "logging":    ["logging", "syslog", "syslogd", "log", "audit", "eventlog"],
    "server":     ["server", "host", "collector", "destination", "remote"],
    "password":   ["password", "passwd", "secret", "credential", "passphrase", "pwd"],
    "length":     ["length", "min-length", "minlength", "minimum", "min", "size"],
    "complexity": ["complexity", "complex", "strong", "strength"],
    "banner":     ["banner", "motd", "login-message", "loginmessage",
                   "post-login-banner", "prelogin", "greeting", "message"],
    "snmp":       ["snmp", "snmpv1", "snmpv2", "snmpv2c", "snmpv3"],
    "community":  ["community", "communities", "commstring"],
    "ntp":        ["ntp", "sntp", "clock", "time", "timeserver"],
    "authenticate": ["authenticate", "authentication", "auth", "aaa", "login"],
    "authorize":  ["authorize", "authorization", "privilege", "role", "rbac", "class"],
    "encrypt":    ["encrypt", "encryption", "cipher", "crypto", "cryptographic"],
    "enable":     ["enable", "enabled", "on", "yes", "true", "permit", "allow"],
    "disable":    ["disable", "disabled", "off", "no", "false", "deny", "none", "unset"],
    "interface":  ["interface", "int", "port", "ethernet", "gigabitethernet", "vlan"],
    "access":     ["access", "access-class", "accesslist", "acl", "access-list",
                   "trusted", "allowlist", "management-access"],
    "user":       ["user", "username", "account", "administrator"],
    "transport":  ["transport", "protocol", "service", "input"],
    "retries":    ["retries", "retry", "attempts", "authentication-retries", "maxtries"],
}

# Vendor syntax keywords. `set` opens nearly every Junos and FortiOS line;
# `config`/`edit`/`next`/`end` bracket every FortiOS block. They are structure,
# not meaning, and including them made unrelated lines look similar.
STOPWORDS = {"set", "config", "edit", "next", "end", "ip", "the", "a", "to",
             "unit", "system", "no"}


_CANON: dict[str, str] = {}
for _canonical, _variants in SYNONYMS.items():
    for _v in _variants:
        _CANON[_v] = _canonical
    _CANON[_canonical] = _canonical


def normalize(tokens: list[str], *, drop_stopwords: bool = True) -> list[str]:
    """Map vendor words onto canonical concepts -- lemmatisation for networking."""
    out = []
    for t in tokens:
        if drop_stopwords and t in STOPWORDS:
            continue
        if t in _CANON:
            out.append(_CANON[t])
            continue
        # `sshv2` / `snmpv3` -- a concept fused with its version
        m = re.match(r"^([a-z]+?)v(\d)$", t)
        if m and m.group(1) in _CANON:
            out.extend([_CANON[m.group(1)], "version"])
            continue
        # Plurals. `time.servers` never matched a line saying `ntp server`,
        # so the disambiguation tiebreak scored 0 and the boolean presence
        # flag won instead -- a confident wrong answer at 0.78.
        if t.endswith("s") and t[:-1] in _CANON:
            out.append(_CANON[t[:-1]])
            continue
        out.append(t)
    return out


# ---------------------------------------------------------------------------
# 12.4 -- Named entity recognition
# ---------------------------------------------------------------------------

SERVICES = {"ssh", "telnet", "http", "https", "snmp", "ntp", "logging", "banner"}
ACTIONS = {"enable", "disable", "set", "permit", "deny"}
ATTRIBUTES = {"version", "timeout", "length", "complexity", "community", "server",
              "access", "retries", "transport", "authenticate", "authorize", "encrypt"}

_IP = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_NUM = re.compile(r"\b\d+\b")


@dataclass
class Entities:
    service: str | None = None
    action: str | None = None
    attribute: str | None = None
    values: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {"SERVICE": self.service, "ACTION": self.action,
                "ATTRIBUTE": self.attribute, "VALUE": self.values}


def tag(line: str) -> Entities:
    """Once a line resolves to SERVICE=ssh, ATTRIBUTE=version, VALUE=1, mapping
    it to `management.ssh.version` is mechanical regardless of vendor."""
    canon = normalize(tokenize(line))
    e = Entities()
    for t in canon:
        if e.service is None and t in SERVICES:
            e.service = t
        elif e.attribute is None and t in ATTRIBUTES:
            e.attribute = t
        elif e.action is None and t in ACTIONS:
            e.action = t
    e.values = _IP.findall(line) or _NUM.findall(line)
    return e


# ---------------------------------------------------------------------------
# 12.6 -- Value extraction
# ---------------------------------------------------------------------------

_FALSEY = {"no", "disable", "disabled", "deny", "off", "none", "unset", "false"}


def extract_value(line: str, as_type: str):
    """Pull the value out of a line, typed."""
    if as_type == "bool":
        toks = set(tokenize(line))
        return not bool(toks & _FALSEY)
    if as_type == "int":
        m = re.search(r"\bv?(\d+)\b", line)     # handles `v2` as well as `2`
        return int(m.group(1)) if m else None
    if as_type == "list":
        return [t for t in tokenize(line)][1:] or None
    ips = _IP.findall(line)
    if ips:
        return ips[0]
    m = re.search(r"\b([A-Za-z0-9_.:-]{2,})\s*$", line.strip())
    return m.group(1) if m else None
