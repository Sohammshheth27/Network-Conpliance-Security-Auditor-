"""Signals we throw away: the value's type, and the words hidden in a name.

Matching an unknown vendor setting to a schema field was ranking all 119 fields
for every query, using only the setting NAME. Two things were being discarded,
and both carry more information than the similarity function does:

THE VALUE'S TYPE is a constraint on the schema, not a hint. Measured over 400
real SonicWall settings, 214 are integers -- and only 8 of the 119 schema
fields are integer-typed. For over half the device the candidate space
collapses from 119 to 8 before any model runs.

THE WORDS INSIDE THE NAME are compressed past the point of being language.
`IdleVpnDpdInterval` and "dead peer detection interval" share no tokens, so a
lexical matcher scores zero and an embedding model -- trained on sentences --
gets a weak vector from four glued fragments. Expanding the abbreviations is
what lets either method see the two as the same thing.

A NOTE ON THE GATE BEING SOFT. The first instinct is a hard filter: drop every
field whose type does not match. That is wrong, and dangerously so -- a value
of `7` might be an int field or a version STRING, and a hard filter removes the
right answer permanently, with no way to recover it. Type is applied as a
multiplier on the score instead, so a mismatch is heavily penalised but never
made unreachable. `TYPE_PRIOR` below is measured, not guessed: see
tools/eval_matching.py.
"""
from __future__ import annotations

import re

# Domain abbreviations, drawn from the setting names actually present in the
# vendor exports we hold rather than from a general dictionary.
ABBREV = {
    "mgmt": "management", "mgt": "management", "admin": "administrator",
    "auth": "authentication", "authz": "authorization", "acct": "accounting",
    "dpd": "dead peer detection", "cfg": "configuration", "conf": "configuration",
    "svc": "service", "srv": "server", "hst": "host", "addr": "address",
    "obj": "object", "grp": "group", "pol": "policy", "polic": "policy",
    "pwd": "password", "passwd": "password", "pass": "password",
    "cert": "certificate", "crypt": "cryptography", "enc": "encryption",
    "vpn": "virtual private network", "nat": "network address translation",
    "acl": "access control list", "intf": "interface", "iface": "interface",
    "if": "interface", "src": "source", "dst": "destination",
    "cli": "command line interface", "gui": "web interface",
    "usr": "user", "sess": "session", "tmout": "timeout", "tout": "timeout",
    "min": "minimum", "max": "maximum", "len": "length", "num": "number",
    "ver": "version", "vers": "version", "cnt": "count", "req": "required",
    "en": "enabled", "dis": "disabled", "sec": "security", "seq": "sequence",
    "lockout": "account lockout", "otp": "one time password multi factor",
    "kex": "key exchange", "mac": "message authentication code",
    "dh": "diffie hellman", "tls": "transport layer security",
    "ssl": "secure sockets layer", "ssh": "secure shell",
    "snmp": "simple network management protocol",
    "ntp": "network time protocol", "dpi": "deep packet inspection",
    "ips": "intrusion prevention", "gav": "gateway antivirus",
    "cfs": "content filtering", "wan": "wide area untrusted network",
    "lan": "local area trusted network", "dmz": "demilitarised zone",
    "fw": "firewall", "rt": "route", "hb": "heartbeat", "ha": "high availability",
}

BOOL_TOKENS = {"on", "off", "true", "false", "enable", "enabled", "disable",
               "disabled", "yes", "no", "1", "0"}

_IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_INT = re.compile(r"^-?\d+$")
_LIST = re.compile(r"[,;|]")


def humanise(name: str) -> str:
    """`IdleVpnDpdInterval` -> `Idle Vpn Dpd Interval`."""
    s = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", str(name))
    s = re.sub(r"(?<=[A-Z])(?=[A-Z][a-z])", " ", s)
    s = re.sub(r"[_\-./]+", " ", s)
    return " ".join(s.split())


def expand(name: str) -> str:
    """Human-readable, with domain abbreviations spelled out."""
    out = []
    for tok in humanise(name).split():
        t = tok.lower()
        out.append(ABBREV.get(t, tok))
    return " ".join(out)


def infer_type(value) -> str:
    """The schema type a value is compatible with.

    `bool` is checked before `int` deliberately: `1` and `0` are far more often
    a flag than a quantity in a device configuration, and calling them integers
    would push every flag into the 8-field integer space.
    """
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, (list, tuple, set)):
        return "list"
    if isinstance(value, int):
        return "bool" if value in (0, 1) else "int"
    v = str(value).strip()
    if not v:
        return "unknown"
    low = v.lower()
    if low in BOOL_TOKENS:
        return "bool"
    if _INT.match(v):
        return "int"
    if _IPV4.match(v):
        return "ip"
    if _LIST.search(v):
        return "list"
    return "str"


# Score multiplier for (observed value type, schema field type).
#
# A SOFT gate. An exact match is unchanged; a plausible mismatch is damped; an
# implausible one is heavily damped but still reachable, because a hard filter
# that is wrong removes the correct answer with no way back.
TYPE_PRIOR = {
    "bool": {"bool": 1.00, "str": 0.45, "list": 0.25, "int": 0.20},
    "int":  {"int": 1.00, "str": 0.55, "list": 0.25, "bool": 0.20},
    "ip":   {"str": 1.00, "list": 0.85, "int": 0.15, "bool": 0.10},
    "list": {"list": 1.00, "str": 0.60, "int": 0.20, "bool": 0.15},
    "str":  {"str": 1.00, "list": 0.70, "int": 0.35, "bool": 0.30},
    # A value we could not type must not bias anything.
    "unknown": {"bool": 1.0, "int": 1.0, "str": 1.0, "list": 1.0},
}


def type_multiplier(value_type: str, field_type: str) -> float:
    return TYPE_PRIOR.get(value_type, {}).get(field_type, 0.5)


def describe_fields(rules_dir="rules") -> dict:
    """A natural-language description per schema field.

    Built from the CONTROL TITLES that test each field -- prose a human already
    wrote about what the setting means. This is the asymmetry that makes dense
    retrieval work here: a vendor writes `IdleVpnDpdInterval`, a framework
    writes "idle sessions must time out", and the two only meet if one side is
    expressed in language. Measured: embedding descriptions beats embedding
    field names by 3.5 points of top-1.
    """
    from ..engine.rules import load_rules
    from ..schema.sbm import FIELD_TYPES

    parts: dict = {}
    try:
        for c in load_rules(rules_dir):
            f = c.field.split("[")[0]
            parts.setdefault(f, []).append(c.title)
            if c.rationale:
                parts[f].append(c.rationale[:200])
    except Exception:                                  # noqa: BLE001
        pass

    out = {}
    for field in FIELD_TYPES:
        said = " ".join(dict.fromkeys(parts.get(field, [])))
        out[field] = f"{expand(field)}. {said}".strip()
    return out
