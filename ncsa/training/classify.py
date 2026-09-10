"""Triage records that were parsed but never mapped to the schema.

A device can be read completely and still be barely understood. The SonicWall
in this repo parses 92,635 of 92,635 records and maps 8,421 of them; the other
84,214 are perfectly legible and entirely inert, because no SBM field claims
them and therefore no control can ask a question about them.

Presenting that 84,214 as the gap would be dishonest in the other direction --
half of it is empty strings and zeros, and most of the rest is interface
counters and licensing state that has no place in a SECURITY baseline. Mapping
those would inflate coverage without improving a single finding.

What matters is the security-relevant remainder, counted in DISTINCT SETTING
NAMES rather than records: 9,711 records collapse to ~610 names, because one
setting appears once per interface, per rule, per zone. 610 is a queue a person
can work through. 84,214 is a number that makes people give up.
"""
from __future__ import annotations

import re

# Names that plausibly bear on security posture. Deliberately broad: a false
# positive costs a reviewer one glance, a false negative silently drops a
# setting nobody will ever look at again.
#
# Long keywords are safe to match anywhere. SHORT ones are not, and are
# handled by SECURITY_SHORT below -- see the note there.
SECURITY = re.compile(
    r"(passw|secret|auth|admin|login|cipher|crypt|ssh|snmp|syslog|"
    r"audit|banner|ntp|mgmt|manage|polic|rule|zone|firewall|vpn|"
    r"ipsec|cert|radius|ldap|tacacs|lockout|idle|timeout|dpi|"
    r"botnet|antispy|block|deny|permit|trust|"
    # Crypto primitives and key material. Without these, sonicOsApi_dgstMD5
    # and sonicOsApi_pubKeyBits -- the REST API's digest algorithm and key
    # length -- were classified as ordinary device state.
    r"md5|sha1|sha2|sha25|sha51|dgst|digest|pubkey|keybits|keysize|"
    # Privilege and role. userGroupObjPrivMask is an authorisation mask.
    r"priv|role|permission|"
    # Web-API attack surface. CORS policy on a management API decides which
    # origins may drive the device; it belongs in an audit.
    r"cors|csrf|xsrf|xss|origin|hsts|samesite)", re.I)

# Keywords strong enough to overrule the cosmetic filter. `prefsParamEncryptMethod`
# is how stored parameters are encrypted; COSMETIC's `pref` was swallowing it
# because the name begins "prefs". A name carrying one of these is security,
# whatever else it looks like.
STRONG = re.compile(r"(passw|secret|auth|crypt|cipher|pubkey|digest|dgst)", re.I)

# Short keywords that collide inside unrelated words. Measured on the real
# SonicWall export, plain substring matching produced:
#
#     ssl  matched  guestProfileObjSes[sLif]e   -- a session lifetime
#     ips  matched  ZR[ipS]Mode, ZR[ipS]plitH   -- RIP split-horizon
#     gav  matched  [gav]ObjProperties          -- an object-table column
#     cfs  matched  [cfs]ProfileObjId           -- likewise
#
# 127 of 805 queue entries came in this way. They are required to sit on a
# token boundary instead: the start of the name, after an underscore or digit,
# or at a camelCase hump. `sslVersion` and `iface_ssl_enable` still match;
# `SessLife` no longer does.
# NOTE the (?-i:) around the boundary. With re.I applied to the whole pattern,
# `[A-Z]` also matches lowercase, so the camelCase hump matched everywhere and
# the boundary did nothing at all -- `guestProfileObjSessLife` still came
# through on the "ssl" inside "SessLife". The boundary must be case-SENSITIVE
# while the keywords stay case-insensitive.
SECURITY_SHORT = re.compile(
    r"(?:^|_|\d|(?-i:(?<=[a-z])(?=[A-Z]))|(?-i:(?<=[A-Z])(?=[A-Z][a-z])))"
    r"(ssl|tls|ips|gav|cfs|geo|mfa|otp|acl|log|time)", re.I)

# Record-keeping that merely CONTAINS a security-looking word. `time` matches
# `addrObjTimeCreated`, `log` matches `logEvtAttrs`, `polic` matches
# `policySrcIf` -- and ranked by occurrence count those bookkeeping fields sat
# at the very top of the queue, ahead of every real setting. A queue whose
# first seven entries are creation timestamps is one nobody finishes.
METADATA = re.compile(
    r"(TimeCreated|TimeUpdated|CreatedTime|UpdatedTime|_?uuid|Serialized|"
    r"EvtAttrs|Attrs$|Index$|Count$|Idx$|Handle$|Ordinal$|Checksum$|"
    r"^.*(Created|Updated|Modified)(By|At|Time)?$)", re.I)

# SonicOS stores most feature state as OBJECT TABLES, and every table repeats
# the same structural columns: gavObjId, gavObjType, gavObjProperties,
# cfsProfileObjId, schedObjInstanceId. The column is bookkeeping regardless of
# which feature owns the table -- `gavObjType` says nothing about antivirus
# policy, it says a row exists.
#
# 271 of 805 queue entries were these columns. Ranked by occurrence they
# outranked every real setting, which is how a reviewer ends up scrolling past
# object ids looking for something actionable.
#
# The FEATURE-BEARING columns of the same tables (gavObjEnabled, cfsPolicyAction)
# do not match this pattern and still reach the queue.
# `Obj\w*` rather than `Obj` directly: SonicOS repeats the owning feature in
# the column name, so the antivirus table's type column is `gavObjGavType`, not
# `gavObjType`. Requiring adjacency let every such column through.
TABLE_COLUMN = re.compile(
    r"(Obj\w*(Id|Type|Properties|InstanceId)|"
    r"Obj(Name|Comment)|"
    r"InstanceId|TableName|TableIntInsId|"
    r"^.*(SPI|Ordinal|RowId|Seq|Slot)$)$", re.I)

# Presentation and wizard state. Never security, always noise.
COSMETIC = re.compile(
    r"(gui|wizard|display|column|widget|dashboard|theme|tooltip|pref|layout|"
    r"sort|chart|graphview|tab_|icon|banner_?img|logo|wallpaper|colou?r)", re.I)

# Values that carry no information: an unset field maps to nothing.
_EMPTY = {"", "0", "off", "false", "no", "0.0.0.0", "::", "-1", "none", "null"}

CAT_SECURITY = "security-relevant"
CAT_COSMETIC = "GUI / display state"
CAT_EMPTY = "empty or default-off"
CAT_OTHER = "other device state"


def base_name(key: str) -> str:
    """Strip the instance index: `policyName_68` and `policyName_71` are one
    setting observed twice, not two settings."""
    return re.sub(r"_\d+$", "", key)


def is_empty(value) -> bool:
    return str(value).strip().lower() in _EMPTY


def classify(key: str, value) -> str:
    name = base_name(key)
    if is_empty(value):
        return CAT_EMPTY
    # A strong crypto/credential keyword outranks the cosmetic filter, which
    # is otherwise free to swallow a real setting whose name merely starts
    # "prefs" or "display".
    if STRONG.search(name):
        return CAT_SECURITY
    if COSMETIC.search(name):
        return CAT_COSMETIC
    if METADATA.search(name):
        return CAT_OTHER          # bookkeeping, whatever word it contains
    if TABLE_COLUMN.search(name):
        return CAT_OTHER          # an object-table column, not a setting
    if SECURITY.search(name) or SECURITY_SHORT.search(name):
        return CAT_SECURITY
    return CAT_OTHER
