"""Vendor value -> canonical value.

Why this module exists
----------------------
Guardrail 5 (plan 10.1) validates types with Pydantic: ``ssh.version`` must be
an int in {1, 2}, ``*.enabled`` must be a bool. But vendors do not write
canonical values:

    Cisco     ip ssh version 2                        -> "2"
    Juniper   set system services ssh protocol-version v2  -> "v2"
    FortiOS   set strong-crypto enable                -> "enable"
    SONiC     "protocol_version": 2                   -> 2

A bench test of qwen3.5:4b on the Juniper line returned ``value="v2"`` -- the
*correct* interpretation. Without normalisation, guardrail 5 would reject it as
a type failure, throwing away a right answer and inflating the UNKNOWN rate.

So normalisation runs BEFORE validation, never instead of it. If a value cannot
be normalised we return None and the caller records UNKNOWN -- plan 6.5's
critical rule: never guess.
"""
import re

# Tokens that mean "off". Order matters only for readability.
_FALSE_TOKENS = {
    "no", "off", "disable", "disabled", "false", "0", "deny", "none",
    "clear", "unset", "inactive", "down",
}
_TRUE_TOKENS = {
    "yes", "on", "enable", "enabled", "true", "1", "permit", "allow",
    "set", "active", "up",
}

_VERSION_PREFIX = re.compile(r"^v(?=\d)", re.IGNORECASE)   # v2 -> 2, but not "vty"
_LEADING_INT = re.compile(r"^\s*(-?\d+)\s*$")


def to_bool(raw: object) -> bool | None:
    """Normalise a vendor token to a boolean, or None if genuinely ambiguous."""
    if isinstance(raw, bool):
        return raw
    if raw is None:
        return None
    token = str(raw).strip().lower()
    if token in _TRUE_TOKENS:
        return True
    if token in _FALSE_TOKENS:
        return False
    return None


def to_int(raw: object) -> int | None:
    """Normalise a vendor token to an int.

    Handles the ``v2`` / ``version 2`` / ``2`` spread that broke the bench test.
    """
    if isinstance(raw, bool):          # bool is an int subclass -- reject early
        return None
    if isinstance(raw, int):
        return raw
    if raw is None:
        return None
    token = str(raw).strip().lower()
    token = re.sub(r"^version\s+", "", token)   # "version 2" -> "2"
    token = _VERSION_PREFIX.sub("", token)      # "v2"        -> "2"
    m = _LEADING_INT.match(token)
    return int(m.group(1)) if m else None


def to_str(raw: object) -> str | None:
    if raw is None:
        return None
    s = str(raw).strip().strip('"').strip("'")
    return s or None


def to_list(raw: object) -> list | None:
    if raw is None:
        return None
    if isinstance(raw, (list, tuple, set)):
        return list(raw)
    s = str(raw).strip()
    if not s:
        return None
    return [p for p in re.split(r"[,\s]+", s) if p]


_COERCERS = {"bool": to_bool, "int": to_int, "str": to_str, "list": to_list}


def normalise(raw: object, as_type: str) -> object | None:
    """Coerce ``raw`` to ``as_type``. Returns None when it cannot be done.

    None is a deliberate signal, not a failure to try: the caller records
    UNKNOWN rather than guessing. Plan 10.5 -- UNKNOWN always beats a wrong PASS.
    """
    fn = _COERCERS.get(as_type)
    if fn is None:
        raise ValueError(f"unknown target type {as_type!r}; expected one of {sorted(_COERCERS)}")
    return fn(raw)
