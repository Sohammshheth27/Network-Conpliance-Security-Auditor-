"""Comparison operators for controls.

Every operator returns a ResultState, never a bare bool, because "false" is not
a single thing here: a control can fail, partially pass, or be undecidable, and
plan 6.5's critical rule is that an undecidable check must surface as UNKNOWN
rather than be forced into PASS or FAIL.
"""
from __future__ import annotations

from typing import Any, Callable

from ..schema.enums import ResultState


def _as_set(v: Any) -> set:
    if v is None:
        return set()
    if isinstance(v, (list, tuple, set)):
        return {str(x).lower() for x in v}
    return {str(v).lower()}


def op_equals(observed: Any, expected: Any) -> ResultState:
    return ResultState.PASS if observed == expected else ResultState.FAIL


def op_not_equals(observed: Any, expected: Any) -> ResultState:
    return ResultState.PASS if observed != expected else ResultState.FAIL


def op_in(observed: Any, expected: Any) -> ResultState:
    allowed = expected if isinstance(expected, (list, tuple, set)) else [expected]
    return ResultState.PASS if observed in allowed else ResultState.FAIL


def op_not_in(observed: Any, expected: Any) -> ResultState:
    disallowed = expected if isinstance(expected, (list, tuple, set)) else [expected]
    return ResultState.PASS if observed not in disallowed else ResultState.FAIL


def op_gte(observed: Any, expected: Any) -> ResultState:
    try:
        return ResultState.PASS if observed >= expected else ResultState.FAIL
    except TypeError:
        return ResultState.UNKNOWN


def op_lte(observed: Any, expected: Any) -> ResultState:
    try:
        return ResultState.PASS if observed <= expected else ResultState.FAIL
    except TypeError:
        return ResultState.UNKNOWN


def op_contains_all(observed: Any, expected: Any) -> ResultState:
    """All required members present. Missing some is PARTIAL, not FAIL.

    Plan 6.5: this is exactly what PARTIAL is for -- "syslog configured but only
    one server". Forcing it to PASS would be dishonest; forcing it to FAIL would
    be unhelpful.
    """
    have, need = _as_set(observed), _as_set(expected)
    if not need:
        return ResultState.PASS
    if need <= have:
        return ResultState.PASS
    return ResultState.PARTIAL if (have & need) else ResultState.FAIL


def op_contains_none(observed: Any, expected: Any) -> ResultState:
    """No forbidden member present -- weak ciphers, telnet in transport.

    A PROHIBITION, so any forbidden member present is a FAIL. Partial credit
    for also offering something safe is not how an attacker experiences the
    device: `transport input telnet ssh` accepts telnet, and the presence of
    ssh alongside it changes nothing about that. This returned PARTIAL, which
    on a report sorts below FAIL and gets remediated later -- so a
    telnet-reachable router was quietly downgraded because it ALSO supported
    ssh. The same reasoning applies to a cipher list offering aes256 and des:
    the device accepts des.
    """
    have, forbidden = _as_set(observed), _as_set(expected)
    return ResultState.PASS if not (have & forbidden) else ResultState.FAIL


def op_min_count(observed: Any, expected: Any) -> ResultState:
    """At least N entries -- two syslog servers, two NTP sources.

    One when two are required is genuinely partial compliance.
    """
    items = observed if isinstance(observed, (list, tuple, set)) else ([] if observed is None else [observed])
    n = len(items)
    try:
        need = int(expected)
    except (TypeError, ValueError):
        return ResultState.UNKNOWN
    if n >= need:
        return ResultState.PASS
    return ResultState.PARTIAL if n > 0 else ResultState.FAIL


def op_max_count(observed: Any, expected: Any) -> ResultState:
    """At most N entries. ``expected: 0`` means "this list must be empty".

    Needed because min_count(0) trivially passes. The exposure derivations
    produce lists of violations, so "no violations" is a max_count check --
    and one violation of a critical control is a FAIL, not a PARTIAL.
    """
    items = observed if isinstance(observed, (list, tuple, set)) else ([] if observed is None else [observed])
    try:
        limit = int(expected)
    except (TypeError, ValueError):
        return ResultState.UNKNOWN
    return ResultState.PASS if len(items) <= limit else ResultState.FAIL


def op_matches(observed: Any, expected: Any) -> ResultState:
    import re

    if observed is None:
        return ResultState.FAIL
    try:
        return ResultState.PASS if re.search(str(expected), str(observed), re.I) else ResultState.FAIL
    except re.error:
        return ResultState.ERROR


def op_is_set(observed: Any, expected: Any = None) -> ResultState:
    """Present and non-empty -- banners, descriptions."""
    if observed is None:
        return ResultState.FAIL
    if isinstance(observed, str) and not observed.strip():
        return ResultState.FAIL
    if isinstance(observed, (list, dict, set, tuple)) and len(observed) == 0:
        return ResultState.FAIL
    return ResultState.PASS


OPERATORS: dict[str, Callable[[Any, Any], ResultState]] = {
    "equals": op_equals,
    "not_equals": op_not_equals,
    "in": op_in,
    "not_in": op_not_in,
    "gte": op_gte,
    "lte": op_lte,
    "contains_all": op_contains_all,
    "contains_none": op_contains_none,
    "min_count": op_min_count,
    "max_count": op_max_count,
    "matches": op_matches,
    "is_set": op_is_set,
}


def evaluate(operator: str, observed: Any, expected: Any) -> ResultState:
    fn = OPERATORS.get(operator)
    if fn is None:
        return ResultState.ERROR
    try:
        return fn(observed, expected)
    except Exception:
        # Plan 6.5: an evaluation that blows up is ERROR, never a silent PASS.
        return ResultState.ERROR
