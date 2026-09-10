"""Reference resolution -- doc section 4's algorithm, implemented.

    resolve(node):
        if primitive: return node
        if reference:
            target = graph.lookup(name)
            if missing: emit unresolved-reference evidence; return UNKNOWN
            if in recursion stack: emit cycle evidence; return UNKNOWN
            return resolve(target)
        if group: return union(resolve(child) for child in children)

Two behaviours matter more than the recursion:

  * A MISSING reference returns UNRESOLVED, never an empty set. An empty set
    silently satisfies "no internet-facing sources", turning a config we could
    not read into a clean bill of health -- a false PASS manufactured by a typo.

  * A CYCLE returns CYCLIC, never a partial union. Group A containing group B
    containing group A is a real thing in migrated configs, and a resolver that
    quietly returns whatever it collected before looping produces a plausible,
    wrong answer.
"""
from __future__ import annotations

from .model import NodeKind, ObjectGraph, Resolution, ResolutionState

# Anything that means "the whole internet" once resolved.
ANY_TOKENS = {"any", "any-ipv4", "any-ipv6", "all", "0.0.0.0/0", "::/0"}
INTERNET_CIDRS = {"0.0.0.0/0", "::/0"}


class Resolver:
    def __init__(self, graph: ObjectGraph):
        self.graph = graph
        self._cache: dict[str, Resolution] = {}

    def resolve(self, name: str) -> Resolution:
        if name in self._cache:
            return self._cache[name]
        res = self._resolve(name, stack=[])
        self._cache[name] = res
        return res

    def _resolve(self, name: str, stack: list[str]) -> Resolution:
        # `any` is a primitive meaning everything -- it is not a missing object.
        if name.lower() in ANY_TOKENS:
            return Resolution(name=name, state=ResolutionState.RESOLVED,
                              values=["0.0.0.0/0"], path=[name])

        if name in stack:
            return Resolution(
                name=name, state=ResolutionState.CYCLIC, path=stack + [name],
                detail=f"reference cycle: {' -> '.join(stack + [name])}",
            )

        node = self.graph.lookup(name)
        if node is None:
            # A literal written inline rather than as a named object.
            if _looks_like_literal(name):
                return Resolution(name=name, state=ResolutionState.RESOLVED,
                                  values=[name], path=[name])
            return Resolution(
                name=name, state=ResolutionState.UNRESOLVED, path=stack + [name],
                detail=f"no object named {name!r} exists in this configuration",
            )

        # A group whose membership the export does not publish is UNSUPPORTED,
        # not an empty set. An empty set silently satisfies "nothing exposed".
        if node.attrs.get("members_unknown") and not node.members:
            return Resolution(
                name=name, state=ResolutionState.UNSUPPORTED, path=stack + [name],
                detail=f"{name!r} is a group whose members are not present in "
                       "this export; its contents cannot be determined")
        if node.attrs.get("protocol_unknown") is not None and not node.values:
            return Resolution(
                name=name, state=ResolutionState.UNSUPPORTED, path=stack + [name],
                detail=f"{name!r} uses IP protocol code "
                       f"{node.attrs['protocol_unknown']!r} which we do not model")

        # An object that exists but carries NO value and NO members is not an
        # empty set -- it is an object we cannot evaluate. On a real NSA 3700,
        # "M0 IP" is the unconfigured management port: address 0.0.0.0, no zone.
        # Returning RESOLVED [] for it let the caller print "to any", turning an
        # interface that has no address into two critical internet-exposure
        # findings. Empty is never an answer; it is the absence of one.
        if not node.values and not node.members:
            return Resolution(
                name=name, state=ResolutionState.UNRESOLVED, path=stack + [name],
                detail=f"{name!r} exists but carries no address or port value in "
                       "this export (unconfigured interface, or an empty object)")

        if node.values and not node.members:
            return Resolution(name=name, state=ResolutionState.RESOLVED,
                              values=list(node.values), path=stack + [name])

        # Group: union of resolved children.
        values: list[str] = []
        paths: list[str] = []
        for member in node.members:
            child = self._resolve(member, stack + [name])
            if child.state is ResolutionState.CYCLIC:
                return child                     # a cycle poisons the whole group
            if child.state is ResolutionState.UNRESOLVED:
                # One bad member makes the whole group's membership uncertain.
                return Resolution(
                    name=name, state=ResolutionState.UNRESOLVED,
                    path=stack + [name] + child.path[len(stack) + 1:],
                    values=values,
                    detail=f"group {name!r} contains unresolved member "
                           f"{child.name!r}; effective membership is unknown",
                )
            values.extend(v for v in child.values if v not in values)
            paths.append(child.name)

        if not values:
            return Resolution(
                name=name, state=ResolutionState.UNRESOLVED,
                path=stack + [name] + (paths if paths else []),
                detail=f"group {name!r} resolves to nothing: its members carry "
                       "no address in this export")

        return Resolution(
            name=name, state=ResolutionState.RESOLVED, values=values,
            path=stack + [name] + (paths if paths else []),
        )

    # ------------------------------------------------------------------ rules
    def resolve_rule(self, rule) -> dict:
        """Resolve every reference in one rule. Returns a resolution report."""
        out = {"src": [], "dst": [], "svc": []}
        for key, names in (("src", rule.source), ("dst", rule.destination),
                           ("svc", rule.services)):
            for n in names:
                out[key].append(self.resolve(n))
        return out

    def unresolved_report(self) -> list[Resolution]:
        return [r for r in self._cache.values() if not r.ok]


def _looks_like_literal(token: str) -> bool:
    """Is this an inline value rather than a reference to a named object?

    The RANGE form is here because a real PAN-OS export writes literal ranges
    straight into a rule's member list -- "10.0.0.0-10.255.255.255" alongside
    named address objects. Without it the range was reported as a missing
    object, which made the whole rule unevaluable and put a caveat on every
    reachability answer above it. `_addr_in` has always understood ranges; only
    this gate did not, so a perfectly readable rule was being discarded.
    """
    import re
    return bool(
        re.match(r"^\d{1,3}(\.\d{1,3}){3}(/\d{1,2})?$", token)
        or re.match(r"^\d{1,3}(\.\d{1,3}){3}-\d{1,3}(\.\d{1,3}){3}$", token)
        or re.match(r"^[0-9a-fA-F:]+/\d{1,3}$", token)
        or re.match(r"^(tcp|udp|icmp)/\d+(-\d+)?$", token, re.I)
    )


def reaches_internet(resolutions: list[Resolution]) -> bool:
    """Does this resolved set include the whole internet?"""
    for r in resolutions:
        if r.ok and any(v in INTERNET_CIDRS for v in r.values):
            return True
    return False


def has_uncertainty(resolutions: list[Resolution]) -> list[Resolution]:
    """Anything that would make a finding INCOMPLETE rather than clean."""
    return [r for r in resolutions if not r.ok]
