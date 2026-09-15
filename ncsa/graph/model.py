"""The security object graph -- plan 15, and section 4 of the parser architecture doc.

WHY THIS EXISTS
---------------
A parser tells you what the file SAYS. This tells you what those references MEAN.

Configurations reference names, not values::

    set security policies from-zone untrust to-zone dmz policy allow-web
        match source-address HR_NET
        match destination-address WEB01
        match application HTTPS

`HR_NET` is not a subnet. It is a name that resolves -- possibly through nested
groups -- to a set of subnets. Until that is resolved, no security question can
be answered: "is RDP reachable from the internet" is unanswerable if you only
know the rule says `RDP_SERVICE`.

WHAT THIS IS NOT
----------------
This is deliberately NOT a full policy analyser. There is no NAT modelling and
no rule-shadowing analysis. Both are real and both matter for a firewall policy
product; neither is asked for by the NCSA problem statement, which is about
device hardening compliance. Building them would be scope for a different
product. What IS built is the part plan 15.2 depends on: resolve references so
that exposure can be COMPUTED rather than assumed.
"""
from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field

from ..schema.evidence import EvidenceRef


class NodeKind(str, Enum):
    ADDRESS = "address"
    ADDRESS_GROUP = "address_group"
    SERVICE = "service"
    SERVICE_GROUP = "service_group"
    ZONE = "zone"
    INTERFACE = "interface"
    RULE = "rule"
    USER = "user"


class ResolutionState(str, Enum):
    """Doc section 9: SUPPORTED / UNSUPPORTED / AMBIGUOUS / UNRESOLVED_REFERENCE.

    An unresolved reference does not fail the scan -- it makes any finding that
    depends on it INCOMPLETE, and says so with the exact reference path. That is
    the difference between "we checked and it is fine" and "we could not check".
    """

    RESOLVED = "RESOLVED"
    UNRESOLVED = "UNRESOLVED"      # the name does not exist in this config
    CYCLIC = "CYCLIC"              # group contains itself, directly or not
    UNSUPPORTED = "UNSUPPORTED"    # construct we do not model
    AMBIGUOUS = "AMBIGUOUS"        # more than one plausible target


class Node(BaseModel):
    """One object in the configuration."""

    model_config = {"frozen": False}

    id: str
    kind: NodeKind
    name: str = ""
    # Concrete values for leaf objects: CIDRs for addresses, "tcp/443" for services
    values: list[str] = Field(default_factory=list)
    # Names this node references. Unresolved until the resolver runs.
    members: list[str] = Field(default_factory=list)
    attrs: dict = Field(default_factory=dict)
    evidence: list[EvidenceRef] = Field(default_factory=list)

    def __str__(self) -> str:
        return f"{self.kind.value}:{self.name or self.id}"


class SecurityRule(BaseModel):
    """A policy rule, in vendor-neutral terms. Doc section 5's SecurityRule."""

    model_config = {"frozen": False}

    id: str
    name: str = ""
    order: int = 0
    enabled: bool = True
    action: str = "allow"
    source: list[str] = Field(default_factory=list)        # names, pre-resolution
    destination: list[str] = Field(default_factory=list)
    services: list[str] = Field(default_factory=list)
    source_zones: list[str] = Field(default_factory=list)
    destination_zones: list[str] = Field(default_factory=list)
    logging: bool | None = None
    # Packets matched since the counter last reset. None means the export does
    # not publish one -- which is NOT the same as zero, and the distinction
    # decides whether "this rule is dead" is a finding or a guess.
    hit_count: int | None = None
    # Host firewalls scope rules to a BINARY rather than a port. Such a rule
    # does not open a port to the network, so a port-based question cannot be
    # decided by it.
    program: str | None = None
    evidence: list[EvidenceRef] = Field(default_factory=list)


class Resolution(BaseModel):
    """The result of resolving one reference. Carries the path, always.

    Doc section 8's evidence contract requires the resolution PATH, not just the
    answer: `RDP_SERVICE -> TCP/3389`. Without it a reader cannot check our work,
    which is the whole point of an audit tool.
    """

    name: str
    state: ResolutionState
    values: list[str] = Field(default_factory=list)
    path: list[str] = Field(default_factory=list)
    detail: str = ""

    @property
    def ok(self) -> bool:
        return self.state is ResolutionState.RESOLVED

    def __str__(self) -> str:
        arrow = " -> ".join(self.path) if self.path else self.name
        return f"{arrow} = {self.values}" if self.ok else f"{arrow} [{self.state.value}]"


class ObjectGraph(BaseModel):
    """A policy, vendor-neutrally.

    All objects and rules from one device, before resolution.

    `unordered` marks platforms with no positional evaluation -- Windows
    Firewall matches by precedence (block beats allow) rather than
    top-to-bottom. Shadow analysis assumes first-match-wins, so it must not
    run there: a "shadowed rule" finding on an unordered platform describes
    semantics the device does not have.
    """

    model_config = {"frozen": False}

    nodes: dict[str, Node] = Field(default_factory=dict)
    rules: list[SecurityRule] = Field(default_factory=list)
    zones_of_interface: dict[str, str] = Field(default_factory=dict)
    untrusted_zones: set[str] = Field(default_factory=set)
    # Read from the config where the vendor exposes it. NOT assumed -- see the
    # default-policy note in junos_builder.
    unordered: bool = False
    default_action: str = "deny"
    default_action_observed: bool = False
    #: The line that STATES the default policy, where the config states one.
    #:
    #: Without this the bridge cited an arbitrary rule's evidence for the
    #: default policy -- misleading even when it worked, and outright wrong on
    #: a device with a `permit-all` default and no rules at all: there was no
    #: rule to borrow evidence from, so an observed permit-all degraded to an
    #: assumption and the finding disappeared. That is the exact false PASS the
    #: Junos builder exists to prevent.
    default_action_evidence: list[EvidenceRef] = Field(default_factory=list)

    # ------------------------------------------------------------------ build
    def add(self, node: Node) -> None:
        self.nodes[node.name or node.id] = node

    def add_rule(self, rule: SecurityRule) -> None:
        self.rules.append(rule)

    def lookup(self, name: str) -> Node | None:
        return self.nodes.get(name)

    def of_kind(self, kind: NodeKind) -> list[Node]:
        return [n for n in self.nodes.values() if n.kind is kind]

    def summary(self) -> str:
        counts: dict[str, int] = {}
        for n in self.nodes.values():
            counts[n.kind.value] = counts.get(n.kind.value, 0) + 1
        parts = ", ".join(f"{v} {k}" for k, v in sorted(counts.items()))
        return f"{len(self.nodes)} objects ({parts}), {len(self.rules)} rules"
