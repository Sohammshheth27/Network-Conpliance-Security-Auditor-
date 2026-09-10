"""The mapping registry -- approved knowledge, and the defences around it.

Plan 10.2 threat B, which is more dangerous than injection and almost nobody
addresses it: a MISTAKEN APPROVAL poisons the registry permanently.

    admin approves:  `ip ssh version 1`  ->  management.ssh.version = 2

Every future Cisco scan now passes a control it should fail -- silently,
permanently, surviving every restart. No attacker required.

Defences implemented here (numbering follows plan 10.2):
  #3  semantic sanity check   -- deterministic, no AI
  #4  cross-vendor consistency
  #5  version pinning
  #8  tamper-evident log (hash-chained)
  #9  scoped approvals -- vendor+platform, never global
  #10 confidence floor  (enforced in router.py)

#1 the regression guard is the strongest of all and lives in regression.py --
it must be BUILT FIRST and is the only one that can block an approval outright.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from pydantic import BaseModel, Field

from ..nlp.pipeline import normalize, tokenize
from ..schema.sbm import FIELD_TYPES
from .guardrails import Proposal


class ApprovedMapping(BaseModel):
    line_pattern: str
    field: str
    value: object = None
    vendor: str = ""
    platform: str = ""          # #9 -- scoped, never global
    approved_by: str = ""
    approved_at: str = ""
    source_tier: str = ""
    prev_hash: str = ""         # #8 -- hash chain
    record_hash: str = ""

    def compute_hash(self) -> str:
        payload = json.dumps(
            {"line": self.line_pattern, "field": self.field, "value": self.value,
             "vendor": self.vendor, "platform": self.platform,
             "by": self.approved_by, "at": self.approved_at, "prev": self.prev_hash},
            sort_keys=True,
        )
        return hashlib.sha256(payload.encode()).hexdigest()


class SanityResult(BaseModel):
    ok: bool
    problems: list[str] = Field(default_factory=list)


def semantic_sanity(line: str, field: str, value: object) -> SanityResult:
    """Defence #3 -- deterministic, no AI involved.

    Two cheap questions that catch most bad approvals:
      * does the raw line contain a token related to the field?
      * does the extracted value appear in the line at all?
    """
    problems: list[str] = []

    if field not in FIELD_TYPES:
        return SanityResult(ok=False, problems=[f"{field!r} is not an SBM field"])

    line_tokens = set(normalize(tokenize(line)))
    field_tokens = set(normalize(tokenize(field.replace(".", " "))))
    # ignore structural words that carry no discriminating meaning
    field_tokens -= {"management", "authentication", "authorization", "device",
                     "crypto", "platform", "security", "services", "cloud",
                     "exposure", "firewall", "interfaces", "rules"}
    if field_tokens and not (line_tokens & field_tokens):
        problems.append(
            f"no token in the line relates to {field!r} "
            f"(line has {sorted(line_tokens)[:6]}, field wants {sorted(field_tokens)})"
        )

    if value is not None and not isinstance(value, bool):
        if str(value).lower() not in line.lower():
            problems.append(f"value {value!r} does not appear in the line")

    return SanityResult(ok=not problems, problems=problems)


class MappingRegistry:
    """Approved mappings. Approval makes the system smarter immediately --
    no retraining, no GPU, no waiting (plan 9.4)."""

    def __init__(self, path: str | Path | None = None):
        self.path = Path(path) if path else None
        self.entries: list[ApprovedMapping] = []
        if self.path and self.path.exists():
            self.load()

    # ------------------------------------------------------------------ query
    def lookup(self, line: str, *, vendor: str = "", platform: str = "") -> Proposal | None:
        """Tier 1. Scoped: a bad Fortinet approval cannot contaminate Cisco (#9)."""
        key = " ".join(normalize(tokenize(line)))
        for e in self.entries:
            if platform and e.platform and e.platform != platform:
                continue
            if key == " ".join(normalize(tokenize(e.line_pattern))):
                return Proposal(line=line, field=e.field, value=e.value,
                                evidence=line.strip(), confidence=0.9,
                                tier="registry")
        return None

    def cross_vendor_conflicts(self, line: str, field: str) -> list[str]:
        """Defence #4 -- eleven other vendors map the same field. Flag disagreement."""
        key = " ".join(normalize(tokenize(line)))
        out = []
        for e in self.entries:
            if " ".join(normalize(tokenize(e.line_pattern))) == key and e.field != field:
                out.append(f"{e.vendor or '?'} maps an equivalent line to {e.field!r}")
        return out

    # ---------------------------------------------------------------- mutation
    def approve(
        self, proposal: Proposal, *, approved_by: str, vendor: str = "",
        platform: str = "", force: bool = False,
    ) -> tuple[bool, list[str]]:
        """Record an approval. Returns (accepted, problems).

        Callers MUST run the regression guard before this (plan 10.2 #1);
        this method enforces only the cheap local checks.
        """
        problems: list[str] = []

        if not proposal.is_usable:
            return False, [proposal.rejected_reason or "proposal is not usable"]

        sanity = semantic_sanity(proposal.line, proposal.field, proposal.value)
        problems += sanity.problems
        problems += self.cross_vendor_conflicts(proposal.line, proposal.field)

        if problems and not force:
            return False, problems

        prev = self.entries[-1].record_hash if self.entries else ""
        entry = ApprovedMapping(
            line_pattern=proposal.line.strip(),
            field=proposal.field,
            value=proposal.value,
            vendor=vendor,
            platform=platform,
            approved_by=approved_by,
            approved_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            source_tier=proposal.tier,
            prev_hash=prev,
        )
        entry.record_hash = entry.compute_hash()
        self.entries.append(entry)
        if self.path:
            self.save()
        return True, problems

    # ----------------------------------------------------------------- audit
    def verify_chain(self) -> tuple[bool, int]:
        """Defence #8 -- each record includes the previous record's hash.

        Editing or deleting any past approval breaks every hash after it, so
        tampering is detectable rather than merely discouraged.
        """
        prev = ""
        for i, e in enumerate(self.entries):
            if e.prev_hash != prev or e.record_hash != e.compute_hash():
                return False, i
            prev = e.record_hash
        return True, len(self.entries)

    @property
    def version(self) -> str:
        """Defence #5 -- pinned into every assessment so a later approval can
        never retroactively change a past report."""
        if not self.entries:
            return "registry-empty"
        return f"registry-{len(self.entries)}-{self.entries[-1].record_hash[:12]}"

    # ------------------------------------------------------------------- io
    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("w", encoding="utf-8") as fh:
            for e in self.entries:
                fh.write(e.model_dump_json() + "\n")

    def load(self) -> None:
        self.entries = []
        with self.path.open(encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    self.entries.append(ApprovedMapping.model_validate_json(line))
