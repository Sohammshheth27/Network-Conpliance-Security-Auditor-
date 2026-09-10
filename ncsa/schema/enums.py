"""Controlled vocabularies. Every state in NCSA lives here, nowhere else.

Plan refs: 2.3 (observation states), 6.5 (result states), 14.1 (source record states).
"""
from enum import Enum


class ObservationState(str, Enum):
    """How we came to know a value -- plan 2.3.

    The distinction this enum protects is the whole point of the SBM:
    ``telnet.enabled = False`` because an admin explicitly disabled it is a
    *different fact* from the same value because we never saw a telnet line.
    Only the first is a provable finding. Most compliance failures are
    absences, so collapsing these two would quietly turn the product into a toy.
    """

    OBSERVED = "OBSERVED"                # seen literally in the config
    DEFAULT_ASSUMED = "DEFAULT_ASSUMED"  # platform default applied, not seen
    NOT_OBSERVED = "NOT_OBSERVED"        # looked for, absent
    UNPARSED = "UNPARSED"                # present but we could not read it


class ObservationSource(str, Enum):
    """Who produced the value -- plan 2.3, 7.3."""

    PARSER = "parser"                      # deterministic, confidence 1.0
    MAPPING_REGISTRY = "mapping_registry"  # platform default table
    LLM_APPROVED = "llm_approved"          # AI proposed, human approved, 0.9

    # Deliberately absent: an unapproved LLM suggestion. Plan 7.3 -- an
    # unapproved guess gets no risk score at all and must surface as UNKNOWN.


class ResultState(str, Enum):
    """Outcome of evaluating one control -- plan 6.5.

    NOTE: plan 6.5 is headed "The six result states" but its table lists
    seven. v1.3 added PARTIAL and ERROR but only updated the count once.
    Seven is correct; the heading is stale.
    """

    PASS = "PASS"
    FAIL = "FAIL"
    PARTIAL = "PARTIAL"                  # some but not all conditions met
    NOT_APPLICABLE = "NOT_APPLICABLE"
    MANUAL_REVIEW = "MANUAL_REVIEW"
    UNKNOWN = "UNKNOWN"
    ERROR = "ERROR"                      # evaluation itself failed

    @property
    def counts_toward_score(self) -> bool:
        """Plan 6.7: only PASS/FAIL/PARTIAL enter the compliance score."""
        return self in (ResultState.PASS, ResultState.FAIL, ResultState.PARTIAL)

    @property
    def needs_evidence(self) -> bool:
        """Plan 14.3: every FAIL and PARTIAL must carry source evidence."""
        return self in (ResultState.FAIL, ResultState.PARTIAL)


class RecordState(str, Enum):
    """Fate of one source line -- plan 14.1.

    Invariant: TOTAL == PARSED + MAPPED + QUARANTINED + UNKNOWN.
    A tool that silently drops lines can report PASS on a control those
    lines would have failed. Plan 14.1 calls that the worst failure mode
    in this product class.
    """

    PARSED = "PARSED"            # understood structurally
    MAPPED = "MAPPED"            # produced an SBM observation
    QUARANTINED = "QUARANTINED"  # suspicious (e.g. injection attempt)
    UNKNOWN = "UNKNOWN"          # not recognised


class Severity(str, Enum):
    """Plan 7.1. Weights double as the 6.7 scoring weights."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @property
    def weight(self) -> int:
        return {"critical": 10, "high": 6, "medium": 3, "low": 1}[self.value]

    @classmethod
    def from_stig_cat(cls, cat: str) -> "Severity":
        """CAT I/II/III -> severity. Plan 7.1.

        Severity comes from the framework, never from our own guess --
        the v1.4 6.4 caveat exists because the plan previously assumed
        CAT II for a rule that is actually CAT I.
        """
        return {"I": cls.HIGH, "II": cls.MEDIUM, "III": cls.LOW}[cat.strip().upper()]

    @classmethod
    def from_xccdf(cls, sev: str) -> "Severity":
        """XCCDF severity attribute as it appears in the real STIG files."""
        return {"high": cls.HIGH, "medium": cls.MEDIUM, "low": cls.LOW}.get(
            (sev or "").lower(), cls.MEDIUM
        )
