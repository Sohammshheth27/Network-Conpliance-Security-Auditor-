"""The Observation -- every value in the SBM is one of these, never a bare value.

Plan 2.3. This is the single most important type in the system.
"""
from typing import Any

from pydantic import BaseModel, Field, model_validator

from .enums import ObservationSource, ObservationState
from .evidence import EvidenceRef

# Confidence by source -- plan 7.3. The parser is trusted absolutely; an
# approved AI mapping is trusted slightly less, permanently, so that a
# finding derived from it can never be mistaken for a parsed fact.
_CONFIDENCE = {
    ObservationSource.PARSER: 1.0,
    ObservationSource.MAPPING_REGISTRY: 1.0,
    ObservationSource.LLM_APPROVED: 0.9,
}


class Observation(BaseModel):
    """One known (or notably unknown) fact about a device.

    Construct via the classmethods rather than directly -- they enforce the
    state/source/evidence combinations that the rest of the engine relies on.
    """

    model_config = {"frozen": True}

    value: Any | None = None
    state: ObservationState
    source: ObservationSource
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: list[EvidenceRef] = Field(default_factory=list)
    field_path: str | None = Field(
        default=None, description="Dotted SBM path, e.g. management.ssh.version"
    )

    # ------------------------------------------------------------------ rules
    @model_validator(mode="after")
    def _check_coherence(self) -> "Observation":
        # An OBSERVED fact without evidence is not evidence-backed, and plan
        # 14.3 requires every finding to trace to a source line. Refusing this
        # at construction is cheaper than discovering it at report time.
        if self.state is ObservationState.OBSERVED and not self.evidence:
            raise ValueError(
                "OBSERVED observations must carry evidence "
                f"(field_path={self.field_path!r})"
            )
        # Plan 2.3: an assumed default was by definition never seen, so it
        # cannot have evidence pointing at a source line.
        if self.state is ObservationState.DEFAULT_ASSUMED and self.evidence:
            raise ValueError(
                "DEFAULT_ASSUMED observations cannot carry source evidence "
                f"(field_path={self.field_path!r})"
            )
        return self

    # ------------------------------------------------------------ constructors
    @classmethod
    def observed(
        cls,
        value: Any,
        evidence: list[EvidenceRef],
        *,
        field_path: str | None = None,
        source: ObservationSource = ObservationSource.PARSER,
    ) -> "Observation":
        """A value we literally saw in the configuration."""
        return cls(
            value=value,
            state=ObservationState.OBSERVED,
            source=source,
            confidence=_CONFIDENCE[source],
            evidence=evidence,
            field_path=field_path,
        )

    @classmethod
    def default_assumed(
        cls, value: Any, *, field_path: str | None = None
    ) -> "Observation":
        """A platform default applied because the config never mentioned it.

        Plan 2.3 -- this is NOT the same fact as having observed the value,
        and the report must be able to tell a reader which one it was.
        """
        return cls(
            value=value,
            state=ObservationState.DEFAULT_ASSUMED,
            source=ObservationSource.MAPPING_REGISTRY,
            confidence=_CONFIDENCE[ObservationSource.MAPPING_REGISTRY],
            field_path=field_path,
        )

    @classmethod
    def not_observed(cls, *, field_path: str | None = None) -> "Observation":
        """We looked for this and it was absent. Most FAILs are absences."""
        return cls(
            value=None,
            state=ObservationState.NOT_OBSERVED,
            source=ObservationSource.PARSER,
            confidence=_CONFIDENCE[ObservationSource.PARSER],
            field_path=field_path,
        )

    @classmethod
    def unparsed(
        cls, evidence: list[EvidenceRef], *, field_path: str | None = None
    ) -> "Observation":
        """Present in the config but we could not interpret it.

        Feeds the AI helper queue (plan 3b) and the UNKNOWN count in 14.1.
        """
        return cls(
            value=None,
            state=ObservationState.UNPARSED,
            source=ObservationSource.PARSER,
            confidence=_CONFIDENCE[ObservationSource.PARSER],
            evidence=evidence,
            field_path=field_path,
        )

    # ------------------------------------------------------------- properties
    @property
    def is_provable(self) -> bool:
        """Can this value support a FAIL?

        Only an OBSERVED value proves the admin configured something. An
        assumed default may be right, but it is an inference, and plan 6.5's
        critical rule says an inference must never masquerade as a finding.
        """
        return self.state is ObservationState.OBSERVED

    @property
    def is_known(self) -> bool:
        """Do we have a value at all, however derived?"""
        return self.state in (
            ObservationState.OBSERVED,
            ObservationState.DEFAULT_ASSUMED,
        )

    def __str__(self) -> str:
        return f"{self.field_path or '?'}={self.value!r} [{self.state.value}]"
