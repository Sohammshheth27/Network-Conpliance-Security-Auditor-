"""Evidence references -- the audit trail behind every observation.

Plan 14.3: every FAIL and PARTIAL must carry at least one of these.
Plan 10.1 defence 4: the AI must return the exact substring it used, and we
verify it appears verbatim in the source.
"""
from pydantic import BaseModel, Field, field_validator


class EvidenceRef(BaseModel):
    """One pointer back into the original configuration file."""

    model_config = {"frozen": True}

    file: str = Field(description="Original filename as ingested")
    line: int | None = Field(default=None, ge=1, description="1-indexed line number")
    raw: str = Field(description="The exact source text, unmodified")
    record_id: str | None = Field(
        default=None,
        description="Structural path for non-line formats: XPath, JSONPath, section path",
    )

    @field_validator("raw")
    @classmethod
    def _raw_not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("evidence.raw must not be empty -- it is the audit trail")
        return v

    def anchors_in(self, source_text: str) -> bool:
        """Plan 10.1 defence 4 -- evidence anchoring.

        Verify this evidence actually appears in the source. Five lines,
        enormous value: it defeats an AI that invents a quotation.
        """
        return self.raw.strip() in source_text

    def __str__(self) -> str:
        loc = f":{self.line}" if self.line is not None else ""
        return f"{self.file}{loc}: {self.raw.strip()}"
