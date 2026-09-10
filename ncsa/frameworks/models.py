"""Unified framework catalogue types.

Plan 6.1: one rulebook, four labels. Our *controls* are ours; what each
framework calls the same requirement is a label attached to it. These types
model the labels -- the imported catalogue -- not our rules.

Licensing (plan 6.2) is enforced in the type system rather than by convention:
every entry declares whether its text may be redistributed. NIST and DISA are
public domain and carry full text. CIS and ISO are copyrighted and carry
identifiers only.
"""
from enum import Enum

from pydantic import BaseModel, Field

from ..schema.enums import Severity


class Framework(str, Enum):
    NIST_800_53 = "nist_800_53"
    DISA_STIG = "disa_stig"
    CIS = "cis"
    ISO_27001 = "iso_27001_2022"
    # Added alongside the original four. 800-171 is loaded from NIST's own
    # OSCAL catalogue; PCI DSS is identifier-only because its text is
    # copyrighted; CMMC and NERC CIP are derived/loaded only when a source is
    # present and stay honestly empty otherwise.
    NIST_800_171 = "nist_800_171_r3"
    CMMC = "cmmc"
    PCI_DSS = "pci_dss_4"
    NERC_CIP = "nerc_cip"


class License(str, Enum):
    """Plan 6.2. Drives what may reach a report, a log, or the RAG index."""

    PUBLIC_DOMAIN = "public_domain"   # NIST, DISA -- embed full text
    IDENTIFIER_ONLY = "identifier_only"  # CIS, ISO, PCI DSS -- numbers, never prose

    @property
    def may_embed_text(self) -> bool:
        return self is License.PUBLIC_DOMAIN


class Automatability(str, Enum):
    """Can this be decided from a configuration file alone?

    Plan 6.6 is explicit that most of a framework cannot be: half of ISO 27001
    is about policies and people, and a tool claiming to automate it would be
    lying. Recording this per entry is what lets 14.2 produce an honest
    coverage number instead of a flattering one.
    """

    CONFIG = "config"        # decidable from the config -- automatable
    PROCEDURAL = "procedural"  # policy/training/physical -- MANUAL_REVIEW
    UNKNOWN = "unknown"        # not yet triaged


class CatalogEntry(BaseModel):
    """One control/rule/recommendation as published by its framework."""

    model_config = {"frozen": True}

    framework: Framework
    id: str = Field(description="AC-17(2) / V-215844 / 1.2.3 / A.8.20")
    title: str | None = Field(
        default=None,
        description="Published title. None when licensing forbids storing it.",
    )
    description: str | None = None
    check: str | None = Field(default=None, description="How to verify (STIG only)")
    fix: str | None = Field(default=None, description="Remediation text (STIG only)")
    severity: Severity | None = None
    license: License = License.PUBLIC_DOMAIN
    automatable: Automatability = Automatability.UNKNOWN

    # provenance -- plan 10.2 defence 5 requires every assessment to record
    # exactly which catalogue version produced a finding
    source_document: str = Field(description="Benchmark/STIG/catalog title + version")
    source_file: str = Field(description="File on disk this was parsed from")
    platform: str | None = Field(
        default=None, description="Vendor/platform for per-platform frameworks"
    )
    page: int | None = Field(
        default=None, description="Page in the source PDF, for human lookup"
    )
    extra: dict = Field(default_factory=dict)

    def citation(self) -> str:
        """A report-safe citation string.

        Never includes copyrighted prose -- for IDENTIFIER_ONLY entries this is
        the document title plus the number, which is exactly what plan 6.2 permits.
        """
        if self.license is License.IDENTIFIER_ONLY:
            return f"{self.source_document} - {self.id}"
        title = f": {self.title}" if self.title else ""
        return f"{self.id}{title}"


class Catalog(BaseModel):
    """Everything loaded from one framework."""

    framework: Framework
    entries: list[CatalogEntry] = Field(default_factory=list)
    sources: list[str] = Field(default_factory=list)

    def __len__(self) -> int:
        return len(self.entries)

    def by_id(self, entry_id: str) -> CatalogEntry | None:
        for e in self.entries:
            if e.id == entry_id:
                return e
        return None

    def for_platform(self, platform: str) -> list[CatalogEntry]:
        return [e for e in self.entries if e.platform == platform]

    def counts_by_automatability(self) -> dict[str, int]:
        out: dict[str, int] = {a.value: 0 for a in Automatability}
        for e in self.entries:
            out[e.automatable.value] += 1
        return out
