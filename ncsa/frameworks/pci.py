"""PCI DSS v4.0.1 — identifiers only.

PCI DSS is copyrighted by the PCI Security Standards Council, so this loader
follows the same rule as CIS and ISO (plan 6.2): **we store requirement numbers
and the twelve published section titles, and never the requirement prose.**

The twelve top-level titles are section headings reproduced across the SSC's
own public material; the sub-requirement identifiers are extracted from the
requirements document. No requirement text is stored, embedded, or indexed.

What that buys: a finding can legitimately cite "PCI DSS v4.0.1 Requirement
1.2.6" without redistributing anything the SSC licenses. What it costs: we
cannot show a reader *what* 1.2.6 says — they need their own copy. That is the
correct trade, and it is the same one already made for CIS.

Source: PCI DSS v4.0.1 Requirements and Testing Procedures.
"""
from __future__ import annotations

import re
from pathlib import Path

from .models import Automatability, Catalog, CatalogEntry, Framework, License

SOURCE_DOC = "PCI DSS v4.0.1"

# The twelve requirements. Section headings only — never the requirement text.
REQUIREMENTS: dict[str, str] = {
    "1": "Install and Maintain Network Security Controls",
    "2": "Apply Secure Configurations to All System Components",
    "3": "Protect Stored Account Data",
    "4": "Protect Cardholder Data with Strong Cryptography During Transmission "
         "Over Open, Public Networks",
    "5": "Protect All Systems and Networks from Malicious Software",
    "6": "Develop and Maintain Secure Systems and Software",
    "7": "Restrict Access to System Components and Cardholder Data by Business "
         "Need to Know",
    "8": "Identify Users and Authenticate Access to System Components",
    "9": "Restrict Physical Access to Cardholder Data",
    "10": "Log and Monitor All Access to System Components and Cardholder Data",
    "11": "Test Security of Systems and Networks Regularly",
    "12": "Support Information Security with Organizational Policies and Programs",
}

# Requirements 9 and 12 are physical security and organisational policy. No
# configuration file decides them, and a tool that scored them from a config
# would be inventing an answer.
PROCEDURAL_REQUIREMENTS = {"9", "12"}


def load(path: str | Path) -> Catalog:
    """Load the twelve requirements, plus sub-requirement identifiers.

    Returns the twelve families alone if the source document is absent, so the
    framework is still citable at requirement level rather than disappearing.
    """
    path = Path(path)
    entries: list[CatalogEntry] = []

    def entry(rid: str, title: str | None, source: str) -> CatalogEntry:
        family = rid.split(".")[0]
        return CatalogEntry(
            framework=Framework.PCI_DSS,
            id=rid,
            title=title,                      # None for sub-requirements
            description=None,                 # never stored: copyrighted
            license=License.IDENTIFIER_ONLY,
            automatable=(
                Automatability.PROCEDURAL if family in PROCEDURAL_REQUIREMENTS
                else Automatability.CONFIG
            ),
            source_document=SOURCE_DOC,
            source_file=source,
            extra={"family": family},
        )

    for rid, title in REQUIREMENTS.items():
        entries.append(entry(rid, title, str(path)))

    sub_ids = _sub_requirement_ids(path)
    for rid in sub_ids:
        entries.append(entry(rid, None, str(path)))

    return Catalog(
        framework=Framework.PCI_DSS,
        entries=entries,
        sources=[str(path)] if path.exists() else [],
    )


def _sub_requirement_ids(path: Path) -> list[str]:
    """Pull `1.2.6`-style identifiers out of the requirements PDF.

    Identifiers only — the surrounding prose is never captured. Returns an
    empty list if the document is missing or unreadable, because a partial
    catalogue is better than a crash and far better than invented numbers.
    """
    if not path.exists() or path.suffix.lower() != ".pdf":
        return []
    try:
        import pypdf
    except ImportError:
        return []

    try:
        reader = pypdf.PdfReader(str(path))
        text = "\n".join((p.extract_text() or "") for p in reader.pages)
    except Exception:                                     # noqa: BLE001
        return []

    found = {
        m.group(1)
        for m in re.finditer(r"^\s*(\d{1,2}\.\d{1,2}(?:\.\d{1,2})?)\s", text, re.M)
    }
    valid = {r for r in found if r.split(".")[0] in REQUIREMENTS}
    return sorted(valid, key=lambda s: [int(x) for x in s.split(".")])
