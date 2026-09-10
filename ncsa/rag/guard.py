"""Licensing tripwires for the retrieval index -- plan 6.2.

The CIS Benchmarks and ISO/IEC 27001 are copyrighted. The line is
REDISTRIBUTION, not local reference, so those texts may sit in a local index and
may steer a mapping author, but they may never leave this machine: not into a
report, not into a commit, not into examples.jsonl, not into a fine-tune set.

Convention does not survive contact with a deadline, so this is asserted in code
on every export path, the same way ``assert_not_parser_corpus`` guards the
ATLAS/AI-RMF knowledge base.
"""
from __future__ import annotations

from ..frameworks.models import License


class LicenseViolation(RuntimeError):
    """Raised when copyrighted prose is about to leave the machine."""


def assert_exportable(docs, *, sink: str) -> None:
    """Refuse to emit IDENTIFIER_ONLY text into ``sink``."""
    bad = [d for d in docs if d.license is License.IDENTIFIER_ONLY and d.text]
    if bad:
        frameworks = sorted({d.framework.value for d in bad})
        raise LicenseViolation(
            f"refusing to write {len(bad)} copyrighted entries ({', '.join(frameworks)}) "
            f"into {sink!r}. These may be CITED by id and source document, never "
            f"reproduced. Use Document.citation() instead of Document.text."
        )


def redact_for_export(doc) -> dict:
    """The only shape an IDENTIFIER_ONLY entry may take outside this machine."""
    out = {"framework": doc.framework.value, "control_id": doc.control_id,
           "source_document": doc.source_document}
    if doc.license is License.PUBLIC_DOMAIN:
        out["text"] = doc.text
        out["title"] = doc.title
    else:
        out["text"] = None
        out["title"] = None
        out["note"] = "copyrighted -- cited by identifier only"
    return out
