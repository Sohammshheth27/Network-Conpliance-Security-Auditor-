"""Retrievable documents built from the four framework catalogues.

One Document == one control/rule/recommendation. What goes into ``text``
depends on the licence, and that is the whole design:

    NIST 800-53   PUBLIC_DOMAIN    id + title + statement/guidance
    DISA STIG     PUBLIC_DOMAIN    id + title + description + check + fix
    CIS           IDENTIFIER_ONLY  id + title (+ body, local shard only)
    ISO 27001     IDENTIFIER_ONLY  id + short title, plus NIST crosswalk terms

An IDENTIFIER_ONLY document is perfectly usable for retrieval -- it just may
never be quoted back out. ``guard.assert_exportable`` enforces that on the way
out; nothing here has to remember to.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field as dc_field

from ..frameworks.models import Framework, License


@dataclass
class Document:
    doc_id: str
    framework: Framework
    control_id: str
    text: str                      # what gets embedded / BM25'd
    license: License
    source_document: str
    title: str | None = None
    platform: str | None = None
    automatable: str = "unknown"
    severity: str | None = None
    meta: dict = dc_field(default_factory=dict)

    def citation(self) -> str:
        """The only form safe to put in a report, whatever the licence."""
        return f"{self.source_document} - {self.control_id}"


def _clean(*parts) -> str:
    return " ".join(" ".join(str(p).split()) for p in parts if p)


def _clean_title(t):
    """Strip table-of-contents dot leaders and trailing page numbers.

    A CIS TOC line that wrapped renders as "Ensure ... Remote Host ....... 41",
    and the leader survives into the title unless it is removed here. It then
    becomes a BM25 token and shows up in every citation.
    """
    if not t:
        return t
    t = re.sub(r"\s*\.{3,}\s*\d*\s*$", "", t)
    return " ".join(t.split()).strip(" .")


def build_corpus(registry, *, cis_bodies: list[dict] | None = None) -> list[Document]:
    """Flatten the FrameworkRegistry into retrievable documents."""
    docs: list[Document] = []

    for fw, cat in registry.catalogs.items():
        for e in cat.entries:
            if e.license is License.PUBLIC_DOMAIN:
                # Full text: the whole point of public domain.
                text = _clean(e.id, e.title, e.description, e.check, e.fix)
            else:
                # Titles only at this layer. CIS bodies are merged below, into
                # a shard that is explicitly local.
                text = _clean(e.id, e.title)
            if not text.strip():
                continue
            docs.append(Document(
                doc_id=f"{e.framework.value}:{e.id}:{len(docs)}",
                framework=e.framework, control_id=e.id, text=text,
                license=e.license, source_document=e.source_document,
                title=_clean_title(e.title), platform=e.platform,
                automatable=e.automatable.value,
                severity=e.severity.value if e.severity else None,
                # `ccis` is what lets the NIST label be derived from a STIG
                # hit instead of retrieved -- see rag/author.py.
                meta={"page": e.page, "source_file": e.source_file,
                      "ccis": (e.extra or {}).get("ccis") or []},
            ))

    # ---- CIS body shard (LOCAL ONLY -- see rag/guard.py) -------------------
    # Retrieval quality on CIS roughly doubles with the body, because `Audit:`
    # contains the vendor command and our probes contain the vendor syntax.
    if cis_bodies:
        for b in cis_bodies:
            sec = b.get("sections", {})
            text = _clean(b.get("id"), b.get("title"), sec.get("Description"),
                          sec.get("Rationale"), sec.get("Audit"),
                          sec.get("Remediation"))
            if not text.strip():
                continue
            docs.append(Document(
                doc_id=f"cis_body:{b['benchmark']}:{b['id']}",
                framework=Framework.CIS, control_id=b["id"], text=text,
                license=License.IDENTIFIER_ONLY,
                source_document=b["benchmark"], title=_clean_title(b.get("title")),
                platform=b.get("vendor"),
                automatable="config" if b.get("automated") else "procedural",
                meta={"shard": "cis_body", "source_file": b.get("source_file"),
                      "has_audit": bool(sec.get("Audit"))},
            ))
    return docs
