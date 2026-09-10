"""NIST SP 800-53 loader (OSCAL JSON).

Plan 6.2: public domain -- we embed the full control text.
Plan 6.4: NIST is the universal spine. Every rule carries a NIST ID, and every
vendor gets a complete NIST answer even when no STIG or CIS benchmark exists
for its platform.

Source: usnistgov/oscal-content, SP 800-53 Rev 5.2.0, OSCAL 1.2.2.
"""
import json
import re
from pathlib import Path

from .models import Automatability, Catalog, CatalogEntry, Framework, License

# Control families that are inherently procedural -- policy, people, physical.
# Plan 6.6: these load but can never be automated from a config file, and must
# report as MANUAL_REVIEW rather than inflate the automation percentage.
_PROCEDURAL_FAMILIES = {
    "at",  # Awareness and Training
    "pm",  # Program Management
    "ps",  # Personnel Security
    "pe",  # Physical and Environmental Protection
    "pl",  # Planning
    "sa",  # System and Services Acquisition
    "sr",  # Supply Chain Risk Management
    "ca",  # Assessment, Authorization and Monitoring
    "cp",  # Contingency Planning
    "ir",  # Incident Response
    "mp",  # Media Protection
    "ma",  # Maintenance
    "pt",  # PII Processing and Transparency
    "ra",  # Risk Assessment
}

# Within technical families, a control whose statement is about *documenting*
# or *reviewing* is still procedural. "-01" controls are policy by convention.
_PROCEDURAL_RE = re.compile(
    r"\b(policy and procedures|develop, document|review and update|training|"
    r"designate|coordinat\w+|disseminat\w+)\b",
    re.I,
)


def _flatten(group: dict, acc: list, family: str | None = None) -> None:
    fam = (group.get("id") or family or "").lower()
    for c in group.get("controls", []) or []:
        acc.append((fam, c))
        for sub in c.get("controls", []) or []:   # control enhancements
            acc.append((fam, sub))
    for g in group.get("groups", []) or []:
        _flatten(g, acc, fam)


def _prose(control: dict) -> str:
    """Concatenate the statement parts into readable text."""
    out: list[str] = []

    def walk(part: dict) -> None:
        if part.get("prose"):
            out.append(part["prose"])
        for p in part.get("parts", []) or []:
            walk(p)

    for part in control.get("parts", []) or []:
        if part.get("name") in ("statement", "item"):
            walk(part)
    return " ".join(out).strip()


def _triage(family: str, control_id: str, title: str, text: str) -> Automatability:
    if family in _PROCEDURAL_FAMILIES:
        return Automatability.PROCEDURAL
    if control_id.lower().endswith("-1"):        # AC-1, AU-1 ... are policy controls
        return Automatability.PROCEDURAL
    if _PROCEDURAL_RE.search(title) or _PROCEDURAL_RE.search(text[:400]):
        return Automatability.PROCEDURAL
    return Automatability.CONFIG


def load(catalog_path: str | Path) -> Catalog:
    """Load the full SP 800-53 catalogue, including control enhancements."""
    p = Path(catalog_path)
    # NOTE: encoding is mandatory. The OSCAL catalogue contains characters
    # outside cp1252 and Windows Python defaults open() to cp1252, which
    # raises UnicodeDecodeError. This bit every framework file we touched.
    with p.open(encoding="utf-8") as fh:
        doc = json.load(fh)

    cat = doc["catalog"]
    meta = cat.get("metadata", {})
    version = meta.get("version", "?")
    source_doc = f"NIST SP 800-53 Rev {version}"

    flat: list[tuple[str, dict]] = []
    for g in cat.get("groups", []) or []:
        _flatten(g, flat)

    entries: list[CatalogEntry] = []
    for family, c in flat:
        cid = (c.get("id") or "").upper()
        title = c.get("title") or ""
        text = _prose(c)
        entries.append(
            CatalogEntry(
                framework=Framework.NIST_800_53,
                id=cid,
                title=title,
                description=text or None,
                license=License.PUBLIC_DOMAIN,      # embed freely
                automatable=_triage(family, cid, title, text),
                source_document=source_doc,
                source_file=p.name,
                extra={"family": family.upper()},
            )
        )

    return Catalog(
        framework=Framework.NIST_800_53,
        entries=entries,
        sources=[str(p)],
    )
