"""NIST SP 800-171 Rev 3, from NIST's own OSCAL catalogue.

Public domain, so unlike CIS and ISO this one carries full text.

The catalogue is worth more than its 130 requirements: every control links to
back-matter resources whose titles are **800-53 control identifiers**. That is
the official 800-53 -> 800-171 crosswalk, shipped inside the same file. We
extract it, which means an existing rule that already cites a NIST 800-53
control gains its 800-171 requirement for free -- exactly the pattern
`iso.py` uses to reach ISO 27001 through the OLIR crosswalk.

    our control -> NIST 800-53 -> [crosswalk in this file] -> 800-171

Source: csrc.nist.gov / github.com/usnistgov/oscal-content,
        NIST_SP800-171_rev3_catalog.json (OSCAL v1.2.2).
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from .models import Automatability, Catalog, CatalogEntry, Framework, License

SOURCE_DOC = "NIST SP 800-171 Rev. 3"

# Families whose requirements are organisational rather than technical. A
# configuration file cannot decide whether staff were trained or whether a
# building has locks, and claiming otherwise is the dishonesty plan 6.6 exists
# to prevent.
PROCEDURAL_FAMILIES = {
    "03.02",  # Awareness and Training
    "03.07",  # Maintenance
    "03.09",  # Personnel Security
    "03.10",  # Physical Protection
    "03.12",  # Security Assessment and Monitoring
    "03.15",  # Planning
    "03.16",  # System and Services Acquisition
    "03.17",  # Supply Chain Risk Management
}


def _controls(node: dict):
    """Depth-first walk; 800-171 nests enhancements under their requirement."""
    for c in node.get("controls", []):
        yield c
        yield from _controls(c)


def _text(control: dict) -> str | None:
    """The requirement statement, flattened out of OSCAL parts."""
    out: list[str] = []

    def walk(part: dict) -> None:
        if part.get("name") in {"statement", "item"}:
            if prose := part.get("prose"):
                out.append(prose.strip())
        for sub in part.get("parts", []) or []:
            walk(sub)

    for part in control.get("parts", []) or []:
        if part.get("name") == "statement":
            walk(part)
    return "\n".join(out) or None


def _guidance(control: dict) -> str | None:
    for part in control.get("parts", []) or []:
        if part.get("name") == "guidance" and part.get("prose"):
            return part["prose"].strip()
    return None


def load(path: str | Path) -> tuple[Catalog, dict[str, list[str]]]:
    """Return the catalogue and the 800-53 -> 800-171 crosswalk.

    The crosswalk is keyed on the 800-53 identifier in UPPER form with the
    OSCAL zero padding removed (``AC-02(03)`` -> ``AC-2(3)``), because that is
    how our rules cite NIST and how `registry.iso_clauses_for` already keys.
    """
    path = Path(path)
    if not path.exists():
        return Catalog(framework=Framework.NIST_800_171), {}

    doc = json.load(path.open(encoding="utf-8"))["catalog"]

    # back-matter resource uuid -> title, where the title IS the 800-53 id
    resources = {
        r["uuid"]: (r.get("title") or "").strip()
        for r in doc.get("back-matter", {}).get("resources", [])
    }

    entries: list[CatalogEntry] = []
    crosswalk: dict[str, list[str]] = {}

    for group in doc.get("groups", []):
        family_id = group.get("id", "")
        # SP_800_171_03.01 -> 03.01
        family_num = family_id.rsplit("_", 1)[-1]
        procedural = family_num in PROCEDURAL_FAMILIES

        for control in _controls(group):
            # SP_800_171_03.01.01 -> 03.01.01
            req_id = control.get("id", "").rsplit("_", 1)[-1]
            if not re.fullmatch(r"[\d.]+[a-z]?", req_id):
                continue

            entries.append(
                CatalogEntry(
                    framework=Framework.NIST_800_171,
                    id=req_id,
                    title=control.get("title"),
                    description=_text(control),
                    check=_guidance(control),
                    license=License.PUBLIC_DOMAIN,
                    automatable=(
                        Automatability.PROCEDURAL if procedural
                        else Automatability.CONFIG
                    ),
                    source_document=SOURCE_DOC,
                    source_file=str(path),
                    extra={"family": group.get("title"), "family_id": family_num},
                )
            )

            # the embedded crosswalk
            for link in control.get("links", []) or []:
                if link.get("rel") != "reference":
                    continue
                ref = resources.get(str(link.get("href", "")).lstrip("#"), "")
                if not re.fullmatch(r"[A-Z]{2}-\d{1,2}(\(\d{1,2}\))?", ref):
                    continue                      # not an 800-53 id; skip
                key = _canon_53(ref)
                crosswalk.setdefault(key, [])
                if req_id not in crosswalk[key]:
                    crosswalk[key].append(req_id)

    return (
        Catalog(
            framework=Framework.NIST_800_171,
            entries=entries,
            sources=[str(path)],
        ),
        crosswalk,
    )


def _canon_53(ref: str) -> str:
    """``AC-02(03)`` -> ``AC-2(3)``. OSCAL zero-pads; our rules do not."""
    m = re.fullmatch(r"([A-Z]{2})-0*(\d+)(?:\(0*(\d+)\))?", ref)
    if not m:
        return ref.upper()
    base = f"{m.group(1)}-{m.group(2)}"
    return f"{base}({m.group(3)})" if m.group(3) else base
