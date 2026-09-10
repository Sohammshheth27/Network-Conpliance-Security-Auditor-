"""CMMC and NERC CIP.

Both are real, in-scope frameworks. Neither is populated here, and the reason
is recorded rather than papered over — an empty catalogue that says why is
worth more than a plausible catalogue that is wrong.

CMMC
----
CMMC Level 2 is **NIST SP 800-171 Revision 2** — 110 requirements, incorporated
by reference in 32 CFR Part 170. It is *not* Revision 3.

We hold Rev 3 (130 requirements, different identifiers). NIST publishes OSCAL
for Rev 3 only, so there is no machine-readable Rev 2 to derive from. Deriving
CMMC from the Rev 3 catalogue we do have would produce a catalogue that looked
right, cited real-looking identifiers, and was wrong about which requirements an
assessor actually evaluates. That is precisely the failure this codebase treats
as unacceptable.

So: drop a Rev 2 catalogue at the path below and CMMC populates from it. Until
then it reports zero and explains itself.

NERC CIP
--------
NERC publishes the CIP standards, but not in a machine-readable control
catalogue we can parse into entries. Supply one and this loader will read it.

Neither framework is fabricated to make a slide look fuller.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from .models import Automatability, Catalog, CatalogEntry, Framework, License

CMMC_SOURCE_DOC = "CMMC Level 2 (NIST SP 800-171 Rev. 2, per 32 CFR 170)"
NERC_SOURCE_DOC = "NERC CIP"


def load_cmmc(path: str | Path) -> Catalog:
    """CMMC Level 2 from an 800-171 **Rev 2** OSCAL catalogue.

    The revision guard is deliberate: a Rev 3 file placed at this path would
    load 130 requirements and silently misstate the CMMC scope, so it is
    rejected by inspection rather than trusted by filename.
    """
    path = Path(path)
    if not path.exists():
        return Catalog(framework=Framework.CMMC)

    try:
        doc = json.load(path.open(encoding="utf-8"))["catalog"]
    except Exception:                                     # noqa: BLE001
        return Catalog(framework=Framework.CMMC)

    title = (doc.get("metadata", {}).get("title") or "").lower()
    version = str(doc.get("metadata", {}).get("version") or "")
    if "rev" in title and "3" in version.split(".")[0]:
        # A Rev 3 catalogue in the Rev 2 slot. Refuse rather than mislabel.
        return Catalog(framework=Framework.CMMC)

    def controls(node: dict):
        for c in node.get("controls", []):
            yield c
            yield from controls(c)

    entries: list[CatalogEntry] = []
    for group in doc.get("groups", []):
        for control in controls(group):
            rid = control.get("id", "").rsplit("_", 1)[-1]
            if not re.fullmatch(r"3\.\d{1,2}\.\d{1,2}", rid):
                continue
            entries.append(
                CatalogEntry(
                    framework=Framework.CMMC,
                    id=rid,
                    title=control.get("title"),
                    license=License.PUBLIC_DOMAIN,
                    automatable=Automatability.UNKNOWN,
                    source_document=CMMC_SOURCE_DOC,
                    source_file=str(path),
                    extra={"level": 2, "family": group.get("title")},
                )
            )
    return Catalog(
        framework=Framework.CMMC, entries=entries, sources=[str(path)]
    )


def load_nerc(path: str | Path) -> Catalog:
    """NERC CIP from a supplied JSON control list.

    Expected shape — a list of ``{"id": "CIP-005-7 R1", "title": "..."}``.
    Absent or malformed, this returns an empty catalogue rather than a guess.
    """
    path = Path(path)
    if not path.exists():
        return Catalog(framework=Framework.NERC_CIP)

    try:
        rows = json.load(path.open(encoding="utf-8"))
    except Exception:                                     # noqa: BLE001
        return Catalog(framework=Framework.NERC_CIP)
    if not isinstance(rows, list):
        return Catalog(framework=Framework.NERC_CIP)

    entries = [
        CatalogEntry(
            framework=Framework.NERC_CIP,
            id=str(r["id"]),
            title=r.get("title"),
            license=License.PUBLIC_DOMAIN,
            automatable=Automatability.UNKNOWN,
            source_document=NERC_SOURCE_DOC,
            source_file=str(path),
        )
        for r in rows
        if isinstance(r, dict) and r.get("id")
    ]
    return Catalog(
        framework=Framework.NERC_CIP, entries=entries, sources=[str(path)]
    )


#: Why a framework is empty, surfaced in the coverage report so nobody has to
#: guess whether a zero means "none apply" or "no source file".
UNPOPULATED_REASONS = {
    Framework.CMMC: (
        "needs an 800-171 Rev 2 OSCAL catalogue at "
        "reference/nist/nist.gov/SP800-171/rev2/json/ — NIST publishes OSCAL "
        "for Rev 3 only, and CMMC Level 2 is defined against Rev 2"
    ),
    Framework.NERC_CIP: (
        "needs a control list at reference/nerc_cip/nerc_cip_controls.json"
    ),
}
