"""DISA CCI list -> NIST SP 800-53 Rev 5. An authoritative crosswalk.

Why this exists: STIG rules are the strongest thing we retrieve. Their text
runs to a 2,174-character median and contains the literal vendor command, so
BM25 ranks them correctly almost every time. NIST is the weakest -- a
174-character median of abstract prose with no command to match -- and that is
where every measured mapping error landed (`snmp.communities` retrieved
`PM-15 Security and Privacy Groups`, which is nonsense).

Every STIG rule cites CCIs, and DISA publishes the CCI -> 800-53 mapping. So
the NIST label does not have to be retrieved at all: it can be DERIVED from the
STIG hit through a published crosswalk, exactly as the ISO label is derived
from the NIST one. Strong retrieval feeds authoritative crosswalks; the weak
retrieval path stops being load-bearing.

Source: https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_CCI_List.zip
"""
from __future__ import annotations

import glob
import re
import xml.etree.ElementTree as ET
from pathlib import Path

# "AC-17 (2)" -> "AC-17.2"; "CM-6 b" -> "CM-6". Our NIST catalogue writes
# enhancements in dot form, and a mapping that does not match the catalogue's
# own spelling silently produces zero hits -- the same trap that held ISO
# coverage at 14% until both sides were canonicalised.
_ENH = re.compile(r"^([A-Z]{2})-(\d+)\s*\((\d+)\)")
_BASE = re.compile(r"^([A-Z]{2})-(\d+)")


def canonical(index: str) -> str | None:
    s = (index or "").strip()
    m = _ENH.match(s)
    if m:
        return f"{m.group(1)}-{m.group(2)}.{m.group(3)}"
    m = _BASE.match(s)
    if m:
        return f"{m.group(1)}-{m.group(2)}"
    return None


def load(cci_dir="reference/cci", *, revision="NIST SP 800-53 Revision 5") -> dict:
    """Return {CCI-000068: ['AC-17.2', ...]}."""
    files = glob.glob(str(Path(cci_dir) / "*.xml"))
    if not files:
        return {}
    out: dict[str, list[str]] = {}
    root = ET.parse(files[0]).getroot()
    for item in root.iter():
        if not item.tag.endswith("cci_item"):
            continue
        cid = item.get("id")
        if not cid:
            continue
        got: list[str] = []
        for ref in item.iter():
            if not ref.tag.endswith("reference"):
                continue
            if (ref.get("title") or "") != revision:
                continue
            c = canonical(ref.get("index") or "")
            if c and c not in got:
                got.append(c)
        if got:
            out[cid] = got
    return out
