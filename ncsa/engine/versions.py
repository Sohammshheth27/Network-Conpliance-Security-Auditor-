"""Version awareness: say when a device runs a release the pack was not checked on.

A mapping pack is a set of regexes and paths written against real
configurations. Syntax changes between OS releases -- a keyword is renamed, a
statement moves under a different block -- and a pack that has never seen the
new form does not read it. The engine then reports that setting as not
present, which is honest about the file but can mislead about the device.

So each pack lists the releases it was verified against (from the version line
of a configuration in the corpus, never from memory), and an assessment of a
device outside them carries a note. The note does not change a single result:
it tells the reviewer which UNKNOWN findings deserve a second look.

Comparison reuses the CVE module's version parser, so "which release is this"
has one answer across the product.
"""
from __future__ import annotations

import re

from ..extended.cve import version_key

_NUMERIC = re.compile(r"\d+(?:\.\d+)*(?:[A-Za-z]\d*)?(?:[-.][\w.]+)?")


def _key(v) -> tuple | None:
    """Parse a vendor version string, ignoring a leading product prefix.

    `FL.10.10.1010` (Aruba) -> (10, 10, 1010); `21.4R3-S4.9` (Junos) -> (21, 4);
    `4.29.2F` (Arista) -> (4, 29, 2); `7.3.0-7012-R8150` (SonicOS) -> (7, 3, 0).
    """
    m = _NUMERIC.search(str(v or ""))
    if not m:
        return None
    k = version_key(m.group())
    return k[0] if k else None


def covers(verified: str, device: str) -> bool | None:
    """True when the device's release falls within a verified release.

    A verified release covers its own sub-releases: 17.9 covers 17.9.3. None
    when either side cannot be parsed.
    """
    v, d = _key(verified), _key(device)
    if v is None or d is None:
        return None
    return d[:len(v)] == v


def version_notes(pack, device_version: str | None) -> list[str]:
    verified = list(getattr(pack, "verified_versions", None) or [])
    if not verified:
        return []
    shown = ", ".join(verified)
    if not device_version:
        return [f"The configuration does not state its OS release. The "
                f"{pack.platform} pack was verified against {shown}; if this "
                "device runs another release, review UNKNOWN findings against "
                "that release's documentation."]
    results = [covers(v, device_version) for v in verified]
    if any(results):
        return []
    if all(r is None for r in results):
        return [f"The OS release {device_version!r} could not be compared with "
                f"the releases this pack was verified against ({shown})."]
    return [f"This device runs {device_version}; the {pack.platform} pack was "
            f"verified against {shown}. Syntax that changed between releases "
            "is not read, so a control depending on it reports UNKNOWN -- "
            f"review UNKNOWN findings against the {device_version} documentation."]
