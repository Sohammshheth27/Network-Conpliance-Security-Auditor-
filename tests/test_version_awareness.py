"""Version awareness: an unverified OS release is stated, never hidden.

The note changes no result. It exists so a reviewer knows which UNKNOWN
findings might be a syntax change rather than a missing setting.
"""
from pathlib import Path

import pytest

from ncsa.engine.versions import _key, covers, version_notes
from ncsa.pipeline import assess
from ncsa.readers.pack import Pack

RTR = Path("samples/cisco/edge-rtr-01.cfg")


@pytest.mark.parametrize("raw,key", [
    ("17.9", (17, 9)),
    ("FL.10.10.1010", (10, 10, 1010)),        # Aruba: product prefix
    ("21.4R3-S4.9", (21, 4)),                 # Junos
    ("4.29.2F", (4, 29, 2)),                  # Arista
    ("7.3.0-7012-R8150", (7, 3, 0)),          # SonicOS
])
def test_vendor_version_strings_parse(raw, key):
    assert _key(raw) == key


def test_a_verified_release_covers_its_sub_releases():
    assert covers("17.9", "17.9.3") is True
    assert covers("17.9", "17.12.1") is False
    assert covers("17.9", "garbage") is None


def _pack(*verified):
    return Pack(vendor="cisco", platform="cisco_iosxe_router", reader="indented",
                verified_versions=list(verified))


def test_notes():
    assert version_notes(_pack(), "15.2") == [], "no claim when nothing verified"
    assert version_notes(_pack("17.9"), "17.9") == []
    [n] = version_notes(_pack("17.9"), "15.2")
    assert "runs 15.2" in n and "verified against 17.9" in n
    [n] = version_notes(_pack("17.9"), None)
    assert "does not state its OS release" in n


@pytest.fixture
def packs_17_9(tmp_path):
    """A COPY of the packs in which the IOS pack declares 17.9 verified.

    The real IOS pack declares nothing: its samples are authored, not captured
    from a device, and a verified release must come from a real configuration.
    The copy tests the wiring without the product making that claim.
    """
    import shutil

    d = tmp_path / "packs"
    shutil.copytree("packs", d, ignore=shutil.ignore_patterns("*.learned.yaml"))
    ios = d / "cisco.yaml"
    ios.write_text(ios.read_text(encoding="utf-8") + '\nverified_versions: ["17.9"]\n',
                   encoding="utf-8")
    return str(d)


def test_a_verified_release_carries_no_version_note(packs_17_9):
    da = assess(str(RTR), redact=False, assessment_id="T-VER-OK", packs_dir=packs_17_9)
    assert da.identity.version == "17.9"
    assert not any("verified against" in n for n in da.notes)


def test_an_unverified_release_is_noted_and_changes_no_result(packs_17_9, tmp_path):
    base = assess(str(RTR), redact=False, assessment_id="T-VER-A", packs_dir=packs_17_9)
    old = tmp_path / "old.cfg"
    old.write_text(RTR.read_text().replace("version 17.9", "version 15.2", 1))
    da = assess(str(old), redact=False, assessment_id="T-VER-B", packs_dir=packs_17_9)
    assert any("runs 15.2" in n for n in da.notes)
    assert da.coverage() == base.coverage(), "a note, never a result change"


def test_real_packs_claim_only_releases_seen_on_a_real_device():
    """Only packs grounded in a captured device export may claim a release:
    SonicWall (the NSA 3700 export) and PAN-OS (a genuine running config)."""
    import glob

    import yaml

    claims = {}
    for p in glob.glob("packs/*.yaml"):
        d = yaml.safe_load(open(p, encoding="utf-8")) or {}
        if d.get("verified_versions"):
            claims[d["platform"]] = d["verified_versions"]
    assert claims == {"sonicwall_sonicos": ["7.3.0"], "panos": ["5.0.0"]}
