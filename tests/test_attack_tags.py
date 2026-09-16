"""MITRE ATT&CK tags must be real, current and direct.

The first test here is the reason the file exists. A map written from memory
cited T1562 "Impair Defenses" -- which ATT&CK v19 revoked. Every tag is now
resolved against the STIX bundle on disk and must be ACTIVE.
"""
import pytest

from ncsa.engine.rules import load_rules
from ncsa.extended.cve import CHECK_ID as CVE_CHECK
from ncsa.extended.wireless import CHECKS as WLAN_CHECKS
from ncsa.frameworks.attack import (ATTACK_MAP, BLAST_ADMIN_TECHNIQUE, BUNDLE,
                                    coverage, load_techniques, tags_for)

bundle_only = pytest.mark.skipif(not BUNDLE.exists(), reason="ATT&CK bundle absent")

VPN_CHECKS = {f"NCSA-X-VPN-00{i}" for i in range(1, 6)}


@pytest.fixture(scope="module")
def techniques():
    return load_techniques()


@bundle_only
def test_every_tagged_technique_is_active_in_the_bundle(techniques):
    cited = {tid for tags in ATTACK_MAP.values() for tid, _ in tags}
    cited.add(BLAST_ADMIN_TECHNIQUE[0])
    missing = sorted(t for t in cited if t not in techniques)
    assert not missing, (
        f"tags cite techniques that are revoked, deprecated or absent in "
        f"ATT&CK {techniques.get('__version__')}: {missing}")


@bundle_only
def test_revoked_techniques_are_not_cited(techniques):
    """T1562 was revoked in v19; it must not survive in the map."""
    assert "T1562" not in techniques
    cited = {tid for tags in ATTACK_MAP.values() for tid, _ in tags}
    assert not any(t.startswith("T1562") for t in cited)


def test_every_tagged_control_exists():
    known = {c.id for c in load_rules("rules")}
    known |= set(WLAN_CHECKS) | VPN_CHECKS | {CVE_CHECK}
    unknown = sorted(set(ATTACK_MAP) - known)
    assert not unknown, f"tags for controls that do not exist: {unknown}"


def test_every_tag_says_why():
    for cid, tags in ATTACK_MAP.items():
        assert tags, f"{cid} is in the map with no tags"
        for tid, why in tags:
            assert len(why) > 20, f"{cid} -> {tid} has no real explanation"


@bundle_only
def test_tags_resolve_names_from_the_bundle(techniques):
    tags = tags_for("NCSA-SNMP-002", techniques)
    assert tags[0]["id"] == "T1602.001"
    assert tags[0]["name"] == techniques["T1602.001"]["name"]
    assert "collection" in tags[0]["tactics"]


def test_an_unresolvable_tag_is_dropped_not_shown():
    """A stale tag must never reach a report looking authoritative."""
    assert tags_for("NCSA-TEL-001", techniques={}) == []


def test_decorative_controls_stay_untagged():
    for cid in ("NCSA-BAN-001", "NCSA-EXT-028", "NCSA-EXT-042"):
        assert cid not in ATTACK_MAP, f"{cid} prevents no specific technique"


@bundle_only
def test_coverage_reports_tagged_and_untagged_honestly(techniques):
    ids = [c.id for c in load_rules("rules")]
    cov = coverage(ids, techniques)
    assert cov["controls_tagged"] + cov["controls_untagged"] == len(ids)
    assert cov["controls_untagged"] > 0
    assert "decoration" in cov["untagged_reason"]
    assert cov["attack_version"]
