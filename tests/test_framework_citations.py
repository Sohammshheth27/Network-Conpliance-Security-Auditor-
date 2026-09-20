"""Every framework identifier we cite must be the catalogue's own spelling.

Two tests already checked that cited NIST ids exist -- but they normalised
`SC-8(1)` to `SC-8.1` before looking, because the rules wrote enhancements one
way and the catalogue another. The scoring code does no such normalisation, so
those two spellings became two separate requirements: one control, its evidence
split in half, scored twice. On the SonicWall that showed as SC-8(1) at 67% and
SC-8.1 at 0% in the same report -- from the same device, about the same control.

The lesson is that a normalising test hides exactly the defect it looks for. So
this file asserts the identifier VERBATIM. If a rule writes a spelling the
catalogue does not use, that is a mapping error, not a formatting preference:
an auditor reading `SC-8(1)` cannot look it up, and a second rule writing it
the other way silently halves the evidence behind both.
"""
import pathlib

import pytest
import yaml

from ncsa.frameworks.models import Framework
from ncsa.frameworks.registry import load_all

RULES = sorted(pathlib.Path("rules").rglob("*.yaml"))


def _cited(key: str) -> dict[str, list[str]]:
    """framework id -> the rule files citing it, exactly as written."""
    out: dict[str, list[str]] = {}
    for p in RULES:
        doc = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        for rid in ((doc.get("frameworks") or {}).get(key) or []):
            out.setdefault(str(rid), []).append(p.as_posix())
    return out


@pytest.fixture(scope="module")
def catalogues():
    reg = load_all("reference")
    return {fw.value: cat for fw, cat in reg.catalogs.items()}


def test_every_cited_nist_id_is_the_catalogues_own_spelling(catalogues):
    ids = {e.id for e in catalogues["nist_800_53"].entries}
    cited = _cited("nist_800_53")
    wrong = {rid: files for rid, files in cited.items() if rid not in ids}
    assert not wrong, (
        "cited with a spelling the NIST catalogue does not use "
        f"(it writes enhancements as SC-8.1, not SC-8(1)): {wrong}")


def test_no_nist_control_is_cited_under_two_spellings():
    """The defect this file exists for: one control, two ids, half the evidence.

    Checked independently of the catalogue, so it still holds if the catalogue
    is replaced by one that uses a different convention.
    """
    seen: dict[str, set] = {}
    for rid in _cited("nist_800_53"):
        seen.setdefault(rid.replace("(", ".").replace(")", "").upper(), set()).add(rid)
    split = {norm: sorted(v) for norm, v in seen.items() if len(v) > 1}
    assert not split, f"the same NIST control cited under two spellings: {split}"


def test_every_cited_iso_id_is_an_annex_a_control(catalogues):
    """A device configuration cannot evidence a management-system clause.

    ISO/IEC 27001 clauses 4-10 govern the organisation: planning, review,
    competence. Annex A holds the controls a firewall can actually satisfy.
    EXT-029 cited clauses 8.1 and 9.3.3 -- operational planning and management
    review results -- which no config could ever demonstrate, and which
    inflated the device's ISO requirement count with rows it was bound to fail.
    """
    cited = _cited("iso_27001_2022")
    clauses = {rid: files for rid, files in cited.items()
               if not rid.startswith("A.")}
    assert not clauses, (
        "management-system clauses cited from a config check; cite the Annex A "
        f"control that the setting actually evidences: {clauses}")


def test_every_cited_iso_id_exists(catalogues):
    ids = {e.id for e in catalogues["iso_27001_2022"].entries}
    missing = {rid: files for rid, files in _cited("iso_27001_2022").items()
               if rid not in ids}
    assert not missing, f"cited ISO ids not in the catalogue: {missing}"


def test_the_extended_checks_use_the_same_spelling(catalogues):
    """VPN, wireless and CVE checks carry their own ids, and drifted too.

    vpn.py wrote SC-8(1) while wireless.py wrote AC-18.1 -- the codebase
    disagreeing with itself about one catalogue's notation.
    """
    ids = {e.id for e in catalogues["nist_800_53"].entries}
    cited: set[str] = set()

    from ncsa.extended.wireless import CHECKS as WIRELESS

    for _t, _s, nist, _w in WIRELESS.values():
        cited.update(nist)

    src = pathlib.Path("ncsa/extended/vpn.py").read_text(encoding="utf-8")
    import re

    cited.update(re.findall(r'"([A-Z]{2}-\d+(?:[.(]\d+\)?)?)"', src))

    wrong = sorted(i for i in cited if i not in ids)
    assert not wrong, f"extended checks cite ids the catalogue does not use: {wrong}"


def test_the_framework_enum_covers_what_the_rules_cite():
    """A rule citing a framework nothing reports would be evidence going
    nowhere -- it would never appear in any score."""
    # `stig_by_platform` is deliberate, not a typo: a STIG Vuln ID is specific
    # to one platform's benchmark, so a rule cites V-215833 for IOS-XE and a
    # different id for ASA rather than one id pretending to cover both.
    known = {"nist_800_53", "iso_27001_2022", "cis_ids", "stig_ids",
             "stig_by_platform", "pci_dss_4", "nist_800_171_r3", "cmmc",
             "nerc_cip"}
    seen = set()
    for p in RULES:
        doc = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        seen.update((doc.get("frameworks") or {}).keys())
    assert seen <= known, f"rules cite unknown framework keys: {sorted(seen - known)}"
    assert Framework.NIST_800_53.value == "nist_800_53"
