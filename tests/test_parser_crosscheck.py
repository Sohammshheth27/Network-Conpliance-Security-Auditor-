"""Two parsers, one syntax.

The finding-level consensus compares two METHODS over one parse tree. This
compares two PARSERS, which catches a different failure: both methods agreeing
because they read the same wrong tree.

Junos specifically, because `readers/braces.py` is the one grammar written by
hand here and it produced four separate bugs -- block-header arguments kept as
one segment, repeated leaf keys overwriting each other, a hardcoded
`default-policy` that made a permit-all device a false PASS, and a grammar
recalled wrongly in four places. Each was caught by a person noticing. This
makes it something the suite runs.
"""
import os

import pytest

from ncsa.consensus import ParserAgreement, crosscheck_braces
from ncsa.consensus.parsers import _found_by, _library_paths, _pack_paths
from ncsa.pipeline import assess

COMBINED = "samples/juniper/srx-combined.conf"
POLICY_ONLY = "samples/juniper/srx-policy-01.conf"


# ------------------------------------------------------------ the comparison
def test_both_parsers_agree_on_every_path_our_packs_read():
    rep = crosscheck_braces(COMBINED)
    assert rep.checked, rep.reason
    assert rep.comparable, "no shared coverage means nothing was verified"
    assert not rep.only_ours, f"only our reader found: {rep.only_ours}"
    assert not rep.only_theirs, f"only the library found: {rep.only_theirs}"
    assert rep.agrees


def test_vacuous_agreement_is_not_reported_as_agreement():
    """A config where NEITHER parser finds any pack path returned agrees=True
    -- an empty result presented as a positive one, which is the same shape as
    every other false clean bill of health this project has caught."""
    rep = crosscheck_braces(POLICY_ONLY)
    assert rep.checked
    assert not rep.comparable
    assert not rep.agrees
    assert "not agreement between the parsers" in rep.explain()


def test_only_paths_the_packs_actually_read_are_compared():
    """The two produce different path vocabularies, so raw count differences
    are noise. Comparing everything would report a disagreement on every path
    and mean nothing."""
    rep = crosscheck_braces(COMBINED)
    assert rep.ours != rep.theirs          # vocabularies differ...
    assert rep.agrees                      # ...and it does not matter
    assert rep.pack_paths_checked == len(_pack_paths("juniper_srx"))


def test_prefix_matching_tolerates_leaf_spelling_differences():
    """Ours records `.../protocol-version`; the library may keep the value on
    the leaf. Exact equality would flag every path."""
    assert _found_by({"system/services/ssh/protocol-version v2"},
                     "system/services/ssh/protocol-version")
    assert _found_by({"system/services/ssh"}, "system/services/ssh")
    assert not _found_by({"system/services/telnet"}, "system/services/ssh")


# --------------------------------------------------------------- robustness
def test_a_missing_file_is_reported_not_raised():
    rep = crosscheck_braces("no/such/file.conf")
    assert not rep.checked and "does not exist" in rep.reason


def test_library_failure_is_not_a_finding_about_the_device(monkeypatch):
    """ciscoconfparse2 being unavailable says nothing about the config."""
    import ncsa.consensus.parsers as mod

    def boom(_text):
        raise RuntimeError("library exploded")

    monkeypatch.setattr(mod, "_library_paths", boom)
    rep = crosscheck_braces(COMBINED)
    assert not rep.checked
    assert "ciscoconfparse2" in rep.reason
    assert not rep.only_ours and not rep.only_theirs


def test_library_actually_parses_junos_braces():
    """Guards the premise: if the junos syntax stopped working, every
    cross-check would silently pass with an empty comparison."""
    paths = _library_paths(open(COMBINED, encoding="utf-8").read())
    assert len(paths) > 20
    assert any(p.startswith("system/services/ssh") for p in paths)


# ------------------------------------------------------------- in the pipeline
def test_assess_carries_the_cross_check_for_junos():
    r = assess(COMBINED)
    assert r.parser_agreement is not None
    assert r.parser_agreement.checked


def test_non_braces_platforms_are_not_cross_checked():
    """Cisco is parsed by the library itself; comparing it to itself would
    prove nothing."""
    assert assess("samples/cisco/edge-rtr-01.cfg").parser_agreement is None


@pytest.mark.skipif(not os.path.exists("samples/juniper/srx-display-xml.xml"),
                    reason="fixture absent")
def test_junos_xml_is_not_cross_checked_against_a_braces_parser():
    assert assess("samples/juniper/srx-display-xml.xml").parser_agreement is None
