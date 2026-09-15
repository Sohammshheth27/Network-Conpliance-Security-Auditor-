"""Junos SRX policy graph from `display xml` output.

Two samples, testing opposite defaults. That pairing is the point: the braces
builder's own docstring warns that `set security policies default-policy
permit-all` is valid and documented, and that assuming deny would report a
permit-all device as compliant -- a false PASS on a high-severity control.
srx-display-xml-weak.xml is exactly that device.

The builder also REFUSES to produce a graph it cannot produce correctly. Junos
XML nests rules inside a zone-pair container and names both elements <policy>,
with no key attribute, so the reader flattens repeated siblings onto one path.
One zone pair is unambiguous; several cannot be associated with their rules,
and pairing by position would attach rules to the wrong security boundary.
"""
import os

import pytest

from ncsa.graph.reach import Query, ask
from ncsa.pipeline import assess

STRONG = "samples/juniper/srx-display-xml.xml"
WEAK = "samples/juniper/srx-display-xml-weak.xml"
have = os.path.exists(STRONG) and os.path.exists(WEAK)
samples_only = pytest.mark.skipif(not have, reason="Juniper XML samples absent")


@pytest.fixture(scope="module")
def strong():
    return assess(STRONG, redact=False, assessment_id="jx-strong").graph


@pytest.fixture(scope="module")
def weak():
    return assess(WEAK, redact=False, assessment_id="jx-weak").graph


@samples_only
def test_the_xml_reader_does_not_reach_the_braces_builder(strong):
    """A graph exists at all.

    junos_builder reads `cfg.multi`, which XmlConfig does not have. Handing it
    an XML document raised AttributeError inside the builder, and every Juniper
    XML device silently got no graph -- invisible until the pipeline's bare
    `except` became a logged one.
    """
    assert strong is not None
    assert strong.rules, "the policy in this export must reach the graph"


@samples_only
def test_a_permit_all_default_is_read_not_assumed(weak):
    """The false-PASS this pairing exists to catch.

    `<default-policy><permit-all/></default-policy>` is a device that forwards
    anything no rule matched. Defaulting to deny would report it as compliant.
    """
    assert weak.default_action == "allow"
    assert weak.default_action_observed is True


@samples_only
def test_a_deny_all_default_is_also_read(strong):
    assert strong.default_action == "deny"
    assert strong.default_action_observed is True


@samples_only
def test_the_permit_all_device_actually_permits(weak):
    """The default is not decoration -- it decides unmatched traffic."""
    a = ask(weak, Query(source="10.0.0.5", destination="8.8.8.8", port=3389,
                        protocol="tcp", source_zone="trust",
                        destination_zone="untrust"))
    assert a.permitted is True
    assert "default" in a.decided_by.lower()


@samples_only
def test_the_zone_pair_scopes_the_rule(strong):
    rule = strong.rules[0]
    assert rule.source_zones == ["trust"]
    assert rule.destination_zones == ["untrust"]
    assert "untrust" in strong.untrusted_zones


@samples_only
def test_an_empty_then_element_is_read_as_the_action(strong):
    """Junos writes the action as an empty element -- <permit/>.

    Its PRESENCE is the value; there is no text to read.
    """
    assert strong.rules[0].action == "allow"
    assert strong.rules[0].logging is True     # <log><session-close/></log>


@samples_only
def test_a_predefined_application_resolves(strong):
    """junos-https is built into the platform and never written to the config.

    Left unresolved it would make the rule unevaluable, and almost every real
    Junos policy references one of these.
    """
    node = strong.lookup("junos-https")
    assert node is not None
    assert node.values == ["tcp/443"]
    assert node.attrs["predefined"] is True
    assert "not read from this configuration" in node.attrs["provenance"]


@samples_only
def test_an_address_absent_from_the_export_is_disclosed_not_guessed(strong):
    """`LAN-NET` is referenced but this export carries no address book.

    The rule is therefore unevaluable, and the answer must say so rather than
    quietly falling through to the default as though nothing were missing.
    """
    a = ask(strong, Query(source="10.0.0.5", destination="8.8.8.8", port=443,
                          protocol="tcp", source_zone="trust",
                          destination_zone="untrust"))
    assert a.skipped == ["allow-web-out"]
    assert "could not be evaluated" in a.explain()


def test_several_zone_pairs_make_the_builder_refuse():
    """Rules and zone pairs cannot be associated through this reader.

    Pairing them by position would attach a rule to the wrong security
    boundary and then answer reachability confidently and wrongly. Returning
    None is a gap the caller already handles: the analyses report "no
    rule-graph builder for this platform" and refuse.
    """
    from ncsa.graph.junos_xml_builder import build

    class _Cfg:
        paths: list = []

        def get_all(self, path):
            if path.endswith("from-zone-name"):
                return [("trust", 1, "<from-zone-name>trust</from-zone-name>"),
                        ("dmz", 2, "<from-zone-name>dmz</from-zone-name>")]
            if path.endswith("to-zone-name"):
                return [("untrust", 3, ""), ("trust", 4, "")]
            return []

        def get(self, path):
            return None

        def evidence(self, ln, raw):
            return None

    assert build(_Cfg()) is None, (
        "an ambiguous zone-pair structure must produce no graph, not a wrong one")
