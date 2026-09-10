"""Palo Alto PAN-OS pack, validated against a REAL exported configuration.

The fixture is not written by us. That matters: a hand-made fixture tends to be
written to match the pack, which makes the pack look correct against its own
assumptions. The real export immediately exposed two things an invented one
would not have —

  * PAN-OS names every interface `ethernet1/1` and every address `81.81.0.1/24`,
    and the slash inside the entry name was splitting the path segment apart;
  * a real config simply omits whole sections (this one has no NTP, no syslog,
    no login banner), so mappings for them cannot be validated here and must
    not be silently assumed correct.
"""
import os
import re

import pytest
import yaml

from ncsa.pipeline import assess, load_packs
from ncsa.readers.pack import load_pack
from ncsa.readers.path_pack import _readable_scope
from ncsa.readers.xml_reader import load as load_xml

FIXTURE = os.path.join(
    os.path.dirname(__file__), "fixtures", "panos_running_config.xml")

#: Mappings the reference export cannot exercise, because the config does not
#: contain those sections at all. Listed explicitly so the gap is visible
#: rather than hidden inside a passing test.
UNVALIDATED = {
    "management.vty.access_class", "management.vty.exec_timeout",
    "authentication.min_password_length", "authentication.complexity",
    "banner.login", "banner.motd",
    "logging.servers", "logging.severity",
    "time.servers", "time.authenticated",
    "snmp.communities",
    "management.ssh.enabled", "management.https.enabled",
    "management.icmp_ratelimit",          # only set when disabled
    "firewall.rules.description",         # rules in this export have none
}


@pytest.fixture(scope="module")
def cfg():
    return load_xml(FIXTURE)


@pytest.fixture(scope="module")
def pack():
    return load_pack("packs/paloalto.yaml")


@pytest.fixture(scope="module")
def result():
    return assess(FIXTURE, redact=True, assessment_id="panos-test")


def test_the_pack_loads_and_is_registered(pack):
    """`load_packs` skips a malformed pack silently, so assert it loaded."""
    assert pack.vendor == "paloalto"
    assert pack.platform == "panos"
    assert pack.reader == "xml"
    assert "panos" in {p.platform for p in load_packs()}


def test_entry_names_containing_a_slash_stay_in_one_segment(cfg):
    """PAN-OS interface names are `ethernet1/1`. The slash must not split them.

    Before this was fixed the path had 11 segments instead of 9, every
    interface and every IP address was unreachable by any mapping, and the
    failure was silent — the fields simply came back NOT_OBSERVED.
    """
    iface = [p for p in cfg.paths if "layer3/ip" in p]
    assert iface, "fixture should contain a layer3 interface address"
    path = iface[0]
    assert "entry[ethernet1%2F1]" in path
    assert len(path.split("/")) == 9


def test_a_wildcard_matches_a_named_entry(cfg):
    """`*` replaces a whole segment; `entry[*]` matches nothing.

    Getting this backwards yields an empty result set and, again, silence.
    """
    assert cfg.glob("devices/*/vsys/*/rulebase/security/rules/*/action")
    assert not cfg.glob(
        "devices/*/vsys/entry[*]/rulebase/security/rules/entry[*]/action")


def test_scope_labels_read_as_the_device_names_them():
    """A finding must say `ethernet1/1`, not `entry[ethernet1%2F1]`."""
    assert _readable_scope("entry[ethernet1%2F1]") == "ethernet1/1"
    assert _readable_scope("entry[81.81.0.1%2F24]") == "81.81.0.1/24"
    assert _readable_scope("entry[secrule1]") == "secrule1"
    assert _readable_scope("port1") == "port1"


def test_every_validatable_mapping_resolves(cfg):
    """Each mapping not in UNVALIDATED must hit the real export.

    A path with a typo returns NOT_OBSERVED, which is indistinguishable from a
    device that genuinely lacks the setting — so it is asserted, not trusted.
    """
    raw = yaml.safe_load(open("packs/paloalto.yaml", encoding="utf-8"))
    missing = []
    for m in raw["mappings"]:
        path, field = m.get("path"), m["field"]
        if not path or field in UNVALIDATED:
            continue
        found = cfg.glob(path) if "*" in path else cfg.get(path) is not None
        if not found:
            missing.append(f"{field} <- {path}")
    assert not missing, "mappings resolving to nothing: " + "; ".join(missing)


def test_the_unvalidated_list_is_honest(cfg):
    """Nothing may sit in UNVALIDATED that the export can actually exercise.

    Without this the list becomes a place to hide broken mappings.
    """
    raw = yaml.safe_load(open("packs/paloalto.yaml", encoding="utf-8"))
    by_field = {m["field"]: m.get("path") for m in raw["mappings"]}
    wrongly_excused = []
    for field in UNVALIDATED:
        path = by_field.get(field)
        if not path:
            continue
        found = cfg.glob(path) if "*" in path else cfg.get(path) is not None
        if found:
            wrongly_excused.append(field)
    assert not wrongly_excused, (
        "these resolve and should not be excused: " + ", ".join(wrongly_excused))


def test_negative_booleans_are_inverted(result):
    """`<disable-telnet>yes</disable-telnet>` means telnet is OFF.

    Read literally it would set `telnet.enabled = True` and report a hardened
    device as insecure — a false positive on the most basic control there is.
    """
    for field, expected in (("management.telnet.enabled", False),
                            ("management.http.enabled", False)):
        found = [f for f in result.assessment.findings if f.field == field]
        assert found, f"no finding for {field}"
        assert found[0].observed is expected
        assert found[0].evidence, "an inverted read still needs its line"
        assert "disable-" in found[0].evidence[0].raw


def test_identity_and_support(result):
    assert result.supported is True
    assert result.identity.vendor == "paloalto"
    assert result.identity.os == "PAN-OS"
    assert result.identity.hostname == "FW1"


def test_coverage_travels_with_the_score(result):
    cov = result.coverage()
    assert cov["controls_total"] > 0
    assert (cov["score_pct"] is None) == (cov["controls_decided"] == 0)
    assert cov["not_applicable"] > 0, "declared N/A fields should be honoured"


def test_no_finding_claims_a_value_without_evidence(result):
    """Every OBSERVED result must cite a line. This is the product's premise."""
    naked = [f.control_id for f in result.assessment.findings
             if f.observed is not None and not f.evidence]
    assert not naked, f"findings asserting a value with no evidence: {naked}"
