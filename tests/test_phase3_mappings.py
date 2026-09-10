"""Mappings added by reading real device output, and the bugs that exposed.

Phase 3's finding was not that the packs were thin. It was that we hold exactly
ONE substantial real configuration -- a 92,635-setting SonicWall export -- and
that every other artifact is a fragment or a constructed fixture of 16-112
records. On those, an UNKNOWN mostly means "this file does not contain the
setting", which no amount of pack work can fix.

So this file covers only what a REAL config could validate, and each test names
the device evidence behind it.
"""
import os

import pytest

from ncsa.pipeline import assess
from ncsa.schema.enums import ResultState

SW = r"E:\sonicwall config file.txt"
ASA = r"E:\ASA.txt"
sw_only = pytest.mark.skipif(not os.path.exists(SW), reason="SonicWall sample absent")
asa_only = pytest.mark.skipif(not os.path.exists(ASA), reason="ASA sample absent")


def _finding(result, field):
    return next(f for f in result.assessment.findings if f.field == field)


@sw_only
def test_external_auth_is_true_when_any_server_type_is_enabled():
    """The device runs LDAP with RADIUS off, and we reported "no AAA".

    Two mappings targeted `authentication.aaa_enabled` -- one reading RADIUS,
    one reading LDAP -- onto a single boolean. Whichever applied last won, so
    the verdict depended on pack ORDER rather than on the device: RADIUS is
    off here, so a box with external authentication configured reported
    exactly the opposite.

    A derivation over all the sources replaces both, and cites the one that
    answered.
    """
    r = assess(SW, redact=False, assessment_id="p3-aaa")
    f = _finding(r, "authentication.aaa_enabled")
    assert f.state is ResultState.PASS
    assert f.observed is True
    assert f.evidence, "a claim about AAA needs the line behind it"
    assert "ldapSrvrEnabled" in f.evidence[0].raw


@sw_only
def test_a_field_with_no_source_present_stays_undecided():
    """`path_any_true` must not read "no source present" as "false".

    Absence of every source is a question the configuration does not answer.
    Returning False there would turn our own coverage gap into a finding
    against the device -- the same mistake as the domain-level N/A.
    """
    from ncsa.readers.path_pack import derive_path_any_true

    class _Cfg:
        def get(self, path):
            return None

        def glob(self, pattern):
            return []

    value, evidence = derive_path_any_true(_Cfg(), {"paths": ["nothing*"]})
    assert value is None, "absent sources must be undecided, never False"
    assert evidence == []


@asa_only
def test_local_only_authentication_is_a_finding_not_an_assumption():
    """`aaa authentication ssh console LOCAL` says there is no AAA server.

    The pack expressed that with `if_absent: false`, which produces a
    DEFAULT_ASSUMED value -- correctly reported as UNKNOWN, because an assumed
    value cannot decide a control. The result was that a device plainly stating
    what it does produced no finding at all. Reading the LOCAL form directly
    makes it an observation, with the line attached.
    """
    r = assess(ASA, redact=False, assessment_id="p3-asa-aaa")
    f = _finding(r, "authentication.aaa_enabled")
    assert f.state is ResultState.FAIL
    assert f.observed is False
    assert f.evidence and "console LOCAL" in f.evidence[0].raw


@asa_only
def test_interface_state_is_read_on_the_asa():
    """The reference ASA has nine interfaces, every one of them shut.

    None of interfaces.name / shutdown / description was mapped for the ASA at
    all, so a device whose entire dataplane is down said nothing about it.
    """
    r = assess(ASA, redact=False, assessment_id="p3-asa-if")
    shut = _finding(r, "interfaces.shutdown")
    assert shut.state is not ResultState.UNKNOWN
    assert shut.evidence, "interface state must cite the line"


def test_the_asa_pack_does_not_guess_at_snmp_state():
    """`no snmp-server location` does NOT mean the agent is off.

    It clears the location string. A mapping that read the family prefix would
    report a live SNMP agent as disabled, which suppresses every SNMP control
    behind the `requires` gate. The form is left unmapped until a real config
    shows a bare `no snmp-server`.
    """
    import yaml
    doc = yaml.safe_load(open("packs/cisco_asa.yaml", encoding="utf-8"))
    for m in doc.get("mappings", []):
        if m.get("field") == "snmp.version":
            rx = m.get("regex", "")
            assert "no snmp-server" not in rx, (
                "mapping snmp.version from a `no snmp-server ...` line reads a "
                "cleared location string as a disabled agent")
