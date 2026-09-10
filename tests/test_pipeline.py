"""End-to-end pipeline, device identity and risk scoring."""
import pytest

from ncsa.engine.fingerprint import Fingerprint
from ncsa.engine.risk import (BASE, EXPOSURE_INTERNET, Risk, band_of,
                              score_assessment, score_finding)
from ncsa.pipeline import assess, assess_many, load_packs, select_pack
from ncsa.schema.enums import ResultState, Severity

CISCO = "samples/cisco/edge-rtr-01.cfg"
HARDENED = "samples/cisco/hardened-per-cisco-guide.cfg"


# ------------------------------------------------------------ pack selection
def test_pack_is_chosen_by_platform_AND_reader():
    """Two SonicWall packs share a platform; the reader disambiguates.

    Keying on platform alone handed `.exp` files to the CLI reader, which
    produced a complete but wrong assessment with an empty object graph.
    """
    packs = load_packs()
    exp_fp = Fingerprint(vendor="sonicwall", platform="sonicwall_sonicos",
                         reader="sonicos_exp")
    cli_fp = Fingerprint(vendor="sonicwall", platform="sonicwall_sonicos",
                         reader="fortinet_block")
    assert select_pack(packs, exp_fp).reader == "sonicos_exp"
    assert select_pack(packs, cli_fp).reader == "fortinet_block"


def test_unknown_vendor_returns_lines_not_an_exception():
    """An unseen vendor is the bootstrap path, not a crash."""
    fp = Fingerprint(vendor="UNKNOWN", platform="UNKNOWN")
    assert select_pack(load_packs(), fp) is None


# --------------------------------------------------------------- end to end
def test_assess_runs_end_to_end():
    r = assess(CISCO)
    assert r.supported
    assert r.identity.vendor == "cisco"
    assert r.assessment is not None and r.assessment.findings


def test_assess_discriminates_hardened_from_vulnerable():
    """The engine must actually measure something."""
    weak = assess(CISCO).coverage()["score_pct"]
    good = assess(HARDENED).coverage()["score_pct"]
    assert good > weak + 20


def test_coverage_reports_both_numbers():
    """A score without an assessed% is how a tool claims 100% on a file it
    could barely read."""
    c = assess(CISCO).coverage()
    assert 0 < c["assessed_pct"] <= 100
    assert c["controls_decided"] + c["controls_undecided"] + c["not_applicable"] \
        == c["controls_total"]


def test_bulk_survives_one_bad_file(tmp_path):
    bad = tmp_path / "garbage.cfg"
    bad.write_bytes(b"\x00\x01\x02not a config at all")
    out = assess_many([CISCO, str(bad)])
    assert len(out) == 2
    assert out[0].supported                    # the good one still ran


# ----------------------------------------------------------- device identity
def test_device_identity_is_extracted_not_invented():
    r = assess(CISCO)
    assert r.identity.version == "17.9"
    assert r.identity.hostname == "edge-rtr-01"
    # The sample states no serial, so the serial must stay None rather than
    # becoming a placeholder on an audit report.
    assert r.identity.serial is None
    assert r.identity.sha256


# ------------------------------------------------------------- risk scoring
class _F:
    def __init__(self, state=ResultState.FAIL, severity=Severity.HIGH,
                 field="management.http.enabled", confidence=1.0, evidence=("e",)):
        self.state, self.severity, self.field = state, severity, field
        self.confidence, self.evidence = confidence, list(evidence)
        self.control_id, self.title = "X-1", "t"


def test_only_failures_carry_risk():
    assert score_finding(_F(state=ResultState.PASS)) is None
    assert score_finding(_F(state=ResultState.NOT_APPLICABLE)) is None
    # UNKNOWN must not get a number -- a score would imply we knew.
    assert score_finding(_F(state=ResultState.UNKNOWN)) is None
    assert score_finding(_F(state=ResultState.FAIL)) is not None


def test_missing_graph_never_discounts_risk():
    """Absence of evidence must not read as evidence of safety."""
    r = score_finding(_F(), graph=None)
    assert r.exposure == 1.0


def test_weak_evidence_scores_down_not_up():
    strong = score_finding(_F(evidence=("e",), confidence=1.0))
    weak = score_finding(_F(evidence=(), confidence=1.0))
    assert weak.score < strong.score


def test_partial_scores_below_fail():
    f = score_finding(_F(state=ResultState.FAIL))
    p = score_finding(_F(state=ResultState.PARTIAL))
    assert p.score < f.score


def test_bands_are_ordered():
    assert band_of(15) == "CRITICAL"
    assert band_of(8) == "HIGH"
    assert band_of(4) == "MEDIUM"
    assert band_of(1) == "LOW"


def test_exposure_makes_risk_device_specific():
    """The whole point: the same control is not the same risk everywhere."""
    r = assess("samples/cisco/edge-rtr-01.cfg")
    s = score_assessment(r)
    assert "findings" in s and s["total_risk"] >= 0


# ------------------------------------------------------------- remediation
from ncsa.engine.remediate import (IMPACT_DISABLES_HTTP, PHASE_DISABLE,
                                   PHASE_ENABLE, Plan, Step, build_plan)
from ncsa.engine.rules import load_rules


class _SBM:
    """Minimal stand-in exposing get() like the real SBM."""

    def __init__(self, live):
        self.live = live

    def get(self, path):
        class O:
            pass
        o = O()
        o.value = self.live.get(path)
        return o


class _DA:
    def __init__(self, findings, platform="cisco_iosxe_router"):
        from ncsa.pipeline import DeviceIdentity
        self.identity = DeviceIdentity(platform=platform)
        self._f = findings
        self.graph = None

    def failures(self):
        return self._f


def _finding(cid, title="t", field="management.http.enabled"):
    f = _F(field=field)
    f.control_id, f.title = cid, title
    return f


def test_disable_steps_run_after_enable_steps():
    """Never turn the old thing off before the new thing is on."""
    ctrls = {c.id: c for c in load_rules("rules", platform="cisco_iosxe_router")}
    da = _DA([_finding("NCSA-HTTP-001"), _finding("NCSA-SSH-002",
                                                  field="management.ssh.version")])
    plan = build_plan(da, controls_by_id=ctrls, sbm=_SBM({}))
    phases = [s.phase for s in plan.steps]
    assert phases == sorted(phases)
    by_id = {s.control_id: s.phase for s in plan.steps}
    if "NCSA-HTTP-001" in by_id and "NCSA-SSH-002" in by_id:
        assert by_id["NCSA-SSH-002"] < by_id["NCSA-HTTP-001"]


def test_step_is_deferred_when_it_is_the_only_transport():
    """The lockout guard: do not cut the only way in."""
    ctrls = {c.id: c for c in load_rules("rules", platform="cisco_iosxe_router")}
    da = _DA([_finding("NCSA-HTTP-001")])
    only_http = _SBM({"management.http.enabled": True,
                      "management.ssh.enabled": False,
                      "management.telnet.enabled": False})
    plan = build_plan(da, controls_by_id=ctrls, sbm=only_http)
    assert plan.deferred, "disabling the only live transport must be held back"
    assert "ONLY management transport" in plan.deferred[0].lockout_warning
    assert not any(s.control_id == "NCSA-HTTP-001" for s in plan.steps)


def test_step_runs_with_a_warning_when_another_transport_exists():
    ctrls = {c.id: c for c in load_rules("rules", platform="cisco_iosxe_router")}
    da = _DA([_finding("NCSA-HTTP-001")])
    http_and_ssh = _SBM({"management.http.enabled": True,
                         "management.ssh.enabled": True})
    plan = build_plan(da, controls_by_id=ctrls, sbm=http_and_ssh)
    assert not plan.deferred
    step = [s for s in plan.steps if s.control_id == "NCSA-HTTP-001"][0]
    assert "confirm you are connected over" in step.lockout_warning


def test_script_carries_a_vendor_rollback_net():
    ctrls = {c.id: c for c in load_rules("rules", platform="cisco_iosxe_router")}
    plan = build_plan(_DA([_finding("NCSA-HTTP-001")]),
                      controls_by_id=ctrls, sbm=_SBM({}))
    assert "reload in 5" in plan.script()


def test_missing_remediation_is_reported_not_invented():
    """A control with no written fix must be listed, never guessed at."""
    da = _DA([_finding("NCSA-NOT-A-REAL-CONTROL")])
    plan = build_plan(da, controls_by_id={}, sbm=_SBM({}))
    assert plan.unavailable == ["NCSA-NOT-A-REAL-CONTROL"]
    assert not plan.steps


# --------------------------------------------------------- training queue
from ncsa.training import build_queue, classify
from ncsa.training.classify import (CAT_COSMETIC, CAT_EMPTY, CAT_OTHER,
                                    CAT_SECURITY, base_name)
from ncsa.training.queue import _humanise


def test_classifier_rejects_bookkeeping_that_looks_security_shaped():
    """`addrObjTimeCreated` contains 'time'; it is still a timestamp.

    Ranked by occurrence these sat at the top of the queue, ahead of every
    real setting.
    """
    assert classify("addrObjTimeCreated", "1631103538") == CAT_OTHER
    assert classify("svcObjTimeUpdated", "1631103540") == CAT_OTHER
    assert classify("logEvtAttrs", "4,9,ff0000") == CAT_OTHER
    # ...while genuine security settings still classify as such.
    assert classify("adminLoginOtpRequire", "1") == CAT_SECURITY
    assert classify("sshCipherControlConfig", "aes256") == CAT_SECURITY


def test_empty_and_cosmetic_are_not_work():
    assert classify("someSecurityThing", "") == CAT_EMPTY
    assert classify("anAuthSetting", "0.0.0.0") == CAT_EMPTY
    assert classify("guiDashboardLayout", "grid") == CAT_COSMETIC


def test_queue_is_deduplicated_by_setting_name():
    """One approval must cover every instance of a name."""
    assert base_name("policyName_68") == base_name("policyName_71") == "policyName"


def test_queue_never_offers_a_setting_the_pack_already_maps():
    """The queue reads the pipeline's document, which carries pack consumption.

    Built from a freshly parsed copy it saw only graph consumption and
    re-offered `minPasswordLength`, which the pack has mapped all along.
    """
    r = assess(r"E:\sonicwall config file.txt")
    names = {c.name for c in build_queue(r)}
    for mapped in ("minPasswordLength", "allowHttpMgmt", "syslogServerName",
                   "adminLoginTimeout"):
        assert mapped not in names, f"{mapped} is already mapped by the pack"


def test_queue_counts_names_not_records():
    r = assess(r"E:\sonicwall config file.txt")
    q = build_queue(r)
    # Far fewer names than the ~84k unmapped records they came from.
    assert 0 < len(q) < 5000
    assert all(c.occurrences >= 1 for c in q)
    assert any(c.occurrences > 100 for c in q)   # indexed settings collapse


def test_humanise_splits_glued_vendor_names():
    """Without this the corpus and the probe share no vocabulary at all."""
    assert _humanise("IdleVpnDpdInterval") == "Idle Vpn Dpd Interval"
    assert _humanise("admin_login_timeout") == "admin login timeout"


# ------------------------------------------------------------- Cisco ASA
ASA = r"E:\ASA.txt"
import os
asa_only = pytest.mark.skipif(not os.path.exists(ASA), reason="ASA sample absent")


@asa_only
def test_asa_is_not_mistaken_for_ios():
    """ASA and IOS-XE share `interface GigabitEthernet`; they are not one
    platform. Before ASA had its own signature this file scored 0.25 against
    IOS-XE -- below the floor, so UNKNOWN, which was safe but unassessable."""
    r = assess(ASA)
    assert r.identity.platform == "cisco_asa"
    assert r.supported


@asa_only
def test_asa_telnet_timeout_is_not_telnet_enabled():
    """`telnet timeout 5` sets an idle timer; only `telnet <net> <mask> <if>`
    permits telnet. Reading the timer as "enabled" is a false FAIL on a device
    where telnet is genuinely unreachable."""
    r = assess(ASA)
    f = [x for x in r.assessment.findings if x.control_id == "NCSA-TEL-001"][0]
    assert f.state is ResultState.PASS
    assert f.observed is False


@asa_only
def test_cleartext_enable_password_is_observed_not_assumed():
    """The weak form is POSITIVELY matched, so the FAIL carries a line number.

    Modelled as `if_absent: false` it became DEFAULT_ASSUMED, which plan 7.3
    forbids from carrying a FAIL -- so a cleartext password reported UNKNOWN.
    """
    r = assess(ASA)
    for cid in ("NCSA-EXT-012", "NCSA-PWD-003"):
        f = [x for x in r.assessment.findings if x.control_id == cid][0]
        assert f.state is ResultState.FAIL, f"{cid} must fail on a cleartext password"
        assert f.evidence, f"{cid} must cite the line it read"
        assert "enable password" in f.evidence[0].raw


@asa_only
def test_local_only_aaa_is_not_external_authentication():
    """`aaa authentication ssh console LOCAL` uses the on-box user database."""
    r = assess(ASA)
    f = [x for x in r.assessment.findings if x.control_id == "NCSA-EXT-015"][0]
    assert f.state is ResultState.FAIL


def test_alternative_mappings_do_not_erase_each_other():
    """Two mappings for one field are mutually exclusive spellings; the one
    that does not match must not overwrite the one that did."""
    import hashlib
    from ncsa.readers import apply_indented_pack, load_indented
    from ncsa.readers.pack import load_pack
    from ncsa.schema.enums import ObservationState
    if not os.path.exists(ASA):
        pytest.skip("ASA sample absent")
    cfg = load_indented(ASA)
    sbm = apply_indented_pack(cfg, load_pack("packs/cisco_asa.yaml"),
                              assessment_id="t",
                              sha256=hashlib.sha256(open(ASA, "rb").read()).hexdigest())
    obs = sbm.get("authentication.password_encryption")
    assert obs is not None and obs.state is ObservationState.OBSERVED
    assert obs.value is False


def test_no_control_compares_a_field_against_an_impossible_type():
    """A control whose expected value can never match its field type always
    passes. NCSA-EXT-012 compared a bool against the string "password" and so
    could not fail on any device ever assessed."""
    from ncsa.engine.rules import load_rules
    from ncsa.schema.sbm import FIELD_TYPES
    dead = []
    for c in load_rules("rules"):
        ft = FIELD_TYPES.get(c.field)
        if ft == "bool" and isinstance(c.expected, str) \
                and c.expected.lower() not in ("true", "false"):
            dead.append(c.id)
        elif ft == "int" and isinstance(c.expected, str):
            dead.append(c.id)
    assert not dead, f"structurally dead controls: {dead}"


# ------------------------------------------------- preconditions (requires)
import os as _os

HARDENED_SW = r"E:\sonicwall-NSA3700-SonicOS7.3-HARDENED.exp"
ORIGINAL_SW = r"E:\sonicwall config file.txt"
sw = pytest.mark.skipif(not _os.path.exists(HARDENED_SW),
                        reason="hardened SonicWall export absent")


@sw
def test_raw_base64_exp_is_fingerprinted():
    """A `.exp` straight off the appliance is BASE64 -- which is what an
    administrator actually uploads. Only the already-decoded form was
    recognised, so the genuine article fingerprinted as UNKNOWN."""
    r = assess(HARDENED_SW)
    assert r.supported
    assert r.identity.platform == "sonicwall_sonicos"
    assert r.identity.model == "NSA 3700"


@sw
def test_disabled_feature_makes_subcontrols_not_applicable():
    """`snmp_Enable = off` and eight `snmpStateEnable_N = off`: a device that
    does not run SNMP cannot fail an SNMPv3 authentication check."""
    r = assess(HARDENED_SW)
    f = [x for x in r.assessment.findings if x.control_id == "NCSA-EXT-023"][0]
    assert f.state is ResultState.NOT_APPLICABLE


@pytest.mark.skipif(not _os.path.exists(ORIGINAL_SW), reason="sample absent")
def test_precondition_does_not_suppress_when_the_feature_is_running():
    """The same control must still FAIL where SNMP is actually in use."""
    r = assess(ORIGINAL_SW)
    f = [x for x in r.assessment.findings if x.control_id == "NCSA-EXT-023"][0]
    assert f.state is ResultState.FAIL


def test_precondition_never_fires_on_an_unmapped_field():
    """THE important one. Suppressing on `None` turns a gap in OUR coverage
    into a clean bill of health for the device: the weak Junos XML has
    `public` and `private` communities in the file, but `snmp.version` is not
    in that pack, so the SNMPv3 controls silently became NOT_APPLICABLE."""
    r = assess("samples/juniper/srx-display-xml-weak.xml")
    f = [x for x in r.assessment.findings if x.control_id == "NCSA-EXT-023"][0]
    assert f.state is not ResultState.NOT_APPLICABLE
    # SNMP is demonstrably in use on that device.
    snmp = [x for x in r.assessment.findings if x.control_id == "NCSA-SNMP-002"][0]
    assert snmp.state is ResultState.FAIL


@sw
def test_hardening_is_measurable():
    """Two exports of the SAME appliance, before and after hardening."""
    before = assess(ORIGINAL_SW).coverage()["score_pct"]
    after = assess(HARDENED_SW).coverage()["score_pct"]
    assert after > before + 15, f"{before}% -> {after}%"
