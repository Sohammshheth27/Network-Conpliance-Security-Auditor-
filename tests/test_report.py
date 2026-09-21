"""The formal report must be accurate, complete and monochrome.

A report is the artefact an auditor signs against, which makes a wrong figure
in it worse than a wrong figure anywhere else in the product: it outlives the
session, it gets emailed, and nobody re-derives it.

So this file asserts three things, in order of importance:

  1. EVERY figure in the report equals what the engine currently reports. Not
     a sample -- the score, the coverage, all seven state counts, and the
     record accounting.
  2. EVERY control appears. All failures, all exclusions, all undecided. A
     report that silently drops the undecided controls reads as far more
     complete than the assessment actually was.
  3. It is monochrome. No colour, no fills. Required by the brief, and it also
     stops a reader skimming a badge instead of reading the evidence.
"""
import os
import re

import pytest

from ncsa.pipeline import assess
from ncsa.report import build_report
from ncsa.schema.enums import ResultState

SW = r"E:\sonicwall config file.txt"
ASA = r"E:\ASA.txt"
sw_only = pytest.mark.skipif(not os.path.exists(SW), reason="SonicWall sample absent")
asa_only = pytest.mark.skipif(not os.path.exists(ASA), reason="ASA sample absent")


@pytest.fixture(scope="module")
def sw():
    da = assess(SW, redact=False, assessment_id="TEST-0001")
    return da, build_report(da, "TEST-0001")


@sw_only
def test_the_device_is_identified_by_every_detail_the_config_states(sw):
    """A report about the wrong device is worthless.

    Hostname, serial and model are what tie this document to a physical
    appliance, and the SHA-256 ties it to the exact file assessed.
    """
    da, html = sw
    i = da.identity
    for attr in ("hostname", "serial", "model", "os", "version", "vendor"):
        value = getattr(i, attr)
        if value:
            assert str(value) in html, f"{attr}={value!r} missing from the report"
    assert i.sha256 in html, "the file digest must appear"


@sw_only
def test_the_score_is_never_shown_without_coverage(sw):
    """A score alone is a lie of omission.

    100% of what we could read is not 100% of the device, and the two figures
    have to travel together.
    """
    da, html = sw
    cov = da.coverage()
    assert f"{cov['score_pct']}%" in html
    assert f"{cov['assessed_pct']}%" in html
    assert "decided controls" in html
    assert "coverage" in html.lower()


@sw_only
def test_every_state_count_matches_the_engine(sw):
    da, html = sw
    for state, n in da.counts().items():
        if n:
            assert f">{n}</td>" in html, (
                f"count for {state} ({n}) does not appear in the report")


@sw_only
def test_every_failing_control_is_printed_with_its_evidence(sw):
    """Not a summary. Each failure, individually, with the line behind it."""
    da, html = sw
    fails = [f for f in da.assessment.findings
             if f.state in (ResultState.FAIL, ResultState.PARTIAL)]
    assert fails, "expected failures on this device"
    missing = [f.control_id for f in fails if f.control_id not in html]
    assert not missing, f"failing controls absent from the report: {missing}"

    # And at least one verbatim configuration line, so the claim is checkable.
    with_ev = next(f for f in fails if f.evidence)
    assert with_ev.evidence[0].raw[:40] in html


@sw_only
def test_every_excluded_control_is_listed_with_its_justification(sw):
    """An exclusion raises the score by leaving the denominator.

    Listing them without the reason would be the same unjustified exclusion
    the engine refuses to make internally.
    """
    da, html = sw
    na = [f for f in da.assessment.findings
          if f.state is ResultState.NOT_APPLICABLE]
    missing = [f.control_id for f in na if f.control_id not in html]
    assert not missing, f"excluded controls absent: {missing}"
    assert "excluded from the compliance score" in _flat(html)


@sw_only
def test_every_undecided_control_is_listed(sw):
    """The section that makes the report honest.

    Dropping these would make the assessment read as far more complete than
    it was.
    """
    da, html = sw
    unk = [f for f in da.assessment.findings
           if f.state is ResultState.UNKNOWN]
    missing = [f.control_id for f in unk if f.control_id not in html]
    assert not missing, f"undecided controls absent: {missing}"
    assert "neither passes nor failures" in _flat(html)


@sw_only
def test_the_report_is_monochrome(sw):
    """No colour, no fills. Required, and it keeps the words load-bearing."""
    _da, html = sw
    colours = set(re.findall(r"#[0-9a-fA-F]{3,8}\b", html))
    assert colours <= {"#000", "#fff", "#000000", "#ffffff"}, (
        f"non-monochrome colours in the report: {sorted(colours)}")
    for banned in ("rgba(", "linear-gradient", "box-shadow", "background-image"):
        assert banned not in html, f"{banned} has no place in a formal report"


@sw_only
def test_all_nine_sections_are_present(sw):
    _da, html = sw
    for heading in ("1. Device identification", "2. Result",
                    "3. Result states", "4. Findings",
                    "5. Controls not applicable", "6. Controls not decided",
                    "7. Policy analysis", "8. Remediation",
                    "9. Method and limitations"):
        assert heading in html, f"missing section: {heading}"


def _flat(html: str) -> str:
    """Collapse whitespace before matching prose.

    The report is hand-wrapped for readability in the source, so a sentence
    that reads as one line in the PDF spans two in the template. Asserting
    against the raw string tests the line breaks, not the meaning.
    """
    return " ".join(html.split())


@sw_only
def test_the_method_states_what_the_assessment_does_not_cover(sw):
    """An auditor needs the limits in writing, not implied."""
    _da, html = sw
    flat = _flat(html)
    assert "What this assessment does not cover" in flat
    assert "must not be recorded as a pass" in flat


@sw_only
def test_remediation_is_marked_as_unverified_against_this_device(sw):
    """A config file records state, never the command that produced it.

    So remediation is prescriptive and cannot be checked against the file.
    Saying so is the difference between a suggestion and a false assurance.
    """
    _da, html = sw
    flat = _flat(html)
    assert "Review before use" in flat
    assert "cannot be verified against the file assessed" in flat
    assert "Each step carries a verification command" in flat


@sw_only
def test_untrusted_config_content_is_escaped(sw):
    """Device content is reproduced verbatim as evidence, and is untrusted.

    This project has already found injection-shaped content inside real device
    data.
    """
    _da, html = sw
    body = html.split("<body>", 1)[1]
    # No raw <script> can survive escaping of config-derived text.
    assert "<script" not in body.lower()


@asa_only
def test_a_platform_with_no_policy_graph_says_so():
    """Absence of policy analysis must be explained, not silently omitted.

    An omitted section is indistinguishable from a clean one.
    """
    da = assess(ASA, redact=True, assessment_id="TEST-ASA")
    html = build_report(da, "TEST-ASA")
    flat = " ".join(html.split())
    assert "No policy object graph was constructed" in flat
    assert "not a statement about the device" in flat


def test_an_unassessable_file_produces_a_refusal_not_a_score(tmp_path):
    """A file we could not read must never yield a compliance figure.

    Presenting one would require assuming facts about a device that could not
    be parsed -- which is the failure this whole product exists to avoid.
    """
    from ncsa.pipeline import DeviceAssessment, DeviceIdentity

    da = DeviceAssessment(
        identity=DeviceIdentity(source_file="encrypted-backup.exp",
                                sha256="a" * 64),
        supported=False,
        notes=["The backup is encrypted and no password was supplied."])
    html = build_report(da, "TEST-REFUSED")
    assert "Assessment not performed" in html
    assert "encrypted" in html
    assert "Compliance score" not in html


# ---------------------------------------------------------------------------
# Locating a finding in the configuration.
#
# A finding an administrator cannot find is a finding they cannot fix. These
# assert the position is not merely PRESENT but CORRECT -- read back from the
# file itself -- because a confidently wrong line number is worse than none.
# ---------------------------------------------------------------------------

@asa_only
def test_cited_line_numbers_match_the_actual_file():
    """`sed -n '80p' ASA.txt` must show the line the report quotes."""
    da = assess(ASA, redact=False, assessment_id="TEST-LINES")
    source = open(ASA, encoding="utf-8", errors="replace").read().splitlines()

    checked = 0
    for finding in da.assessment.findings:
        for e in finding.evidence:
            if e.line is None:
                continue
            assert 1 <= e.line <= len(source), (
                f"{finding.control_id} cites line {e.line}; the file has "
                f"{len(source)} lines")
            actual = source[e.line - 1].strip()
            assert e.raw.strip() in actual or actual in e.raw.strip(), (
                f"{finding.control_id} cites line {e.line} as {e.raw!r} but "
                f"that line reads {actual!r}")
            checked += 1
    assert checked > 0, "expected line-anchored evidence on this device"


@asa_only
def test_the_evidence_table_is_headed_line_for_a_line_oriented_config():
    da = assess(ASA, redact=False, assessment_id="TEST-HDR")
    html = build_report(da, "TEST-HDR")
    assert 'style="width:10%">Line</th>' in html
    assert "Configuration line" in html


@sw_only
def test_every_evidence_row_carries_a_position(sw):
    """No evidence is printed without something to locate it by."""
    da, _html = sw
    for finding in da.assessment.findings:
        for e in finding.evidence:
            assert e.line is not None or e.record_id, (
                f"{finding.control_id}: evidence {e.raw[:40]!r} has neither a "
                "line number nor a record identifier")


@sw_only
def test_the_source_file_is_named_beside_the_evidence(sw):
    """Multi-device reports and bulk uploads make this necessary."""
    da, html = sw
    assert f'Source: <span class="mono">{da.identity.source_file}' in html


def test_derived_evidence_carries_the_line_of_the_rule_it_describes():
    """"Rule X is not evaluable" must say where rule X is.

    The reason is derived rather than quoted, but the rule it concerns sits on
    a real line. Without carrying it through, this finding reached the report
    with no position at all -- naming a problem rule and giving no way to find
    it.
    """
    import os
    sample = "samples/juniper/srx-display-xml.xml"
    if not os.path.exists(sample):
        pytest.skip("Juniper XML sample absent")

    da = assess(sample, redact=False, assessment_id="TEST-DERIVED")
    derived = [e for f in da.assessment.findings for e in f.evidence
               if "not evaluable" in e.raw]
    assert derived, "expected an unevaluable-rule finding on this sample"

    source = open(sample, encoding="utf-8", errors="replace").read().splitlines()
    for e in derived:
        assert e.line is not None, (
            f"derived evidence {e.raw[:50]!r} has no line number")
        # The cited line must be the rule it names, not an arbitrary one.
        rule_name = e.raw.split("rule ", 1)[1].split(" not evaluable", 1)[0]
        assert rule_name in source[e.line - 1], (
            f"cited line {e.line} reads {source[e.line - 1]!r}, which does not "
            f"name rule {rule_name!r}")


def test_no_evidence_anywhere_lacks_a_locator():
    """Across every configuration we hold, every line is findable."""
    import os
    for path in (r"E:\sonicwall config file.txt", r"E:\ASA.txt",
                 "samples/cisco/edge-rtr-01.cfg",
                 "samples/juniper/srx-display-xml.xml"):
        if not os.path.exists(path):
            continue
        da = assess(path, redact=False, assessment_id="TEST-LOC")
        if da.assessment is None:
            continue
        for f in da.assessment.findings:
            for e in f.evidence:
                assert e.line is not None or e.record_id, (
                    f"{os.path.basename(path)} :: {f.control_id} :: "
                    f"{e.raw[:50]!r} cannot be located")


@sw_only
def test_setting_positions_are_real_file_positions_not_object_indices():
    """`policyName_1` is at setting 37,290, not setting 1.

    The graph builder passed the OBJECT's index -- the 1 in `policyName_1` --
    as though it were the setting's position in the export. Setting 1 is
    `checksumVersion`. Every graph-derived finding on this platform therefore
    cited a position holding an unrelated value, and an administrator who
    followed the reference would have found the wrong thing and concluded the
    report was wrong.

    This reads every cited position back out of the file.
    """
    da = assess(SW, redact=False, assessment_id="TEST-POS")
    settings = open(SW, encoding="utf-8", errors="replace").read().split("&")

    checked = 0
    for finding in da.assessment.findings:
        for e in finding.evidence:
            rid = e.record_id or ""
            if not rid.startswith("setting["):
                continue
            n = int(rid[len("setting["):-1])
            assert 1 <= n <= len(settings), (
                f"{finding.control_id} cites setting {n}; the file holds "
                f"{len(settings)}")

            actual_key = settings[n - 1].split("=", 1)[0]
            # Derived evidence ("rule X not evaluable") is not a quoted line;
            # it points at the rule it concerns, which is still a real setting.
            if "not evaluable" in e.raw or "unresolved reference" in e.raw:
                assert actual_key, f"setting {n} is empty"
                continue

            cited_key = e.raw.split("=", 1)[0]
            assert cited_key == actual_key, (
                f"{finding.control_id} cites setting {n} as {cited_key!r} but "
                f"that position holds {actual_key!r}")
            checked += 1

    assert checked >= 10, "expected many position-anchored findings"


@sw_only
def test_a_single_line_export_shows_the_setting_number_not_a_column_of_ones(sw):
    """A column reading 1 for every finding distinguishes nothing.

    Line 1 is where all 92,636 settings genuinely are, so it is accurate --
    and useless. The setting number is unique per finding and can actually be
    retrieved, so that is what the report gives.
    """
    _da, html = sw
    assert ">Setting</th>" in html
    assert 'style="width:10%">Line</th>' not in html

    numbers = re.findall(r"<td class='num mono'>(\d+)</td>", html)
    assert len(numbers) > 10, "expected many evidence rows"
    assert len(set(numbers)) > len(numbers) // 2, (
        f"only {len(set(numbers))} distinct positions across {len(numbers)} "
        "rows -- the number is not identifying anything")


@sw_only
def test_the_report_states_how_to_retrieve_a_cited_setting(sw):
    """A position an administrator cannot act on is not a locator.

    The file has no newlines, so `sed -n 'Np'` alone does nothing. The report
    gives the command that does work.
    """
    _da, html = sw
    # The ampersand is HTML-escaped in the rendered command, so unescape
    # before matching -- otherwise this tests the encoding, not the content.
    import html as html_mod
    flat = _flat(html_mod.unescape(html))
    assert "one physical line" in flat
    assert "tr '&'" in flat and "sed -n" in flat


# ---------------------------------------------------------------------------
# Extended checks and ATT&CK in the report.
#
# They are added AFTER the method section, as an appendix, because none of
# them enters the score. The SonicWall figures asserted elsewhere in this file
# are the proof that adding them changed nothing already reported.
# ---------------------------------------------------------------------------

@sw_only
def test_extended_checks_are_an_appendix_outside_the_score(sw):
    da, html = sw
    flat = _flat(html)
    assert "Appendix A. Extended checks" in flat
    assert "not included in the score or the coverage stated in section 2" in flat
    cov = da.coverage()
    assert (cov["score_pct"], cov["assessed_pct"]) == (41.3, 68.7)
    for label in ("Known vulnerabilities", "IPsec VPN", "Wireless"):
        assert label in flat


@sw_only
def test_the_report_states_wlan_exposure_as_latent(sw):
    """No access point and no interface in WLAN: the paths are latent."""
    _da, html = sw
    flat = _flat(html)
    assert "Blast radius from untrusted zones" in flat
    assert "latent -- nothing is in the zone today" in flat


@sw_only
def test_attack_tags_appear_on_findings(sw):
    _da, html = sw
    assert "Adversary technique (MITRE ATT&amp;CK)" in html
    assert "T1602.001" in html


@sw_only
def test_extended_failures_cite_their_setting(sw):
    _da, html = sw
    flat = _flat(html)
    assert "ipsecPFSEnablePFS" in flat, "the PFS failure must quote its setting"
    assert "buildNum=" in flat, "CVE matches must cite the firmware setting"
