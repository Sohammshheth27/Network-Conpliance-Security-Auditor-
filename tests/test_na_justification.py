"""Every NOT_APPLICABLE must be justified, and must be a claim someone made.

WHY THIS IS THE STRICTEST INVARIANT IN THE ENGINE
-------------------------------------------------
UNKNOWN and NOT_APPLICABLE are not symmetric, and the asymmetry runs the wrong
way for anyone tempted to tidy the numbers:

    UNKNOWN stays in the denominator. It depresses assessed coverage and is
    visible on the report.

    NOT_APPLICABLE is excluded from scoring entirely. A wrong one silently
    RAISES the score, because it removes a hard control from the denominator.

So a false N/A is worse than a false UNKNOWN, and inflating N/A is the easiest
way to make this tool lie. Measured before this was fixed: 242 of 269 N/A
verdicts across 11 real configs came from `supported_domains` -- a list whose
actual meaning is "domains this pack models" -- with no justification recorded
anywhere. Several were plainly false, most memorably cisco.yaml declaring
IOS-XE to have no `l2` capability, on the platform that invented DHCP snooping
and dynamic ARP inspection.

A domain the pack does not model is a gap in US. It is UNKNOWN.
A domain the platform does not have is a fact about the DEVICE. It is N/A, and
the pack author has to say so and say why.
"""
import os

import pytest
import yaml

from ncsa.corpus.golden import _default_samples
from ncsa.pipeline import assess, load_packs

PACK_FILES = sorted(
    os.path.join("packs", n) for n in os.listdir("packs") if n.endswith(".yaml")
)

SAMPLES = [s for s in list(_default_samples()) +
           [r"E:\sonicwall config file.txt", r"E:\ASA.txt"] if os.path.exists(s)]


@pytest.mark.parametrize("path", PACK_FILES)
def test_every_declared_domain_exclusion_states_a_reason(path):
    """`not_applicable_domains` is a claim about the platform. Claims need reasons."""
    doc = yaml.safe_load(open(path, encoding="utf-8"))
    if not isinstance(doc, dict):
        pytest.skip("not a pack")
    for domain, reason in (doc.get("not_applicable_domains") or {}).items():
        assert isinstance(reason, str) and len(reason.strip()) > 15, (
            f"{os.path.basename(path)}: domain {domain!r} is excluded with no "
            f"usable reason. An auditor asked to accept an exclusion needs to "
            f"know why.")


@pytest.mark.parametrize("path", PACK_FILES)
def test_every_declared_field_exclusion_states_a_reason(path):
    doc = yaml.safe_load(open(path, encoding="utf-8"))
    if not isinstance(doc, dict):
        pytest.skip("not a pack")
    naf = doc.get("not_applicable_fields")
    if not naf:
        return
    assert isinstance(naf, dict), (
        f"{os.path.basename(path)}: not_applicable_fields must be a "
        "{field: reason} mapping so each exclusion carries its justification")
    for field, reason in naf.items():
        assert isinstance(reason, str) and len(reason.strip()) > 10, (
            f"{os.path.basename(path)}: field {field!r} excluded with no reason")


def test_no_pack_claims_a_capability_gap_it_has_not_declared():
    """A domain missing from `supported_domains` must NOT become N/A by itself.

    This is the regression that matters: the old behaviour inferred a platform
    capability claim from a coverage list, and that inference is what produced
    242 unjustified verdicts.
    """
    for pack in load_packs():
        declared = set(getattr(pack, "not_applicable_domains", {}) or {})
        modelled = set(pack.supported_domains or [])
        # A domain may be BOTH unmodelled and genuinely absent, but a pack must
        # never declare a domain absent while also claiming to model it -- that
        # is a contradiction, and it silently wins as N/A.
        overlap = declared & modelled
        assert not overlap, (
            f"{pack.platform}: {sorted(overlap)} declared not-applicable while "
            "also listed as modelled")


@pytest.mark.skipif(not SAMPLES, reason="no sample configs available")
def test_every_not_applicable_finding_carries_a_justification():
    """The end-to-end invariant, over every vendor we can assess.

    Not a spot check: this walks all available real configs and fails on the
    first N/A that cannot say why it is not applicable.
    """
    unjustified = []
    for path in SAMPLES:
        try:
            r = assess(path, redact=True, assessment_id="na-check")
        except Exception:                                  # noqa: BLE001
            continue
        if r.assessment is None:
            continue
        for f in r.assessment.findings:
            if f.state.value != "NOT_APPLICABLE":
                continue
            # Justified means the reason states a WHY, or points at the
            # observation that disabled the feature.
            if not (f.evidence or ": " in f.reason):
                unjustified.append(
                    f"{os.path.basename(path)} :: {f.field} :: {f.reason}")

    assert not unjustified, (
        f"{len(unjustified)} NOT_APPLICABLE verdict(s) with no justification. "
        "N/A is excluded from scoring, so an unjustified one silently raises "
        "the score:\n  " + "\n  ".join(unjustified[:10]))


@pytest.mark.skipif(not SAMPLES, reason="no sample configs available")
def test_unmodelled_domains_surface_as_unknown_not_as_not_applicable():
    """Cisco IOS-XE must not be reported as having no layer-2 capability.

    The pack does not model `l2`, which is a gap in our coverage. The platform
    invented DHCP snooping and dynamic ARP inspection, so the honest verdict is
    UNKNOWN -- and UNKNOWN keeps the control in the denominator.
    """
    cisco = [s for s in SAMPLES if "cisco" in s and s.endswith(".cfg")]
    if not cisco:
        pytest.skip("no Cisco sample")
    r = assess(cisco[0], redact=True, assessment_id="cisco-l2")
    l2 = [f for f in r.assessment.findings if f.field.startswith("l2.")]
    assert l2, "the l2 controls should still be evaluated"
    assert not any(f.state.value == "NOT_APPLICABLE" for f in l2), (
        "an unmodelled domain must not be reported as a platform capability "
        f"gap: {[(f.field, f.state.value) for f in l2]}")

    # In fact cisco.yaml has mapped all three l2 fields since it was written --
    # `supported_domains` was overriding working mappings. A router running
    # neither DHCP snooping, dynamic ARP inspection nor IP source guard now
    # FAILS these controls, which is the correct hardening verdict and was
    # previously reported as "not applicable".
    assert all(f.state.value == "FAIL" for f in l2), (
        f"expected real verdicts, got {[(f.field, f.state.value) for f in l2]}")
