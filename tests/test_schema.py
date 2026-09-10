"""Schema contract tests.

The schema is agreed on Day 1 and then treated as fixed (plan 17.1), so these
tests exist to catch a change that would silently break another track.
"""
import pytest
from pydantic import ValidationError

from ncsa.schema import (
    EvidenceRef,
    FIELD_NAMES,
    FIELD_TYPES,
    Observation,
    ObservationSource,
    ObservationState,
    RecordState,
    ResultState,
    SecurityBaselineModel,
    Severity,
    SourceAccounting,
    normalise,
)


def ev(raw="ip ssh version 2", line=42, file="cisco.cfg"):
    return EvidenceRef(file=file, line=line, raw=raw)


# --------------------------------------------------------------- Observation
class TestObservation:
    def test_observed_requires_evidence(self):
        """Plan 14.3: a finding with no evidence is not a finding."""
        with pytest.raises(ValidationError):
            Observation(
                value=2,
                state=ObservationState.OBSERVED,
                source=ObservationSource.PARSER,
                confidence=1.0,
                evidence=[],
            )

    def test_default_assumed_rejects_evidence(self):
        """A default was never seen, so it cannot cite a source line."""
        with pytest.raises(ValidationError):
            Observation(
                value=True,
                state=ObservationState.DEFAULT_ASSUMED,
                source=ObservationSource.MAPPING_REGISTRY,
                confidence=1.0,
                evidence=[ev()],
            )

    def test_the_distinction_that_matters(self):
        """Plan 2.3 -- the reason Observation exists at all.

        Two observations with the SAME value, only one of which can support
        a FAIL. Collapsing these is how a toy compliance tool is built.
        """
        disabled = Observation.observed(
            False, [ev("no ip http server", 10)], field_path="management.http.enabled"
        )
        never_seen = Observation.not_observed(field_path="management.http.enabled")

        assert disabled.value is False
        assert never_seen.value is None
        assert disabled.is_provable
        assert not never_seen.is_provable

    def test_confidence_is_derived_not_supplied(self):
        """Plan 7.3 -- an approved AI mapping is permanently 0.9, not 1.0."""
        parsed = Observation.observed(2, [ev()])
        approved = Observation.observed(
            2, [ev()], source=ObservationSource.LLM_APPROVED
        )
        assert parsed.confidence == 1.0
        assert approved.confidence == 0.9

    def test_frozen(self):
        obs = Observation.observed(2, [ev()])
        with pytest.raises(ValidationError):
            obs.value = 1


# ------------------------------------------------------------------ Evidence
class TestEvidence:
    def test_anchoring_accepts_real_quote(self):
        """Plan 10.1 defence 4 -- evidence anchoring."""
        source = "line vty 0 4\n transport input ssh\n"
        assert EvidenceRef(file="c.cfg", line=2, raw="transport input ssh").anchors_in(source)

    def test_anchoring_rejects_invented_quote(self):
        """An AI that invents a quotation must be caught here."""
        source = "line vty 0 4\n transport input ssh\n"
        assert not EvidenceRef(file="c.cfg", line=2, raw="ip ssh version 2").anchors_in(source)

    def test_raw_cannot_be_empty(self):
        with pytest.raises(ValidationError):
            EvidenceRef(file="c.cfg", line=1, raw="   ")


# --------------------------------------------------------------- normalise
class TestNormalise:
    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("2", 2),            # Cisco   : ip ssh version 2
            ("v2", 2),           # Juniper : protocol-version v2
            ("version 2", 2),    # prose form
            (2, 2),              # SONiC   : already an int
            ("  2 ", 2),
            ("vty", None),       # must NOT strip the v from a word
            ("", None),
            (None, None),
        ],
    )
    def test_ssh_version_across_vendors(self, raw, expected):
        """The bench failure this module exists for.

        qwen3.5:4b returned "v2" for the Juniper line -- the correct reading.
        Without this, type validation would discard a right answer.
        """
        assert normalise(raw, "int") == expected

    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("enable", True), ("disable", False),
            ("no", False), ("yes", True),
            ("permit", True), ("deny", False),
            (True, True), (False, False),
            ("banana", None),   # ambiguous -> None -> caller records UNKNOWN
        ],
    )
    def test_bool_tokens(self, raw, expected):
        assert normalise(raw, "bool") == expected

    def test_bool_is_not_an_int(self):
        """bool subclasses int in Python; ssh.version must not accept True."""
        assert normalise(True, "int") is None

    def test_unknown_type_is_a_programming_error(self):
        with pytest.raises(ValueError):
            normalise("x", "float")


# --------------------------------------------------------------------- enums
class TestEnums:
    def test_seven_result_states_despite_the_heading(self):
        """Plan 6.5 is headed 'six' but lists seven. Seven is correct."""
        assert len(ResultState) == 7
        assert ResultState.PARTIAL in ResultState
        assert ResultState.ERROR in ResultState

    def test_only_pass_fail_partial_score(self):
        """Plan 6.7 -- NA/MANUAL/UNKNOWN/ERROR leave the denominator alone."""
        scoring = {s for s in ResultState if s.counts_toward_score}
        assert scoring == {ResultState.PASS, ResultState.FAIL, ResultState.PARTIAL}

    def test_fail_and_partial_need_evidence(self):
        """Plan 14.3."""
        assert ResultState.FAIL.needs_evidence
        assert ResultState.PARTIAL.needs_evidence
        assert not ResultState.PASS.needs_evidence

    def test_severity_weights(self):
        """Plan 6.7 weighting."""
        assert Severity.CRITICAL.weight == 10
        assert Severity.HIGH.weight == 6
        assert Severity.MEDIUM.weight == 3
        assert Severity.LOW.weight == 1

    def test_stig_cat_one_is_high(self):
        """v1.4 6.4 caveat: severity comes from the rule, not from a guess.

        V-215844 (the real SSH rule) is CAT I -- the plan previously assumed
        CAT II for it.
        """
        assert Severity.from_stig_cat("I") is Severity.HIGH
        assert Severity.from_xccdf("high") is Severity.HIGH


# ----------------------------------------------------------------------- SBM
class TestSBM:
    def sbm(self):
        return SecurityBaselineModel(
            assessment_id="a-1", source_file="cisco.cfg", source_sha256="deadbeef"
        )

    def test_rejects_unknown_field(self):
        """A typo in a vendor pack must fail loudly, not create a dead field."""
        s = self.sbm()
        with pytest.raises(KeyError):
            s.set("management.ssh.verison", Observation.observed(2, [ev()]))

    def test_scoped_vty_paths_accepted(self):
        """Plan 2.3.1: vty is scoped; con and vty must not collide."""
        s = self.sbm()
        s.set(
            "management.vty[0-4].transport_input",
            Observation.observed(["ssh"], [ev("transport input ssh", 88)]),
        )
        assert s.value("management.vty[0-4].transport_input") == ["ssh"]
        assert len(s.scoped("management.vty")) == 1

    def test_value_ignores_unknown_states(self):
        s = self.sbm()
        s.set("management.telnet.enabled", Observation.not_observed())
        assert s.value("management.telnet.enabled", default="?") == "?"

    def test_field_enum_is_stable_and_sorted(self):
        """FIELD_NAMES is handed to the model as a JSON-schema enum."""
        assert FIELD_NAMES == sorted(FIELD_TYPES)
        assert "management.ssh.version" in FIELD_NAMES
        assert all(t in ("bool", "int", "str", "list") for t in FIELD_TYPES.values())


# ---------------------------------------------------------- source accounting
class TestSourceAccounting:
    def test_no_silent_loss(self):
        """Plan 14.1 -- TOTAL == PARSED + MAPPED + QUARANTINED + UNKNOWN."""
        acc = SourceAccounting(total=1412)
        acc.record(RecordState.PARSED, 950)
        acc.record(RecordState.MAPPED, 340)
        acc.record(RecordState.QUARANTINED, 14)
        acc.record(RecordState.UNKNOWN, 108)
        assert acc.balances
        assert round(acc.coverage_pct, 1) == 91.4

    def test_imbalance_is_detectable(self):
        """If 110 lines vanish, the report must be able to say so."""
        acc = SourceAccounting(total=1412)
        acc.record(RecordState.PARSED, 1290)
        assert not acc.balances
