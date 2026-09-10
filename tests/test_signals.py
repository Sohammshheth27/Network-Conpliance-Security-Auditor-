"""Type inference, abbreviation expansion, and the type prior.

The type prior is the single biggest measured gain in field matching (+15.5
points of top-1 on held-out vendors), and it is also the most dangerous piece:
a wrong type SUPPRESSES the correct field. These tests pin both the gain and
the safety property that makes it survivable.
"""
import pytest

from ncsa.nlp.signals import (ABBREV, TYPE_PRIOR, describe_fields, expand,
                              humanise, infer_type, type_multiplier)
from ncsa.schema.sbm import FIELD_TYPES


# ---------------------------------------------------------- type inference
@pytest.mark.parametrize("value,expected", [
    ("on", "bool"), ("off", "bool"), ("enabled", "bool"), ("false", "bool"),
    (True, "bool"), (0, "bool"), (1, "bool"),
    ("15", "int"), ("14400", "int"), (300, "int"),
    ("192.168.1.1", "ip"),
    ("a,b,c", "list"), (["x", "y"], "list"),
    ("dh-group1-sha1", "str"), ("NSA 3700", "str"),
    ("", "unknown"),
])
def test_value_types(value, expected):
    assert infer_type(value) == expected


def test_zero_and_one_are_flags_not_quantities():
    """`1` and `0` are far more often a flag than a magnitude in a device
    config. Typing them as integers would push every flag into the 8-field
    integer space and suppress the correct boolean field."""
    assert infer_type("1") == "bool"
    assert infer_type("0") == "bool"
    assert infer_type("2") == "int"


# ------------------------------------------------------------- expansion
def test_camel_case_is_split():
    assert humanise("IdleVpnDpdInterval") == "Idle Vpn Dpd Interval"
    assert humanise("allowHttpMgmt") == "allow Http Mgmt"


def test_domain_abbreviations_are_spelled_out():
    """`Dpd` and "dead peer detection" share no tokens, so neither lexical nor
    dense matching can connect them until one side is expanded."""
    out = expand("IdleVpnDpdInterval").lower()
    assert "dead peer detection" in out
    assert "virtual private network" in out
    assert expand("allowHttpMgmt").lower().endswith("management")


def test_expansion_leaves_unknown_words_alone():
    assert "Marcraft" in expand("MarcraftSetting")


# ------------------------------------------------------------- type prior
def test_exact_type_match_is_unpenalised():
    for t in ("bool", "int", "str", "list"):
        assert type_multiplier(t, t) == 1.0


def test_mismatch_is_damped_but_never_zero():
    """THE safety property. A hard filter that is wrong removes the correct
    answer with no way back: `7` might be an int field or a version STRING.
    Every multiplier must stay above zero so a mismatch is recoverable."""
    for vt, row in TYPE_PRIOR.items():
        for ft, mult in row.items():
            assert mult > 0.0, f"{vt}->{ft} would make a field unreachable"


def test_unknown_value_type_biases_nothing():
    for ft in ("bool", "int", "str", "list"):
        assert type_multiplier("unknown", ft) == 1.0


def test_int_prior_prefers_int_fields_strongly():
    """Only 8 of 119 fields are int-typed; that is the whole leverage."""
    assert type_multiplier("int", "int") > 4 * type_multiplier("int", "bool")


def test_type_pruning_is_worth_having():
    """Sanity-check the premise: int-typed fields really are a small slice."""
    ints = sum(1 for t in FIELD_TYPES.values() if t == "int")
    assert ints / len(FIELD_TYPES) < 0.15


# ------------------------------------------------------------ descriptions
def test_every_field_gets_a_description():
    d = describe_fields()
    assert set(d) == set(FIELD_TYPES)
    assert all(v.strip() for v in d.values())


def test_descriptions_use_control_prose_where_it_exists():
    """The asymmetry that makes dense retrieval work: a vendor writes an
    identifier, a framework writes a sentence."""
    d = describe_fields()
    http = d["management.http.enabled"].lower()
    assert "http" in http
    assert len(http) > len("management http enabled") + 10


# ------------------------------------------------------------- re-ranker
from ncsa.nlp.rerank import LlmReranker, needs_rerank, _prompt, _schema


def test_schema_makes_off_list_fields_ungeneratable():
    """Not 'rejected afterwards' -- the decoder cannot emit them at all."""
    s = _schema(["a.b", "c.d"])
    enum = s["properties"]["field"]["enum"]
    assert "a.b" in enum and "c.d" in enum
    assert None in enum, "abstaining must be a first-class answer"
    assert "management.http.enabled" not in enum


def test_prompt_carries_the_value_and_its_type():
    """The value is the strongest signal we have; a re-ranker that only sees
    the name is doing the same weak job as the retriever."""
    p = _prompt("IdleVpnDpdInterval", "15", ["a.b"], {"a.b": "desc"})
    assert "15" in p
    assert "int" in p
    assert "dead peer detection" in p.lower()     # expansion reaches the model


def test_model_failure_never_becomes_a_mapping():
    """A dead model must degrade to the retriever's pick, clearly marked --
    never to a confident wrong answer."""
    rr = LlmReranker(host="http://127.0.0.1:9", timeout=1)
    field, conf, why = rr.rerank("x", "1", ["a.b", "c.d"])
    assert field == "a.b"          # retriever's own top pick
    assert conf == 0.0             # carries no confidence of its own
    assert "unavailable" in why


def test_single_candidate_is_not_sent_to_the_model():
    rr = LlmReranker(host="http://127.0.0.1:9", timeout=1)
    field, conf, why = rr.rerank("x", "1", ["only.one"])
    assert field == "only.one" and "only one" in why


def test_confident_retrieval_skips_the_model():
    """One re-rank costs ~12.8s; 841 unknown settings would be three hours."""
    clear = [("a.b", 1.0, ""), ("c.d", 0.2, "")]
    close = [("a.b", 1.0, ""), ("c.d", 0.95, "")]
    assert not needs_rerank(clear)
    assert needs_rerank(close)


def test_no_candidates_means_no_call_and_no_answer():
    rr = LlmReranker(host="http://127.0.0.1:9", timeout=1)
    assert rr.rerank("x", "1", [])[0] is None
