"""The suggester's confidence must mean something.

THE BUG THIS EXISTS TO PREVENT
------------------------------
Every accepted suggestion used to score exactly 1.639, on every setting, on
every device. That number is 100 x 1/(RRF_K+1) -- the reciprocal-rank constant
for a first-place finish. It said "this came first" and nothing about whether
the match was any good, so:

  * the queue could not be ordered by likelihood;
  * no threshold could separate "probably right" from "needs a human";
  * a perfect match and a wild guess were indistinguishable.

The similarity was being computed and thrown away one function below.

WHAT CONFIDENCE IS AND IS NOT
-----------------------------
Measured on 378 held-out labelled pairs (tools/eval_confidence.py):

    confidence   n     precision
      80-100     6       100.0%
      60-79     41        87.8%
      40-59    131        82.4%
      20-39    198        55.6%

Monotonic, and useful for ordering. NOT a probability, and explicitly not an
auto-approval licence: on the real SonicWall queue `natPolicyEnabled` is
proposed as `l2.ip_source_guard` at 80.7, which is simply wrong. High
confidence narrows the reviewer's work; it does not replace the reviewer.
"""
import os

import pytest

from ncsa.nlp.semantic import SemanticMatcher, confidence
from ncsa.pipeline import assess
from ncsa.training.queue import build_queue

SW = r"E:\sonicwall config file.txt"
sw_only = pytest.mark.skipif(not os.path.exists(SW), reason="SonicWall sample absent")


@pytest.fixture(scope="module")
def queue():
    """Built ONCE. Suggesting for 400 settings means 400 embedding lookups on a
    2.7 MB export; doing that per test made this file take minutes.

    Skips when the embedding service is unreachable. The matcher degrades to
    type-prior x lexical in that case, which is deliberate -- an assessment
    must never depend on a model server being up -- but the degraded arm
    produces far fewer distinct confidences, so the spread assertions below
    would fail for a reason that has nothing to do with the code under test.
    """
    if not SemanticMatcher(lexical=None).fit().dense_available:
        pytest.skip("embedding service unreachable; dense arm unavailable")
    r = assess(SW, redact=False, assessment_id="conf")
    return build_queue(r, with_suggestions=True, limit=400)


def test_confidence_rises_with_similarity_and_margin():
    """The two signals must both move the number, in the right direction."""
    assert confidence(0.9, 0.10, 1.0) > confidence(0.5, 0.10, 1.0)
    assert confidence(0.9, 0.20, 1.0) > confidence(0.9, 0.02, 1.0)


def test_a_type_mismatch_collapses_confidence():
    """An integer value cannot be a list-typed field.

    The type prior is worth 12 points of top-1 accuracy on its own, and a zero
    multiplier has to mean zero -- not merely 'a bit less'.
    """
    assert confidence(0.95, 0.30, 0.0) == 0.0


def test_confidence_stays_in_range():
    for sim in (-1.0, 0.0, 0.5, 1.0, 2.0):
        for margin in (-1.0, 0.0, 0.5, 5.0):
            c = confidence(sim, margin, 1.0)
            assert 0.0 <= c <= 100.0, f"out of range: {c}"


@sw_only
def test_the_queue_no_longer_reports_one_constant_score(queue):
    """The regression, stated as a number.

    227 distinct confidences across 400 queued settings, where there used to be
    exactly one. If this collapses back toward 1, the rank constant has
    returned and the queue is unorderable again.
    """
    scored = [c for c in queue if c.suggested_field]
    assert len(scored) > 50, "expected a populated queue"

    distinct = {round(c.suggestion_score, 1) for c in scored}
    assert len(distinct) > 20, (
        f"only {len(distinct)} distinct confidence value(s) across "
        f"{len(scored)} suggestions -- the score has collapsed to a rank "
        "constant again")


@sw_only
def test_confidence_is_on_a_zero_to_one_hundred_scale(queue):
    """The x100 that suited the old rank constant would put this in the thousands."""
    for c in queue:
        if c.suggested_field:
            assert 0.0 <= c.suggestion_score <= 100.0, (
                f"{c.name}: confidence {c.suggestion_score} is off-scale")


@sw_only
def test_the_queue_is_ordered_by_confidence_first(queue):
    """The point of the number: the most likely proposals come first."""
    scores = [c.suggestion_score for c in queue]
    assert scores == sorted(scores, reverse=True), (
        "the queue must lead with its most confident proposals")


def test_match_reports_the_similarity_it_used():
    """`why` has to show the working.

    A reviewer accepting a proposal is accepting OUR reasoning; the similarity
    and margin that produced it belong on the record.
    """
    sem = SemanticMatcher(lexical=None).fit()
    if not sem.dense_available:
        pytest.skip("embedding service unreachable")
    hits = sem.match("adminLoginTimeout", "10", k=3, use_lexical=False)
    assert hits
    _field, conf, why = hits[0]
    assert "sim=" in why and "margin=" in why
    assert 0.0 <= conf <= 100.0
