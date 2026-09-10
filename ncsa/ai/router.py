"""12.7 -- the tier router.

    tier 0  exact regex from the mapping pack        1 ms    known vendors
    tier 1  mapping registry (previously approved)   1 ms    learned
    tier 2  NLP pipeline                            50 ms    unknown vendor,
                                                             familiar vocabulary
    tier 3  local Qwen + RAG                          5 s    genuinely novel
    tier 4  human approval                             --    below all thresholds

Realistic split on an unknown vendor: tier 2 resolves 70-80%, because vendors
reuse the same technical vocabulary. Thirty unknown lines is ~1.5 seconds
through tier 2 versus ~3 minutes through tier 3.

THE CONFIDENCE FLOOR (plan 10.2 #10) LIVES HERE, and it is the most important
thing in this file. The bench finding that motivated it: given a line whose
true field was absent from the enum, the model did not abstain -- it
confidently picked the nearest member and returned a plausible, wrong answer.
So a line that tier 2 cannot match ABOVE THRESHOLD does not reach tier 3 with
an open question; it reaches a human. Building the abstain path before the
happy path is the whole point.
"""
from __future__ import annotations

from dataclasses import dataclass

from ..nlp.matcher import Match, NlpMatcher
from .guardrails import Proposal, validate

# Below this, tier 2 declines to answer and the line escalates.
#
# CALIBRATED, not guessed. Measured on 9 unseen-vendor lines with known correct
# fields plus 5 lines with no correct field:
#     correct answers      score >= 0.52
#     wrong answers        score <= 0.30
#     no-correct-answer    score <= 0.57
# The distributions OVERLAP, so no threshold separates them perfectly. 0.60 sits
# above every wrong and every no-answer score, which means tier 2 never asserts
# a wrong field -- at the cost of escalating some correct lines it could have
# resolved. That trade is deliberate: escalation costs time, a wrong assertion
# costs a false PASS (plan 10.5).
NLP_ACCEPT = 0.60
# Below this, we do not even ask the model -- there is nothing useful to
# retrieve, so any answer would be a guess dressed as an inference.
NLP_ESCALATE_FLOOR = 0.20
# One-click Approve is disabled below this; the mapper must type the field
# name. Plan 10.2 #10 -- this is what kills rubber-stamping.
APPROVE_ONE_CLICK = 0.50


@dataclass
class Routed:
    proposal: Proposal
    tier: int
    needs_human: bool
    one_click_ok: bool
    candidates: list[Match]


class TierRouter:
    def __init__(self, matcher: NlpMatcher, registry=None, interpreter=None):
        self.matcher = matcher
        self.registry = registry
        self.interpreter = interpreter

    def route(self, line: str, *, lines=None, index: int = 0,
              quarantined: bool = False) -> Routed:
        # Guardrail 6 aftermath: a line flagged by the injection pre-scan never
        # reaches the model at all. Quarantine is not a warning, it is a gate.
        if quarantined:
            return Routed(
                Proposal(line=line, tier="quarantined",
                         rejected_reason="line quarantined by injection pre-scan"),
                tier=4, needs_human=True, one_click_ok=False, candidates=[],
            )

        # --- tier 1: previously approved --------------------------------------
        if self.registry is not None:
            known = self.registry.lookup(line)
            if known is not None:
                return Routed(known, tier=1, needs_human=False,
                              one_click_ok=True, candidates=[])

        # --- tier 2: NLP -------------------------------------------------------
        candidates = self.matcher.match(line, k=5)
        top = candidates[0] if candidates else None

        if top and top.score >= NLP_ACCEPT:
            from ..nlp.pipeline import extract_value
            p = Proposal(
                line=line, field=top.field,
                value=extract_value(line, top.example.as_type),
                evidence=line.strip(), confidence=round(top.score, 2), tier="nlp",
            )
            p = validate(p, line)
            if p.is_usable:
                return Routed(p, tier=2, needs_human=True,
                              one_click_ok=top.score >= APPROVE_ONE_CLICK,
                              candidates=candidates)

        # --- tier 3: the model, but only with usable retrieval ----------------
        if top and top.score >= NLP_ESCALATE_FLOOR and self.interpreter is not None:
            examples = [(c.example.line, c.field) for c in candidates[:5]]
            allowed = sorted({c.field for c in candidates}) or None
            p = self.interpreter.interpret(
                line, lines=lines, index=index, examples=examples,
                allowed_fields=allowed,
            )
            if p.is_usable:
                # An unapproved model suggestion carries no confidence and no
                # risk score (plan 7.3). It exists only to be approved.
                return Routed(p, tier=3, needs_human=True,
                              one_click_ok=False, candidates=candidates)
            return Routed(p, tier=4, needs_human=True,
                          one_click_ok=False, candidates=candidates)

        # --- tier 4: human --------------------------------------------------
        reason = (
            "no retrieval above the confidence floor -- asking the model would "
            "produce a guess, not an inference"
        )
        return Routed(
            Proposal(line=line, tier="human", rejected_reason=reason),
            tier=4, needs_human=True, one_click_ok=False, candidates=candidates,
        )
