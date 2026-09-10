"""LLM re-ranking: turn recall into precision.

Retrieval and ranking fail differently, and the benchmark shows exactly where
the gap is. On held-out vendors, hybrid+type retrieval reaches 64.8% top-5 but
only 45.5% top-1 -- so for roughly a fifth of settings the right field IS
retrieved and then ranked below something else. No amount of embedding tuning
recovers that: it is a comparison problem, not a search problem.

A bi-encoder scores a query against each candidate INDEPENDENTLY. It never sees
two candidates side by side, so it cannot reason "this is a timeout in minutes
and that one is in seconds, and the value is 15, so it is the first". A
cross-encoder can, and a small instruction model is a serviceable cross-encoder
when the candidate list is already short.

WHAT IS DIFFERENT FROM ASKING AN LLM TO PARSE
The model never sees the configuration file and never invents a field name. It
is handed ONE setting, its value, and at most ten candidates that retrieval
already selected, and it picks one or abstains. Three properties follow:

  * the field whitelist is a DECODER ENUM (guardrails.response_schema), so an
    off-list name is not merely rejected, it is ungeneratable;
  * `null` is always allowed, so "none of these" is a first-class answer rather
    than a forced guess;
  * a model failure returns no proposal, never a wrong one.

The output is still a PROPOSAL. Nothing here writes a pack or decides a
compliance verdict.
"""
from __future__ import annotations

import json
import urllib.request

from .signals import expand, infer_type

MODEL = "qwen3.5:4b"
HOST = "http://localhost:11434"

SYSTEM = (
    "You map one network-device configuration setting to a field in a "
    "vendor-neutral security schema.\n"
    "You are given the setting name, its value, and a numbered list of "
    "candidate fields with descriptions.\n"
    "Choose the ONE candidate that means the same thing as the setting.\n"
    "If none of them means the same thing, answer null. Answering null is "
    "correct and expected -- most device settings have no security field.\n"
    "Never invent a field name. Never explain. Answer only in the required "
    "JSON."
)


def _schema(fields):
    """Decoder-level constraint: the model can only emit a listed field or null."""
    return {
        "type": "object",
        "properties": {
            "field": {"type": ["string", "null"], "enum": list(fields) + [None]},
            "confidence": {"type": "number"},
            "because": {"type": "string"},
        },
        "required": ["field", "confidence"],
    }


def _prompt(name, value, candidates, descriptions, context="") -> str:
    vt = infer_type(value)
    lines = [
        f"SETTING NAME : {name}",
        f"EXPANDED     : {expand(name)}",
        f"VALUE        : {value!r}   (looks like type: {vt})",
    ]
    if context:
        lines.append(f"NEARBY       : {context[:200]}")
    lines.append("")
    lines.append("CANDIDATE FIELDS:")
    for i, f in enumerate(candidates, 1):
        d = (descriptions.get(f) or expand(f))[:150]
        lines.append(f"  {i}. {f}  --  {d}")
    lines.append("")
    lines.append("Which candidate means the same thing as this setting? "
                 "Answer null if none does.")
    return "\n".join(lines)


class LlmReranker:
    """Re-rank a short candidate list with a local instruction model."""

    def __init__(self, model=MODEL, host=HOST, timeout=60, descriptions=None):
        self.model, self.host, self.timeout = model, host, timeout
        if descriptions is None:
            from .signals import describe_fields
            descriptions = describe_fields()
        self.descriptions = descriptions
        self.available = None                      # probed lazily

    # ------------------------------------------------------------------ core
    def rerank(self, name, value, candidates, *, context="", top_k=10):
        """Return (field, confidence, reason). field is None when abstaining.

        `candidates` is the retrieval output, best first. The order is given to
        the model as-is: a cross-encoder that ignores a good retriever's
        ordering throws away information.
        """
        cands = list(candidates)[:top_k]
        if not cands:
            return None, 0.0, "no candidates to choose from"
        if len(cands) == 1:
            return cands[0], 0.5, "only one candidate"

        payload = {
            "model": self.model,
            "think": False,
            "stream": False,
            "format": _schema(cands),
            "options": {"temperature": 0, "num_predict": 120, "num_ctx": 4096},
            "messages": [
                {"role": "system", "content": SYSTEM},
                {"role": "user",
                 "content": _prompt(name, value, cands, self.descriptions, context)},
            ],
        }
        try:
            req = urllib.request.Request(
                f"{self.host}/api/chat",
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                body = json.loads(r.read().decode("utf-8"))
            out = json.loads(body["message"]["content"])
        except Exception as exc:                       # noqa: BLE001
            # A model failure must never become a mapping. Fall back to the
            # retriever's own top pick, clearly marked as un-reranked.
            self.available = False
            return cands[0], 0.0, f"reranker unavailable ({type(exc).__name__})"

        self.available = True
        field = out.get("field")
        if field is not None and field not in cands:
            # Should be impossible with the enum, but a schema is a contract
            # and contracts get violated by model updates.
            return None, 0.0, f"model returned an off-list field {field!r}"

        conf = float(out.get("confidence") or 0.0)
        conf = min(max(conf, 0.0), 1.0)
        return field, conf, (out.get("because") or "")[:200]





def needs_rerank(hits, *, margin=0.25) -> bool:
    """Is retrieval uncertain enough to be worth 13 seconds of a model?

    Measured: one re-rank costs ~12.8s on CPU. A device with 841 unknown
    settings would take three hours if every candidate were sent, which is not
    a tool anybody runs. It is also wasted: where the top hit beats the runner
    up by a wide margin, retrieval is usually right and the model only agrees
    expensively.

    So the model is spent on the ambiguous middle -- the cases where the answer
    is in the top five but not first, which is exactly the 19-point gap between
    top-1 and top-5 that the re-ranker exists to close.
    """
    if len(hits) < 2:
        return False
    top, second = hits[0][1], hits[1][1]
    if top <= 0:
        return True
    return (top - second) / top < margin


def rerank_queue(candidates, matcher, *, reranker=None, top_k=10,
                 min_confidence=0.0, only_uncertain=True, budget=None):
    """Apply retrieval then selective re-ranking across a training queue.

    ``budget`` caps how many model calls the whole queue may make, so a large
    device degrades to "the most ambiguous N were re-ranked" rather than
    running for hours. Which ones were spent on is recorded per candidate.
    """
    rr = reranker or LlmReranker()
    spent = 0
    for c in candidates:
        value = c.sample_values[0] if c.sample_values else None
        hits = matcher.match(c.name, value, k=top_k)
        if not hits:
            continue
        fields = [f for f, *_ in hits]

        if only_uncertain and not needs_rerank(hits):
            c.suggested_field = fields[0]
            c.suggestion_score = float(hits[0][1]) * 100
            c.suggested_from = "retrieval (confident; not re-ranked)"
            continue
        if budget is not None and spent >= budget:
            c.suggested_field = fields[0]
            c.suggestion_score = float(hits[0][1]) * 100
            c.suggested_from = "retrieval (re-rank budget exhausted)"
            continue

        spent += 1
        field, conf, why = rr.rerank(c.name, value, fields)
        if field is None:
            # An abstention is information: it says retrieval found nothing
            # that means the same thing, which is a coverage gap rather than a
            # low-confidence guess.
            c.suggested_field = None
            c.suggestion_score = 0.0
            c.suggested_from = f"reranker abstained: {why}"
            continue
        if conf < min_confidence:
            continue
        c.suggested_field = field
        c.suggestion_score = conf
        c.suggested_from = f"llm-rerank: {why}"
    return candidates
