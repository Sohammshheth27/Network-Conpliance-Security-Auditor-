"""Semantic field matching: type prior x dense similarity x lexical.

Replaces ranking all 119 schema fields by name similarity alone. Three signals,
combined because they fail differently:

    type prior     from the VALUE. Cheap, and the strongest single constraint
                   -- 214 of 400 real settings are integers and only 8 fields
                   are integer-typed.
    dense          expanded setting name vs a natural-language DESCRIPTION of
                   each field. Handles `IdleVpnDpdInterval` -> "idle timeout",
                   which shares no tokens with anything.
    lexical        BM25 over real vendor lines we already map. Wins where a
                   setting name literally contains the command
                   (`ip http server`), which is where dense is weakest.

Embeddings are optional. Without a reachable embedding service this degrades
to type prior x lexical rather than failing -- an assessment must not depend on
a model server being up.
"""
from __future__ import annotations

import json
import urllib.request

import numpy as np

from .signals import expand, describe_fields, infer_type, type_multiplier

EMBED_URL = "http://localhost:11434/api/embed"
EMBED_MODEL = "nomic-embed-text"
RRF_K = 60


class SemanticMatcher:
    def __init__(self, fields=None, descriptions=None, lexical=None,
                 embed_fn=None):
        from ..schema.sbm import FIELD_TYPES

        self.field_types = dict(FIELD_TYPES)
        self.fields = list(fields or FIELD_TYPES)
        self.descriptions = descriptions or describe_fields()
        self.lexical = lexical                 # an NlpMatcher, or None
        self._embed = embed_fn or _ollama_embed
        self._mat = None
        # Query vectors are cached: the benchmark asks the same question once
        # per ablation arm, and an embedding round-trip costs ~0.5s. Without
        # this the ablation makes ~700 HTTP calls to answer 233 questions.
        self._qcache: dict = {}

    # ------------------------------------------------------------- indexing
    def fit(self):
        """Embed the field descriptions once."""
        try:
            self._mat = self._embed([self.descriptions.get(f, expand(f))
                                     for f in self.fields])
        except Exception:                              # noqa: BLE001
            self._mat = None                           # degrade, never fail
        return self

    def warm(self, queries) -> None:
        """Embed many queries in one round-trip. Batching is not an
        optimisation here so much as the difference between a benchmark that
        finishes and one that does not."""
        todo = [q for q in dict.fromkeys(queries) if q not in self._qcache]
        if not todo:
            return
        try:
            for q, vec in zip(todo, self._embed(todo)):
                self._qcache[q] = vec
        except Exception:                              # noqa: BLE001
            pass

    @property
    def dense_available(self) -> bool:
        return self._mat is not None

    # ------------------------------------------------------------- querying
    def match(self, name, value=None, *, k=5, context="",
              type_gate=True, use_dense=True, use_lexical=True):
        """Rank schema fields for one unknown vendor setting.

        Returns [(field, score, why)] best first.
        """
        vt = infer_type(value) if value is not None else "unknown"
        query = expand(name)
        if context:
            query = f"{query} {expand(context)}"
        if value is not None and vt in ("str", "ip"):
            # The value itself is evidence when it is a word rather than a
            # magnitude: `dh-group1-sha1` all but names its own field.
            query = f"{query} {str(value)[:60]}"

        # Each signal is separately switchable so an ablation can attribute
        # the gain. Without this the "dense" arm silently included lexical and
        # the measured improvement could not be assigned to either.
        scored = self._dense_scored(query) if use_dense else []
        dense = [f for f, _ in scored]
        sim_of = dict(scored)
        lex = self._lexical_ranks(query) if use_lexical else []

        fused: dict = {}
        for ranks in (dense, lex):
            for rank, f in enumerate(ranks, 1):
                fused[f] = fused.get(f, 0.0) + 1.0 / (RRF_K + rank)
        if not fused:
            return []

        # The MARGIN between the best and second-best similarity. On its own a
        # high cosine means little -- these field descriptions are all security
        # settings and sit close together in the space. What separates a real
        # match from a plausible one is how far clear of the runner-up it is.
        margin = 0.0
        if len(scored) >= 2:
            margin = scored[0][1] - scored[1][1]

        ranked = []
        for f, base in fused.items():
            mult = (type_multiplier(vt, self.field_types.get(f, "str"))
                    if type_gate else 1.0)
            why = f"type({vt})x{mult:.2f}"
            if f in dense[:10]:
                why += f" dense#{dense.index(f) + 1}"
            if f in lex[:10]:
                why += f" lex#{lex.index(f) + 1}"
            ranked.append((f, base * mult, why, sim_of.get(f, 0.0)))

        # RANKING is unchanged -- still the fused reciprocal rank times the
        # type prior, which is the arrangement the benchmark measured at 59.0%
        # top-1. Only the reported NUMBER changes, from a rank constant to a
        # confidence, so accuracy is preserved while the score becomes usable.
        ranked.sort(key=lambda t: -t[1])

        out = []
        for pos, (f, _fused_score, why, sim) in enumerate(ranked[:k]):
            conf = confidence(sim, margin if pos == 0 else 0.0,
                              type_multiplier(vt, self.field_types.get(f, "str"))
                              if type_gate else 1.0)
            out.append((f, conf, f"{why} sim={sim:.3f} margin={margin:.3f}"))
        return out

    # ------------------------------------------------------------ internals
    def _dense_ranks(self, query) -> list:
        return [f for f, _sim in self._dense_scored(query)]

    def _dense_scored(self, query) -> list:
        """(field, cosine similarity), best first.

        The similarity used to be computed here and discarded, leaving only the
        ordering. That is why every accepted suggestion scored an identical
        1.639: the reported number was the reciprocal-rank constant
        1/(RRF_K+1), which says "this came first" and nothing whatever about
        how sure the model is. A confident match and a wild guess were
        indistinguishable, so the queue could not be ranked by likelihood and
        no auto-accept threshold was possible.
        """
        if self._mat is None:
            return []
        q = self._qcache.get(query)
        if q is None:
            try:
                q = self._embed([query])[0]
            except Exception:                          # noqa: BLE001
                return []
            self._qcache[query] = q
        sims = self._mat @ q
        order = np.argsort(-sims)[:25]
        return [(self.fields[i], float(sims[i])) for i in order]

    def _lexical_ranks(self, query) -> list:
        if self.lexical is None:
            return []
        try:
            return [h.field for h in self.lexical.match(query, k=25)]
        except Exception:                              # noqa: BLE001
            return []


def _ollama_embed(texts, batch=32):
    vecs = []
    for i in range(0, len(texts), batch):
        req = urllib.request.Request(
            EMBED_URL,
            data=json.dumps({"model": EMBED_MODEL,
                             "input": [t[:600] for t in texts[i:i + batch]]}).encode(),
            headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=600) as r:
            vecs += json.load(r)["embeddings"]
    m = np.asarray(vecs, dtype=np.float32)
    return m / (np.linalg.norm(m, axis=1, keepdims=True) + 1e-9)


def confidence(similarity: float, margin: float, type_mult: float) -> float:
    """A number that means something, on 0-100.

    Three signals, and the middle one carries most of the weight:

      similarity  how close the setting name is to the field description. On
                  its own it is weak -- every SBM field describes a security
                  setting, so they cluster and even a poor match scores high.
      margin      how far clear of the runner-up. This is what separates "this
                  is the field" from "one of these six could be".
      type_mult   whether the observed VALUE could be that field's type. An
                  integer value cannot be a list-typed field, and this prior
                  alone was worth 12 points of top-1 accuracy in the benchmark.

    Deliberately NOT a probability. It is not calibrated against outcomes, and
    calling it one would invite an auto-approval threshold that nothing has
    earned. It is an ordering aid: higher means look at this one first.
    """
    sim = max(0.0, min(1.0, similarity))
    mar = max(0.0, min(1.0, margin * 4.0))     # margins are small; spread them
    base = 0.45 * sim + 0.55 * mar
    return round(100.0 * base * max(0.0, min(1.0, type_mult)), 1)
