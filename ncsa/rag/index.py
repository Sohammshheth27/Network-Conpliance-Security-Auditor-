"""Hybrid retrieval: BM25 + dense, fused by reciprocal rank.

Neither half is sufficient on its own here, and the failure modes are opposite:

  * BM25 alone nails `ip http server` -> the CIS Cisco audit text that contains
    that exact string, and is useless when the framework says "web-based
    administrative interface" and we say "http".
  * Dense alone handles that paraphrase and then cheerfully ranks every control
    containing the word "management" above the one that matters.

Reciprocal Rank Fusion is used rather than a weighted score blend because the
two scores are not on comparable scales -- BM25 is unbounded and corpus
dependent, cosine is [-1,1] -- and every attempt to normalise them into each
other reintroduces the tuning constant we were trying to avoid. RRF only reads
ranks, so it needs no calibration and cannot be broken by an outlier score.

The confidence floor from plan 5.3 lives here too: retrieval that cannot clear
it returns nothing rather than its best guess, and the caller escalates.
"""
from __future__ import annotations

from dataclasses import dataclass

import numpy as np

from ..frameworks.models import Framework, License
from .embed import EmbeddingCache

_RRF_K = 60          # standard RRF damping; ranks beyond ~60 stop mattering


@dataclass
class Hit:
    doc: object
    rrf: float
    bm25_rank: int | None
    dense_rank: int | None
    bm25_score: float | None = None
    dense_score: float | None = None
    also_in: list = None      # other benchmarks publishing the same item

    def explain(self) -> str:
        b = f"bm25#{self.bm25_rank}" if self.bm25_rank is not None else "bm25:-"
        d = f"dense#{self.dense_rank}" if self.dense_rank is not None else "dense:-"
        return f"{b} {d} rrf={self.rrf:.4f}"


def _tokens(s: str) -> list[str]:
    import re
    return re.findall(r"[a-z0-9][a-z0-9._-]*", s.lower())


class HybridIndex:
    def __init__(self, docs, *, cache_path="reference/.embed_cache.npz"):
        from rank_bm25 import BM25Okapi

        self.docs = list(docs)
        self._bm25 = BM25Okapi([_tokens(d.text) for d in self.docs])
        self._cache = EmbeddingCache(cache_path)
        self._mat: np.ndarray | None = None
        self._embedded: set = set()

    # ------------------------------------------------------------- building
    def embed_all(self, *, progress=None, only=None, truncate=1200) -> None:
        """Embed the corpus, or the subset ``only(doc)`` selects.

        Embedding every document is not automatically right. Measured on this
        machine, nomic-embed-text on CPU runs at 1.4 docs/sec on real 2,000-
        character framework text -- two hours for the full 9,838-document
        corpus. (An earlier 12/sec figure was measured on 45-character toy
        strings and was wrong by 16x.)

        That cost only buys something where lexical retrieval fails. CIS body
        text and STIG check text contain the literal vendor command, so BM25
        already ranks them correctly; NIST and ISO are abstract prose with no
        command to match, and are where every measured error occurred. So the
        default is to spend the compute there. Documents left un-embedded
        simply have no dense rank, and RRF already handles a missing rank.
        """
        idx = [i for i, d in enumerate(self.docs) if (only is None or only(d))]
        vecs = self._cache.encode([self.docs[i].text for i in idx],
                                  progress=progress, truncate=truncate)
        mat = np.zeros((len(self.docs), vecs.shape[1]), dtype=np.float32)
        mat[idx] = vecs
        self._mat = mat
        self._embedded = set(idx)
        self._cache.save()

    @property
    def embedded(self) -> bool:
        return self._mat is not None

    # ------------------------------------------------------------ querying
    def search(self, query: str, *, k=10, frameworks=None, platform=None,
               min_rrf=0.0, pool=60, dedupe=True) -> list[Hit]:
        """Retrieve. ``frameworks``/``platform`` filter BEFORE ranking."""
        keep = [
            i for i, d in enumerate(self.docs)
            if (frameworks is None or d.framework in frameworks)
            and (platform is None or d.platform is None
                 or _platform_match(d.platform, platform))
        ]
        if not keep:
            return []
        keep_set = set(keep)

        bm = self._bm25.get_scores(_tokens(query))
        bm_order = [i for i in np.argsort(-bm) if i in keep_set][:pool]
        bm_rank = {int(i): r for r, i in enumerate(bm_order, 1)}

        dn_rank, dn_score = {}, {}
        if self._mat is not None:
            q = self._cache.encode([query])[0]
            sims = self._mat @ q
            masked = np.full_like(sims, -np.inf)
            live = [i for i in keep if not self._embedded or i in self._embedded]
            masked[live] = sims[live]
            dn_order = np.argsort(-masked)[:pool]
            dn_rank = {int(i): r for r, i in enumerate(dn_order, 1)}
            dn_score = {int(i): float(sims[i]) for i in dn_order}

        fused: dict[int, float] = {}
        for i, r in bm_rank.items():
            fused[i] = fused.get(i, 0.0) + 1.0 / (_RRF_K + r)
        for i, r in dn_rank.items():
            fused[i] = fused.get(i, 0.0) + 1.0 / (_RRF_K + r)

        hits = [
            Hit(doc=self.docs[i], rrf=s, bm25_rank=bm_rank.get(i),
                dense_rank=dn_rank.get(i), bm25_score=float(bm[i]),
                dense_score=dn_score.get(i))
            for i, s in sorted(fused.items(), key=lambda kv: -kv[1])
            if s >= min_rrf
        ]
        if dedupe:
            hits = _collapse(hits)
        return hits[:k]


def _platform_match(doc_platform: str, want: str) -> bool:
    a, b = doc_platform.lower(), want.lower()
    return a in b or b in a


def _collapse(hits):
    """Collapse the same recommendation appearing in several benchmarks.

    CIS publishes "1.1.1 Ensure System Logging to a Remote Host" in a dozen
    vendor benchmarks. Un-collapsed, one such recommendation fills the entire
    top-k and hides every other control the field should map to. The survivor
    keeps the best rank and records the others in `also_in`, so a reviewer can
    still see the mapping holds across benchmarks.
    """
    seen: dict[tuple, Hit] = {}
    for h in hits:
        d = h.doc
        key = (d.framework, (d.title or d.text[:80]).lower(), d.control_id)
        first = seen.get(key)
        if first is None:
            seen[key] = h
            h.also_in = []
        else:
            first.also_in.append(d.source_document)
    return list(seen.values())
