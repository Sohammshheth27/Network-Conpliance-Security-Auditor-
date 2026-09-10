"""Governance KB -- retrievable AI-security knowledge, structurally isolated.

WHY THIS IS A SEPARATE INDEX
----------------------------
The MITRE ATLAS entry for prompt injection *contains prompt injection examples*
-- strings like "ignore previous instructions" appear in it, because that is
what the technique looks like.

If ATLAS text shared a corpus with our config-line examples, a config line
mentioning those words would retrieve the ATLAS page as a "similar example",
and we would paste an attack into our own model's prompt. No attacker needed;
and an attacker who knows we index ATLAS can craft a config line to trigger it
deliberately.

So there are two corpora and they never touch:

  Parser corpus (knowledge/examples.jsonl)   Governance KB (this module)
  ----------------------------------------   ---------------------------
  real config lines -> SBM field             ATLAS / AI RMF / OWASP
  "what field does this line set?"           "which technique does X defend?"
  feeds the MODEL PROMPT at scan time        feeds REPORTS at write-up time
  sees attacker-influenced data              never sees attacker data

Plan 13.1 already demands Parser RAG and Security RAG stay separate. This is a
third corpus, isolated from both, and :func:`assert_not_parser_corpus` exists so
a future refactor cannot quietly merge them.

Retrieval is TF-IDF (plan 12.5), not embeddings: this corpus is small, the
queries are keyword-shaped ("prompt injection", "poisoning"), and it keeps the
governance path free of any dependency on the local model.
"""
from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel, Field

from ..frameworks.ai_security import GUARDRAIL_COVERAGE, AiSecurityKB

# Any corpus carrying this marker must never reach prompt construction.
CORPUS_TAG = "governance"


class GovernanceDoc(BaseModel):
    model_config = {"frozen": True}

    doc_id: str
    source: str                    # "MITRE ATLAS" | "NIST AI RMF" | "OWASP LLM"
    title: str
    text: str
    kind: str                      # technique | mitigation | function | guardrail
    corpus: str = CORPUS_TAG       # tripwire -- see assert_not_parser_corpus


class GovernanceKB:
    """Searchable AI-security knowledge for reports, decks and audits."""

    def __init__(self, docs: list[GovernanceDoc]):
        self.docs = docs
        self._vec = None
        self._matrix = None

    # -------------------------------------------------------------- building
    @classmethod
    def build(cls, ai_kb: AiSecurityKB) -> "GovernanceKB":
        docs: list[GovernanceDoc] = []

        for t in ai_kb.techniques.values():
            docs.append(
                GovernanceDoc(
                    doc_id=t.id,
                    source="MITRE ATLAS",
                    title=t.name,
                    text=f"{t.name}. {t.description}",
                    kind="technique",
                )
            )
        for m in ai_kb.mitigations.values():
            docs.append(
                GovernanceDoc(
                    doc_id=m.id,
                    source="MITRE ATLAS",
                    title=m.name,
                    text=f"{m.name}. {m.description}",
                    kind="mitigation",
                )
            )
        for fn, desc in ai_kb.ai_rmf_functions.items():
            docs.append(
                GovernanceDoc(
                    doc_id=f"AIRMF.{fn}",
                    source="NIST AI RMF 100-1",
                    title=fn,
                    text=f"{fn}: {desc}",
                    kind="function",
                )
            )
        for i, g in enumerate(GUARDRAIL_COVERAGE):
            docs.append(
                GovernanceDoc(
                    doc_id=f"NCSA.GUARD.{i:02d}",
                    source="NCSA guardrails",
                    title=g["guardrail"],
                    text=(
                        f"{g['guardrail']} defends against "
                        f"{', '.join(g['atlas']) or 'no specific ATLAS technique'}; "
                        f"OWASP {g['owasp_llm']}; AI RMF {g['ai_rmf']}."
                    ),
                    kind="guardrail",
                )
            )
        return cls(docs)

    # ------------------------------------------------------------- retrieval
    def _ensure_index(self) -> None:
        if self._matrix is not None:
            return
        from sklearn.feature_extraction.text import TfidfVectorizer

        self._vec = TfidfVectorizer(analyzer="word", ngram_range=(1, 2), stop_words="english")
        self._matrix = self._vec.fit_transform([d.text for d in self.docs])

    def search(self, query: str, k: int = 5) -> list[tuple[GovernanceDoc, float]]:
        """Retrieve governance knowledge. Never call this while building a
        prompt that will also contain configuration text."""
        self._ensure_index()
        from sklearn.metrics.pairwise import cosine_similarity

        q = self._vec.transform([query])
        scores = cosine_similarity(q, self._matrix)[0]
        order = scores.argsort()[::-1][:k]
        return [(self.docs[i], float(scores[i])) for i in order if scores[i] > 0]

    # --------------------------------------------------------------- outputs
    def coverage_matrix(self) -> str:
        """Plan 10.4 -- our guardrails down the side, frameworks across the top."""
        rows = ["GUARDRAIL COVERAGE (plan 10.4)", ""]
        rows.append(f"{'Guardrail':<42}{'ATLAS':<44}{'OWASP LLM':<34}{'AI RMF'}")
        rows.append("-" * 130)
        for g in GUARDRAIL_COVERAGE:
            atlas = ", ".join(g["atlas"]) or "--"
            rows.append(f"{g['guardrail']:<42}{atlas:<44}{g['owasp_llm']:<34}{g['ai_rmf']}")
        rows.append("-" * 130)
        by_fn: dict[str, int] = {}
        for g in GUARDRAIL_COVERAGE:
            by_fn[g["ai_rmf"]] = by_fn.get(g["ai_rmf"], 0) + 1
        rows.append(
            "AI RMF functions covered: "
            + ", ".join(f"{k} ({v})" for k, v in sorted(by_fn.items()))
        )
        return "\n".join(rows)

    def save(self, path: str | Path) -> None:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        with p.open("w", encoding="utf-8") as fh:
            for d in self.docs:
                fh.write(d.model_dump_json() + "\n")

    @classmethod
    def load(cls, path: str | Path) -> "GovernanceKB":
        docs = []
        with Path(path).open(encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    docs.append(GovernanceDoc.model_validate_json(line))
        return cls(docs)


def assert_not_parser_corpus(records: list[dict]) -> None:
    """Tripwire for the examples.jsonl generator (plan 5.4).

    Call this on anything about to become parser-RAG training data. It refuses
    governance documents outright, so a future refactor that merges the two
    corpora fails a test instead of silently creating the injection path
    described at the top of this module.
    """
    for r in records:
        if r.get("corpus") == CORPUS_TAG:
            raise ValueError(
                "Governance document reached the parser corpus. "
                "ATLAS text must never enter the index that builds prompts "
                "containing configuration data -- see ncsa/knowledge/governance.py."
            )
