"""12.5 -- Similarity matching. Tier 2 of the router.

Two complementary measures, which is what "Pattern Recognition **and** NLP"
means in practice: TF-IDF over normalised tokens (semantic-ish) combined with
BM25 keyword scoring (plan 9.4's hybrid retrieval).

Config lines are not prose. They share EXACT keywords -- `ssh`, `telnet`,
`snmp-server`. Keyword search beats pure semantic search on technical text, so
hybrid beats either alone.

This is the tier that resolves an unknown vendor without any model at all, in
about 50 ms, and it is the reason the demo survives a stalled Ollama.
"""
from __future__ import annotations

from dataclasses import dataclass

from .pipeline import normalize, tokenize


@dataclass
class Example:
    """One known (line -> field) pair. The corpus is built from our own packs."""

    line: str
    field: str
    vendor: str = ""
    as_type: str = "str"

    @property
    def normalised(self) -> str:
        return " ".join(normalize(tokenize(self.line)))


@dataclass
class Match:
    field: str
    score: float
    example: Example
    method: str = "hybrid"


class NlpMatcher:
    """Rank candidate SBM fields for an unseen configuration line."""

    def __init__(self, examples: list[Example]):
        self.examples = examples
        self._vec = None
        self._matrix = None
        self._bm25 = None

    # ------------------------------------------------------------------ index
    def fit(self) -> "NlpMatcher":
        from sklearn.feature_extraction.text import TfidfVectorizer

        corpus = [e.normalised for e in self.examples]
        # char n-grams as well as words: vendor tokens are often glued together
        # (`admintimeout`), and word-level features alone would miss them.
        self._vec = TfidfVectorizer(analyzer="word", ngram_range=(1, 2), min_df=1)
        self._matrix = self._vec.fit_transform(corpus)

        try:
            from rank_bm25 import BM25Okapi

            self._bm25 = BM25Okapi([c.split() for c in corpus])
        except ImportError:      # hybrid degrades to TF-IDF only
            self._bm25 = None
        return self

    # -------------------------------------------------------------- retrieval
    def match(self, line: str, k: int = 5) -> list[Match]:
        if self._matrix is None:
            self.fit()
        from sklearn.metrics.pairwise import cosine_similarity

        q = " ".join(normalize(tokenize(line)))
        dense = cosine_similarity(self._vec.transform([q]), self._matrix)[0]

        # RAW cosine similarity, deliberately not rescaled to the best hit.
        # Normalising by max() pinned the top score at 1.00 for every query,
        # so NLP_ACCEPT could never reject anything and every line looked
        # confidently resolved -- including the ones we got wrong.
        if self._bm25 is not None:
            import numpy as np

            kw = np.asarray(self._bm25.get_scores(q.split()), dtype=float)
            kw = kw / 10.0                      # BM25 is unbounded; damp it
            scores = 0.7 * dense + 0.3 * np.clip(kw, 0, 1)
        else:
            scores = dense

        order = scores.argsort()[::-1][:k]
        return [
            Match(field=self.examples[i].field, score=float(scores[i]),
                  example=self.examples[i])
            for i in order if scores[i] > 0
        ]

    def best(self, line: str) -> Match | None:
        hits = self.match(line, k=1)
        return hits[0] if hits else None


def _norm(v):
    import numpy as np

    v = np.asarray(v, dtype=float)
    return v / v.max() if v.max() > 0 else v


# ---------------------------------------------------------------------------
def corpus_from_packs(pack_dir: str, sample_dir: str | None = None) -> list[Example]:
    """Plan 5.4 -- the RAG corpus is a by-product of work already done.

    Run every mapping-pack regex over the sample configs; every match yields a
    (real line, field, value) triple. That is the plan's actual instruction,
    and it matters: deriving pseudo-lines by stripping regex syntax produced
    garbage examples like 'hostname S' and '.GroupId', which then matched
    everything equally badly.
    """
    import re
    from pathlib import Path

    import yaml

    out: list[Example] = []
    seen: set[tuple[str, str]] = set()
    samples = list(Path(sample_dir).rglob("*")) if sample_dir else []
    sample_texts = []
    for sp in samples:
        if sp.is_file() and sp.suffix.lower() in (".cfg", ".conf", ".txt"):
            sample_texts.append(sp.read_text(encoding="utf-8", errors="replace"))

    for f in sorted(Path(pack_dir).glob("*.yaml")):
        with f.open(encoding="utf-8") as fh:
            pack = yaml.safe_load(fh) or {}
        vendor = pack.get("vendor", "")
        for m in pack.get("mappings", []) or []:
            rx, fld = m.get("regex"), m.get("field")
            if not rx or not fld:
                continue
            as_type = (m.get("value") or {}).get("as", "str")
            for text in sample_texts:
                for line in text.splitlines():
                    line = line.rstrip()
                    if not line.strip():
                        continue
                    try:
                        if re.search(rx, line.strip()) or re.search(rx, line):
                            key = (line.strip(), fld)
                            if key not in seen:
                                seen.add(key)
                                out.append(Example(line=line.strip(), field=fld,
                                                   vendor=vendor, as_type=as_type))
                    except re.error:
                        continue
    return _disambiguate(out)


def _disambiguate(examples: list[Example]) -> list[Example]:
    """One line, one label.

    A pack legitimately has several mappings that match the same physical line:
    `logging host 10.0.0.5` satisfies both the `logging.enabled` presence rule
    and the `logging.servers` extraction rule. Both are correct as PARSING
    rules, but as TRAINING examples they teach the matcher that one line means
    two different things -- and it then picks one at random.

    Keep the label whose own field name shares the most tokens with the line;
    that is the more specific of the two ("servers" appears in the line,
    "enabled" does not). Presence-style booleans lose to extraction-style
    fields, which is the right precedence.
    """
    from .pipeline import normalize, tokenize

    by_line: dict[str, list[Example]] = {}
    for e in examples:
        by_line.setdefault(e.line, []).append(e)

    out: list[Example] = []
    for line, group in by_line.items():
        if len(group) == 1:
            out.append(group[0])
            continue
        line_tokens = set(normalize(tokenize(line)))
        def specificity(ex: Example) -> tuple[int, int, int]:
            ftok = set(normalize(tokenize(ex.field.replace(".", " "))))
            leaf = ex.field.rsplit(".", 1)[-1]
            leaf_tok = set(normalize(tokenize(leaf)))
            # The LEAF is what the mapping actually extracts. `ntp server ...`
            # names a server, so time.servers beats time.ntp_enabled -- both
            # share the token `ntp`, but only one has its leaf in the line.
            # Without this the tiebreak fell to field-name length and picked
            # the boolean presence flag, a confident wrong answer at 0.78.
            return (len(leaf_tok & line_tokens), len(ftok & line_tokens), -len(ex.field))
        out.append(max(group, key=specificity))
    return out


def corpus_from_stig(registry, limit_per_field: int = 40) -> list[Example]:
    """Plan 5.2 Tier 3 -- STIG fix text is simultaneously rule content AND
    free example lines, in the vendor's own syntax, public domain.

    Only lines that look like commands are taken, and they are labelled by
    keyword against the SBM field list. Unlabelled commands are skipped rather
    than guessed at.
    """
    import re

    from ..frameworks.models import Framework

    KEYS = [
        ("management.ssh.version",        [r"ip ssh version", r"protocol-version"]),
        ("management.ssh.max_auth_tries", [r"authentication-retries", r"ssh.*retr"]),
        ("management.vty.exec_timeout",   [r"exec-timeout", r"idle-timeout", r"session.*timeout"]),
        ("management.vty.transport_input",[r"transport input"]),
        ("management.vty.access_class",   [r"access-class"]),
        ("management.http.enabled",       [r"ip http server"]),
        ("authentication.aaa_enabled",    [r"aaa new-model", r"aaa authentication"]),
        ("authentication.min_password_length", [r"min-length", r"minimum-length"]),
        ("logging.servers",               [r"logging host", r"logging server"]),
        ("time.servers",                  [r"ntp server"]),
        ("time.authenticated",            [r"ntp authenticate"]),
        ("snmp.communities",              [r"snmp-server community"]),
        ("snmp.version",                  [r"snmp-server (group|user)"]),
        ("banner.login",                  [r"banner (login|motd)"]),
    ]
    cat = registry.catalogs.get(Framework.DISA_STIG)
    if cat is None:
        return []

    counts: dict[str, int] = {}
    out: list[Example] = []
    for entry in cat.entries:
        for raw in (entry.fix or "").splitlines():
            line = re.sub(r"^\s*\S*[#>]\s*", "", raw).strip()   # strip R1(config)#
            if len(line) < 6 or line.lower().startswith(("configure", "example", "step")):
                continue
            for field, pats in KEYS:
                if counts.get(field, 0) >= limit_per_field:
                    continue
                if any(re.search(p, line, re.I) for p in pats):
                    out.append(Example(line=line, field=field,
                                       vendor=entry.platform or "stig"))
                    counts[field] = counts.get(field, 0) + 1
                    break
    return _disambiguate(out)
