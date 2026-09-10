"""Framework retrieval index -- plan 5.4 / 6.1.

What this is FOR, stated up front because it is the thing most likely to be
got wrong: this index authors MAPPINGS. It does not decide compliance.

    authoring time   SBM field --> RAG --> candidate controls --> human --> rules/*.yaml
    assessment time  config --> readers --> SBM --> engine(rules/*.yaml) --> findings

The engine never calls retrieval. If it did, the same configuration could score
differently on two runs -- a different index build, a re-embed, a tie broken the
other way -- and an assessment nobody can reproduce is an assessment nobody can
audit. Retrieval is allowed to be fuzzy precisely because a human freezes its
output into YAML before any device is ever judged by it.
"""
from .corpus import Document, build_corpus
from .index import HybridIndex, Hit
from .probe import Probe, MappingProposal, probes_from_packs

__all__ = ["Document", "build_corpus", "HybridIndex", "Hit",
           "Probe", "MappingProposal", "probes_from_packs"]
