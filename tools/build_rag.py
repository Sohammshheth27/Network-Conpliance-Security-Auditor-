"""Build the framework retrieval index. One command, end to end.

    python -m tools.build_rag              # build + embed + propose
    python -m tools.build_rag --no-embed   # BM25 only, seconds instead of minutes

Embeddings are cached by content hash, so a rebuild after a catalogue change
only embeds what actually changed.
"""
from __future__ import annotations

import argparse
import json
import sys
import time

from ncsa.frameworks.registry import load_all
from ncsa.rag.author import coverage, propose, write_proposals
from ncsa.rag.cis_body import load_cache
from ncsa.rag.corpus import build_corpus
from ncsa.rag.index import HybridIndex
from ncsa.rag.probe import probes_from_packs


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-embed", action="store_true")
    ap.add_argument("--no-cis-body", action="store_true")
    ap.add_argument("--per-framework", type=int, default=3)
    ap.add_argument("--out", default="reference/mapping_proposals.jsonl")
    a = ap.parse_args()

    t0 = time.time()
    reg = load_all("reference")
    bodies = [] if a.no_cis_body else load_cache()
    docs = build_corpus(reg, cis_bodies=bodies)
    from collections import Counter
    print(f"corpus: {len(docs)} documents "
          f"{dict(Counter(d.framework.value for d in docs))}")
    print(f"        CIS body shard: {len(bodies)} recommendations")

    ix = HybridIndex(docs)
    if not a.no_embed:
        n = len(docs)

        def prog(done, total):
            if total:
                pct = 100 * done / total
                print(f"\r  embedding {done}/{total} ({pct:.0f}%)",
                      end="", flush=True)

        t = time.time()
        ix.embed_all(progress=prog)
        print(f"\r  embedded {n} documents in {time.time()-t:.0f}s"
              f"{' '*20}")

    probes = probes_from_packs()
    props = propose(ix, probes, per_framework=a.per_framework)
    info = write_proposals(props, a.out)
    print(f"probes:    {len(probes)} SBM fields")
    print(f"proposals: {info['written']} -> {info['path']}")
    for fw, cov in coverage(props, probes).items():
        print(f"   {fw:<18}{cov}")
    print(f"total {time.time()-t0:.0f}s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
