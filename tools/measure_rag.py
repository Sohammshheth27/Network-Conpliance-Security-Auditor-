"""Before/after measurement: BM25 alone vs BM25+dense, same corpus.

Embeds NIST + ISO only (see HybridIndex.embed_all for why), then re-runs the
identical probes and prints what changed. Held to the same corpus in both
arms so the delta is dense-vs-lexical and not corpus growth.
"""
from __future__ import annotations

import json
import sys
import time

from ncsa.frameworks.models import Framework
from ncsa.frameworks.registry import load_all
from ncsa.rag.author import FRAMEWORKS
from ncsa.rag.cis_body import load_cache
from ncsa.rag.corpus import build_corpus
from ncsa.rag.index import HybridIndex
from ncsa.rag.probe import probes_from_packs

FIELDS = ["management.http.enabled", "banner.login", "logging.servers",
          "snmp.communities", "authentication.min_password_length",
          "management.vty.exec_timeout", "time.ntp_enabled"]

DENSE_FOR = {Framework.NIST_800_53, Framework.ISO_27001}


def top(ix, probe, fw):
    h = ix.search(probe.query_text(), k=1, frameworks={fw}, min_rrf=0.0150)
    if not h:
        return "-", None
    d = h[0].doc
    return f"{d.control_id} {(d.title or '')[:34]}", h[0]


def main():
    docs = build_corpus(load_all("reference"), cis_bodies=load_cache())
    print(f"corpus {len(docs)} documents")
    ix = HybridIndex(docs)
    ps = {p.field: p for p in probes_from_packs()}

    before = {f: {fw.value: top(ix, ps[f], fw)[0] for fw in FRAMEWORKS}
              for f in FIELDS}

    n = sum(1 for d in docs if d.framework in DENSE_FOR)
    print(f"embedding {n} NIST+ISO documents (CIS/STIG stay BM25)...")

    def prog(done, total):
        print(f"\r  {done}/{total}", end="", flush=True)

    t = time.time()
    ix.embed_all(only=lambda d: d.framework in DENSE_FOR, progress=prog)
    print(f"\r  done in {time.time()-t:.0f}s{' '*24}")

    after = {f: {fw.value: top(ix, ps[f], fw)[0] for fw in FRAMEWORKS}
             for f in FIELDS}

    json.dump({"before": before, "after": after},
              open("reference/.rag_measurement.json", "w"), indent=1)

    changed = same = 0
    for f in FIELDS:
        print(f"\n=== {f}")
        for fw in FRAMEWORKS:
            b, a = before[f][fw.value], after[f][fw.value]
            if b == a:
                same += 1
                print(f"  {fw.value:<16} =  {b[:58]}")
            else:
                changed += 1
                print(f"  {fw.value:<16} -  {b[:58]}")
                print(f"  {'':<16} +  {a[:58]}")
    print(f"\n{changed} changed, {same} unchanged, of {len(FIELDS)*len(FRAMEWORKS)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
