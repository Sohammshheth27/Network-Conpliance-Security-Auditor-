"""Benchmark field matching on held-out vendors.

    python -m tools.eval_matching            # full ablation
    python -m tools.eval_matching --quick    # lexical + type prior only

WHY HOLD OUT A WHOLE VENDOR. Random pair splits leak: the same schema field is
mapped by several vendors, so a random test pair usually has its answer sitting
in the training set under a different spelling. Holding out an entire vendor is
the only split that reproduces the real question -- "a device from a vendor
nobody here has described".

WHAT THE NUMBERS ARE FOR. Every accuracy claim about matching should cite this
script and a date, not an impression. The labeled set is the 233 (vendor
syntax -> schema field) pairs already written into the packs, which a human
authored and the golden corpus keeps honest.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

import numpy as np

from ncsa.nlp.matcher import Example, NlpMatcher
from ncsa.nlp.semantic import SemanticMatcher, _ollama_embed
from ncsa.nlp.signals import describe_fields, expand, humanise, infer_type
from ncsa.pipeline import load_packs
from ncsa.schema.sbm import FIELD_TYPES

RESULTS = Path("corpus/matching_benchmark.json")


def labeled_pairs() -> list:
    """(vendor, vendor_syntax, schema_field, sample_value)."""
    out = []
    for p in load_packs():
        for m in p.mappings:
            raw = m.path or m.regex or m.jsonpath
            if not (raw and m.field):
                continue
            # The value a mapping produces is part of the signal available at
            # match time, so the benchmark must supply it too. `const` gives it
            # directly; otherwise fall back to the declared field type.
            spec = m.value or {}
            val = spec.get("const", m.const)
            if val is None:
                ft = FIELD_TYPES.get(m.field.split("[")[0], "str")
                val = {"bool": "on", "int": "10", "list": "a,b"}.get(ft, "value")
            out.append((p.vendor, raw, m.field.split("[")[0], val))
    return out


def _score(ranked, gold) -> tuple:
    fields = [f for f, *_ in ranked] if ranked and isinstance(ranked[0], tuple) \
        else list(ranked)
    return (1 if fields[:1] == [gold] else 0,
            1 if gold in fields[:5] else 0)


def run(quick=False) -> dict:
    pairs = labeled_pairs()
    vendors = sorted({v for v, *_ in pairs})
    descs = describe_fields()
    print(f"{len(pairs)} labeled pairs across {len(vendors)} vendors\n")

    arms = ["lexical", "lexical+type", "dense-only", "dense-only+type",
            "hybrid", "hybrid+type"]
    if quick:
        arms = ["lexical", "lexical+type"]
    tally = {a: [0, 0, 0] for a in arms}          # top1, top5, n
    per_vendor = {}

    for held in vendors:
        train = [x for x in pairs if x[0] != held]
        test = [x for x in pairs if x[0] == held]
        if not test or not train:
            continue

        lex = NlpMatcher([Example(line=r, field=f, vendor=v)
                          for v, r, f, _ in train]).fit()
        # Candidates: only fields the training vendors actually use. Proposing
        # a field no pack has ever mapped would be a guess with no support.
        cands = sorted({f for _v, _r, f, _val in train})

        sem = None
        if not quick:
            sem = SemanticMatcher(fields=cands, descriptions=descs,
                                  lexical=lex, embed_fn=_ollama_embed).fit()
            if not sem.dense_available:
                print("  (embedding service unreachable -- dense arms skipped)")
                sem = None
            else:
                # One round-trip for every query in this fold.
                from ncsa.nlp.signals import expand as _x, infer_type as _t
                warm = []
                for _v, raw, _g, val in test:
                    q = _x(raw)
                    if val is not None and _t(val) in ("str", "ip"):
                        q = f"{q} {str(val)[:60]}"
                    warm.append(q)
                sem.warm(warm)

        rows = {a: [0, 0] for a in arms}
        for _v, raw, gold, val in test:
            q = humanise(raw)
            lex_rank = [h.field for h in lex.match(q, k=10)]

            got = {"lexical": lex_rank}
            if "lexical+type" in arms:
                got["lexical+type"] = _apply_type(lex_rank, val)
            if sem is not None:
                got["dense-only"] = [f for f, *_ in sem.match(
                    raw, val, k=10, type_gate=False, use_lexical=False)]
                got["dense-only+type"] = [f for f, *_ in sem.match(
                    raw, val, k=10, type_gate=True, use_lexical=False)]
                got["hybrid"] = [f for f, *_ in sem.match(
                    raw, val, k=10, type_gate=False)]
                got["hybrid+type"] = [f for f, *_ in sem.match(
                    raw, val, k=10, type_gate=True)]

            for a in arms:
                if a not in got:
                    continue
                t1, t5 = _score(got[a], gold)
                rows[a][0] += t1
                rows[a][1] += t5

        n = len(test)
        per_vendor[held] = {a: {"top1": round(100 * rows[a][0] / n, 1),
                                "top5": round(100 * rows[a][1] / n, 1),
                                "n": n} for a in arms}
        print(f"hold out {held:<12} n={n}")
        for a in arms:
            r = per_vendor[held][a]
            print(f"   {a:<16} top-1 {r['top1']:5.1f}%   top-5 {r['top5']:5.1f}%")
        print()
        for a in arms:
            tally[a][0] += rows[a][0]
            tally[a][1] += rows[a][1]
            tally[a][2] += n

    print("WEIGHTED OVERALL")
    overall = {}
    for a in arms:
        t1, t5, n = tally[a]
        overall[a] = {"top1": round(100 * t1 / n, 1) if n else 0.0,
                      "top5": round(100 * t5 / n, 1) if n else 0.0, "n": n}
        print(f"   {a:<16} top-1 {overall[a]['top1']:5.1f}%   "
              f"top-5 {overall[a]['top5']:5.1f}%   (n={n})")

    out = {"generated": datetime.now().replace(microsecond=0).isoformat(),
           "pairs": len(pairs), "vendors": vendors,
           "overall": overall, "per_vendor": per_vendor}
    RESULTS.parent.mkdir(parents=True, exist_ok=True)
    RESULTS.write_text(json.dumps(out, indent=1), encoding="utf-8")
    print(f"\nwritten -> {RESULTS}")
    return out


def _apply_type(ranked_fields, value):
    """Re-rank an existing ranking by the type prior alone."""
    from ncsa.nlp.signals import type_multiplier
    vt = infer_type(value)
    scored = [(f, (1.0 / (60 + i)) * type_multiplier(vt, FIELD_TYPES.get(f, "str")))
              for i, f in enumerate(ranked_fields, 1)]
    scored.sort(key=lambda t: -t[1])
    return [f for f, _ in scored]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true")
    a = ap.parse_args()
    run(quick=a.quick)
    return 0


if __name__ == "__main__":
    sys.exit(main())
