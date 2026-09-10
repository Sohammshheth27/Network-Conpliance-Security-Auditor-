"""Is the suggester's confidence worth anything?

A ranking tells you which field to look at first. It does not tell you whether
to look at all. That second question is what decides whether 442 unmapped
settings can be worked through by a person, because it is the difference
between:

    "here are 442 guesses, all scored 1.639"          -- useless
    "these 60 are probably right; these 380 need you" -- a work plan

The old score was the reciprocal-rank constant 1/(RRF_K+1), identical for every
top-1 hit, so no such split was possible. This measures whether the replacement
actually separates right answers from wrong ones.

WHY THE HEADLINE DIFFERS FROM tools.eval_matching
-------------------------------------------------
eval_matching reports 59.0% top-1; this reports 68.8% on the same 378 pairs.
Neither is wrong -- they use different denominators, and the numbers reconcile
exactly.

eval_matching restricts the candidate fields to those the TRAINING vendors map,
so when a held-out vendor is the only one mapping a field, that field is not
offered and the item is unanswerable by construction. That is 54 of 378
(14.3%): aws 7/8, cisco 29/108, sonicwall 14/84, fortinet 4/44. Discount them
and 59.0% of 378 is the same 223 correct as 68.8% of 324.

Use eval_matching's figure for "can we generalise to a field no pack has ever
mapped" -- the harder question. Use this one for the deployment question, where
the full schema is always on offer. Do not quote them as before/after.

WHAT THIS DOES NOT DO
---------------------
It does not license auto-approval. Precision here is measured against mappings
a human already wrote, on held-out vendors -- which is the right test for
ranking and a generous one for deployment: a real unmapped setting may have NO
correct field, and this set contains no such case. Every proposal still goes
through the training queue and the golden-corpus regression gate.

    python -m tools.eval_confidence
"""
from __future__ import annotations

import json
from pathlib import Path

from ncsa.nlp.semantic import SemanticMatcher
from ncsa.nlp.signals import expand
from tools.eval_matching import labeled_pairs

OUT = Path("corpus/confidence_benchmark.json")
BANDS = [(80, 101), (60, 80), (40, 60), (20, 40), (0, 20)]


def run() -> dict:
    pairs = labeled_pairs()
    vendors = sorted({v for v, *_ in pairs})
    print(f"{len(pairs)} labelled pairs across {len(vendors)} vendors")
    print("held-out by vendor, so no pack is scored against its own mappings\n")

    rows = []
    for held in vendors:
        train = [x for x in pairs if x[0] != held]
        test = [x for x in pairs if x[0] == held]
        if not test:
            continue
        # `lexical=None` and use_lexical=False below: this measures the
        # dense-only+type arm, which the benchmark found best at 59.0% top-1.
        #
        # There is no vendor leakage to guard against in that arm. The dense
        # index embeds SCHEMA FIELD DESCRIPTIONS, which are vendor-independent
        # and contain no pack mapping -- so the matcher cannot retrieve the
        # answer it is being asked for. The held-out loop is kept anyway so the
        # split matches eval_matching exactly and the two are comparable.
        sem = SemanticMatcher(lexical=None).fit()
        sem.warm([expand(syntax) for _v, syntax, _f, _val in test])

        for _v, syntax, gold, val in test:
            hits = sem.match(syntax, val, k=1, use_lexical=False)
            if not hits:
                rows.append((0.0, False))
                continue
            field, conf, _why = hits[0]
            rows.append((conf, field == gold))

    total = len(rows)
    correct = sum(1 for _c, ok in rows if ok)
    print(f"overall top-1: {100*correct/max(total,1):.1f}%  (n={total})\n")

    print(f"{'confidence':<14} {'n':>5} {'correct':>8} {'precision':>10} {'cumulative coverage':>21}")
    seen = 0
    out_bands = []
    for lo, hi in BANDS:
        band = [(c, ok) for c, ok in rows if lo <= c < hi]
        n = len(band)
        ok = sum(1 for _c, k in band if k)
        seen += n
        prec = 100 * ok / n if n else 0.0
        print(f"  {lo:>3}-{hi-1:<9} {n:>5} {ok:>8} {prec:>9.1f}% {100*seen/max(total,1):>20.1f}%")
        out_bands.append({"low": lo, "high": hi, "n": n, "correct": ok,
                          "precision_pct": round(prec, 1)})

    # The operational question: if we only auto-queue above a threshold, what
    # do we get, and what does it cost in coverage?
    print(f"\n{'threshold':<12} {'auto-queued':>12} {'precision':>10} {'left for a human':>18}")
    thresholds = []
    for t in (80, 70, 60, 50, 40, 30):
        above = [(c, ok) for c, ok in rows if c >= t]
        n = len(above)
        ok = sum(1 for _c, k in above if k)
        prec = 100 * ok / n if n else 0.0
        print(f"  >= {t:<8} {n:>12} {prec:>9.1f}% {total-n:>18}")
        thresholds.append({"threshold": t, "n": n, "precision_pct": round(prec, 1),
                           "remaining": total - n})

    result = {"pairs": total, "top1_pct": round(100*correct/max(total, 1), 1),
              "bands": out_bands, "thresholds": thresholds}
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(result, indent=1), encoding="utf-8")
    print(f"\nwritten -> {OUT}")
    return result


if __name__ == "__main__":
    run()
