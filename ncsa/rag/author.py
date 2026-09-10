"""Author framework mappings from SBM fields -- the RAG's only job.

Produces `mapping_proposals.jsonl`: for every SBM field, candidate controls in
each of the four frameworks. Nothing here writes to rules/*.yaml. A proposal is
PROPOSED until a person approves it (plan 10.2, scoped approvals).

ORDER IS DELIBERATE, and it follows the measured strength of each source:

    STIG   retrieved   median 2,174 chars, contains the vendor command  -> strong
    CIS    retrieved   body shard carries `Audit:` with the command     -> strong
    NIST   derived     from the STIG rule's CCIs via the DISA CCI list
    ISO    derived     from the NIST control via the NIST OLIR crosswalk

The two derived frameworks are the two that retrieval was measurably bad at.
NIST is 174 characters of abstract prose per control; ISO is SIX -- 70 of its
121 entries have no title at all, so "retrieving" ISO was ranking numbers
against a query and returning noise that read like an answer.

Both now come from published crosswalks with their evidence recorded, and both
inherit the score of the hit they were derived from: a NIST label is never
stronger than the STIG rule that implied it, and an ISO label is never stronger
than the NIST control. Retrieval remains the fallback where no crosswalk
applies, so nothing is lost -- it just stops being load-bearing where it does
not work.
"""
from __future__ import annotations

import json
from pathlib import Path

from ..frameworks.models import Framework
from .probe import MappingProposal

FRAMEWORKS = [Framework.NIST_800_53, Framework.DISA_STIG,
              Framework.CIS, Framework.ISO_27001]

# Below this fused rank score the candidate is noise. Plan 5.3's confidence
# floor: return nothing rather than the best of a bad set.
MIN_RRF = 0.0150


def _titles(index, framework) -> dict:
    return {d.control_id: d.title for d in index.docs if d.framework is framework}


def _retrieved(pr, hits, fw) -> list:
    out = []
    for h in hits:
        d = h.doc
        out.append(MappingProposal(
            field=pr.field, framework=fw.value, control_id=d.control_id,
            source_document=d.source_document, score=h.rrf,
            retrieval={"via": "retrieval", "bm25_rank": h.bm25_rank,
                       "dense_rank": h.dense_rank,
                       "also_in": len(h.also_in or [])},
            title=d.title, platform=d.platform, automatable=d.automatable))
    return out


def _nist_from_cci(pr, stig_hits, cci_map, nist_titles, limit) -> list:
    """NIST controls the top STIG rules cite. Authoritative, not inferred."""
    out, seen = [], set()
    for h in stig_hits:
        for cid in (h.doc.meta.get("ccis") or []):
            for ctrl in cci_map.get(cid, []):
                if ctrl in seen:
                    continue
                seen.add(ctrl)
                out.append(MappingProposal(
                    field=pr.field, framework=Framework.NIST_800_53.value,
                    control_id=ctrl,
                    source_document="NIST SP 800-53 Rev 5 (via DISA CCI)",
                    score=h.rrf,
                    retrieval={"via": "stig_cci", "from_stig": h.doc.control_id,
                               "cci": cid, "bm25_rank": None, "dense_rank": None},
                    title=nist_titles.get(ctrl), automatable="unknown"))
                if len(out) >= limit:
                    return out
    return out


def _iso_from_crosswalk(pr, nist_id, score, crosswalk, iso_titles, limit) -> list:
    if not nist_id:
        return []
    clauses = crosswalk.get(nist_id) or crosswalk.get(nist_id.split(".")[0]) or []
    clauses = [c for c in clauses if c.startswith("A.")][:limit]
    return [
        MappingProposal(
            field=pr.field, framework=Framework.ISO_27001.value, control_id=c,
            source_document="ISO/IEC 27001:2022 (via NIST OLIR)",
            score=score / rank,
            retrieval={"via": "nist_olir_crosswalk", "from_nist": nist_id,
                       "crosswalk_rank": rank, "bm25_rank": None,
                       "dense_rank": None},
            title=iso_titles.get(c), automatable="unknown")
        for rank, c in enumerate(clauses, 1)
    ]


def propose(index, probes, *, per_framework=3, min_rrf=MIN_RRF,
            iso_crosswalk=None, cci_map=None) -> list[MappingProposal]:
    out: list[MappingProposal] = []
    nist_titles = _titles(index, Framework.NIST_800_53)
    iso_titles = _titles(index, Framework.ISO_27001)

    for pr in probes:
        q = pr.query_text()

        stig = index.search(q, k=per_framework, frameworks={Framework.DISA_STIG},
                            min_rrf=min_rrf)
        cis = index.search(q, k=per_framework, frameworks={Framework.CIS},
                           min_rrf=min_rrf)
        out += _retrieved(pr, stig, Framework.DISA_STIG)
        out += _retrieved(pr, cis, Framework.CIS)

        # --- NIST: derived from the STIG rule's CCIs, else retrieved ---------
        nist = []
        if cci_map and stig:
            nist = _nist_from_cci(pr, stig, cci_map, nist_titles, per_framework)
        if not nist:
            nist = _retrieved(pr, index.search(
                q, k=per_framework, frameworks={Framework.NIST_800_53},
                min_rrf=min_rrf), Framework.NIST_800_53)
        out += nist

        # --- ISO: derived from the NIST control ------------------------------
        if iso_crosswalk is not None:
            top = nist[0] if nist else None
            out += _iso_from_crosswalk(
                pr, top.control_id if top else None, top.score if top else 0.0,
                iso_crosswalk, iso_titles, per_framework)
        else:
            out += _retrieved(pr, index.search(
                q, k=per_framework, frameworks={Framework.ISO_27001},
                min_rrf=min_rrf), Framework.ISO_27001)
    return out


def write_proposals(proposals, path="reference/mapping_proposals.jsonl",
                    *, local_review=True) -> dict:
    """Write proposals for human review.

    ``local_review=True`` keeps CIS/ISO titles, which a reviewer on this machine
    needs and the licence permits locally. Anything destined to leave -- a
    commit, a report, a training set -- must be written with False, and
    guard.assert_exportable is what stops that being forgotten.
    """
    p = Path(path)
    with p.open("w", encoding="utf-8") as fh:
        for mp in proposals:
            fh.write(json.dumps(mp.to_json(licensed_ok=local_review),
                                ensure_ascii=False) + "\n")
    return {"written": len(proposals), "path": str(p),
            "titles_included": local_review}


def coverage(proposals, probes) -> dict:
    have = {fw.value: set() for fw in FRAMEWORKS}
    for m in proposals:
        have[m.framework].add(m.field)
    n = len(probes)
    return {fw: f"{len(s)}/{n} fields ({100*len(s)/n:.0f}%)"
            for fw, s in have.items()}
