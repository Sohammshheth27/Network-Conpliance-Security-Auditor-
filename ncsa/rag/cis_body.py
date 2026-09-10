"""Extract per-recommendation body text from the CIS Benchmark PDFs.

``frameworks/cis.py`` reads the table of contents, which yields the identifier
and title -- enough to CITE a recommendation. It is not enough to RETRIEVE one:
"Ensure 'aaa new-model' is enabled" shares almost no vocabulary with the SBM
field it should match.

The body does carry that vocabulary, and the ``Audit:`` section carries the
actual vendor command, which is the single strongest signal we have for mapping
a configuration setting to a recommendation.

LOCAL ONLY. The output of this module is copyrighted CIS prose. It stays on the
machine that holds the licensed PDFs: see ``rag/guard.py``. The cache path is
under reference/ precisely so the existing .gitignore covers it.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

# A body heading. The table of contents cannot match this: TOC lines end with
# dot leaders and a page number, so the line-anchored `$` fails there.
# CIS changed this vocabulary partway through: benchmarks published before
# ~2020 tag each recommendation (Scored)/(Not Scored), newer ones use
# (Automated)/(Manual). Accepting only the new pair made six older benchmarks
# -- including CIS Cisco Firewall v4.1.0 and CIS Cisco IOS 16 -- extract ZERO
# recommendations and report no error, which is the worst way to lose data:
# `Enable 'aaa new-model'` was simply missing from the index.
_HEADING = re.compile(
    r"^(\d+(?:\.\d+){1,4})\s+(.{4,150}?)\s*"
    r"\((Automated|Manual|Scored|Not Scored)\)\s*$", re.M)
# Scored/Automated both mean "decidable from configuration".
_AUTOMATABLE = {"Automated", "Scored"}

_SECTIONS = ("Profile Applicability:", "Description:", "Rationale:", "Impact:",
             "Audit:", "Remediation:", "Default Value:", "References:",
             "CIS Controls:", "Additional Information:")


def _sections_of(body: str) -> dict[str, str]:
    """Split one recommendation's body into its labelled sections."""
    marks = []
    for s in _SECTIONS:
        i = body.find(s)
        if i >= 0:
            marks.append((i, s))
    marks.sort()
    out = {}
    for n, (i, s) in enumerate(marks):
        end = marks[n + 1][0] if n + 1 < len(marks) else len(body)
        out[s.rstrip(":")] = body[i + len(s):end].strip()
    return out


def extract_pdf(path: Path) -> list[dict]:
    from pypdf import PdfReader

    try:
        reader = PdfReader(str(path))
    except Exception as exc:                       # noqa: BLE001
        return [{"_error": f"{type(exc).__name__}: {exc}", "_file": str(path)}]

    text = "\n".join(pg.extract_text() or "" for pg in reader.pages)
    hits = list(_HEADING.finditer(text))
    out = []
    for n, m in enumerate(hits):
        end = hits[n + 1].start() if n + 1 < len(hits) else len(text)
        body = text[m.end():end]
        # A heading with no body is a cross-reference or a stray TOC artefact.
        if len(body.strip()) < 60:
            continue
        sec = _sections_of(body)
        out.append({
            "id": m.group(1),
            "title": m.group(2).strip(),
            "automated": m.group(3) in _AUTOMATABLE,
            "benchmark": path.stem,
            "vendor": path.parent.name,
            "source_file": str(path),
            "sections": sec,
        })
    return out


def build_cache(cis_dir="reference/cis_benchmarks",
                out="reference/cis_benchmarks/_body_cache.jsonl",
                *, verbose=True, resume=True) -> dict:
    """Extract every benchmark body. Resumable, and safe to interrupt.

    ``resume=True`` skips benchmarks already present and APPENDS. Two things
    forced this: the run takes ~30 minutes, and an earlier attempt was launched
    twice by accident -- two processes opening the same path in "w" mode wrote
    608 duplicate records into one file. Keying on the benchmark name makes a
    second run converge instead of compounding.
    """
    root, dst = Path(cis_dir), Path(out)
    done: set[str] = set()
    if resume and dst.exists():
        for line in dst.open(encoding="utf-8"):
            if line.strip():
                try:
                    done.add(json.loads(line)["benchmark"])
                except Exception:                      # noqa: BLE001
                    pass

    pdfs = sorted(root.rglob("*.pdf"))
    todo = [p for p in pdfs if p.stem not in done]
    if verbose:
        print(f"{len(pdfs)} PDFs; {len(done)} benchmarks already cached; "
              f"{len(todo)} to do", flush=True)

    n_rec, errs = 0, []
    mode = "a" if (resume and dst.exists()) else "w"
    with dst.open(mode, encoding="utf-8") as fh:
        for i, p in enumerate(todo, 1):
            recs = extract_pdf(p)
            if recs and "_error" in recs[0]:
                errs.append(recs[0])
                if verbose:
                    print(f"[{i}/{len(todo)}] ERROR {p.name}: "
                          f"{recs[0]['_error']}", flush=True)
                continue
            for r in recs:
                fh.write(json.dumps(r, ensure_ascii=False) + "\n")
            fh.flush()
            n_rec += len(recs)
            if verbose:
                print(f"[{i}/{len(todo)}] {len(recs):>4} recs  {p.name[:66]}",
                      flush=True)
    return {"pdfs": len(pdfs), "skipped": len(done), "new_recommendations": n_rec,
            "errors": errs, "cache": str(dst)}


def dedupe_cache(path="reference/cis_benchmarks/_body_cache.jsonl") -> dict:
    """Collapse records duplicated by a double-launched extraction."""
    p = Path(path)
    seen, keep = set(), []
    for line in p.open(encoding="utf-8"):
        if not line.strip():
            continue
        r = json.loads(line)
        k = (r.get("benchmark"), r.get("id"))
        if k in seen:
            continue
        seen.add(k)
        keep.append(line.rstrip("\n"))
    with p.open("w", encoding="utf-8") as fh:
        fh.write("\n".join(keep) + "\n")
    return {"kept": len(keep)}


def load_cache(path="reference/cis_benchmarks/_body_cache.jsonl") -> list[dict]:
    p = Path(path)
    if not p.exists():
        return []
    return [json.loads(l) for l in p.open(encoding="utf-8") if l.strip()]


if __name__ == "__main__":
    import sys
    r = build_cache()
    print(json.dumps({k: v for k, v in r.items() if k != "errors"}, indent=2))
    print(f"errors: {len(r['errors'])}")
    for e in r["errors"][:10]:
        print("  ", e["_file"], e["_error"])
