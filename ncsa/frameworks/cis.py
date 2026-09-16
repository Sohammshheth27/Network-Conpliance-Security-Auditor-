"""CIS Benchmark loader (PDF).

Licensing -- plan 6.2, read this before changing anything here
---------------------------------------------------------------
CIS Benchmarks are copyrighted. The rule is about *redistribution*, not local
reference, so this loader draws the line there:

  * ``id``, ``level``, ``automated``, ``page``  -- facts/identifiers. Safe
    anywhere: report, log, deck.
  * ``title``                                   -- CIS prose. Kept LOCALLY so a
    mapping author can see what "1.2.3" means without opening the PDF, but the
    entry is marked IDENTIFIER_ONLY, so :meth:`CatalogEntry.citation` never
    emits it and the RAG excluder skips it.

Consequences enforced elsewhere:
  * ``citation()`` returns "<benchmark title> - <number>" for these entries.
  * The examples.jsonl generator (plan 5.4) must exclude reference/cis_benchmarks/
    entirely, or copyrighted prose reaches the vector store and then reports.
  * reference/cis_benchmarks/ must be .gitignored before any public push.
"""
import re
from pathlib import Path

from .models import Automatability, Catalog, CatalogEntry, Framework, License

# CIS PDFs render their table of contents as:
#     1.1.1  Enable 'aaa new-model' (Automated) ........................ 23
# The body headings do not survive text extraction reliably, but the TOC does,
# and the TOC carries everything we actually need.
_TOC_RE = re.compile(
    r"^\s*(\d+(?:\.\d+){1,4})\s+(.{4,150}?)\s*\.{3,}\s*(\d+)\s*$", re.M
)
_LEVEL_RE = re.compile(r"\((L(\d)|Level\s*(\d))\)", re.I)
_AUTO_RE = re.compile(r"\((Automated|Manual)\)", re.I)


_NUMBERED = re.compile(r"^\s*\d+(?:\.\d+){1,4}\s")
_LEADER_END = re.compile(r"\.{3,}\s*\d+\s*$")


def _join_wrapped_toc(text: str) -> str:
    """Re-join TOC entries whose title wraps onto the next line.

        6.3 Ensure no security groups allow ingress from 0.0.0.0/0 to remote server administration
        ports (Automated) ..................................... 283

    The TOC pattern needs the number, the title and the dot leader on ONE
    line, so a wrapped title matched nothing and the recommendation vanished
    from the catalogue -- in the AWS benchmark, exactly the three networking
    recommendations (6.2-6.4) a firewall auditor needs. Up to two continuation
    lines are joined, and only when they do not start a new numbered entry.
    """
    lines = text.splitlines()
    out, i = [], 0
    while i < len(lines):
        line = lines[i]
        if _NUMBERED.match(line) and not _LEADER_END.search(line):
            j = i + 1
            while (j < len(lines) and j <= i + 2 and not _NUMBERED.match(lines[j])
                   and not _LEADER_END.search(line)):
                line = line.rstrip() + " " + lines[j].strip()
                j += 1
            if _LEADER_END.search(line):
                out.append(line)
                i = j
                continue
        out.append(lines[i])
        i += 1
    return "\n".join(out)


def _parse_pdf(path: Path, vendor: str) -> list[CatalogEntry]:
    from pypdf import PdfReader

    try:
        reader = PdfReader(str(path))
    except Exception:
        return []

    text = _join_wrapped_toc("\n".join((p.extract_text() or "") for p in reader.pages))
    doc_title = path.stem.replace("_", " ")

    entries: list[CatalogEntry] = []
    seen: set[str] = set()
    for num, raw_title, page in _TOC_RE.findall(text):
        if num in seen:
            continue
        seen.add(num)

        title = raw_title.strip()
        lvl_m = _LEVEL_RE.search(title)
        level = int(lvl_m.group(2) or lvl_m.group(3)) if lvl_m else None
        auto_m = _AUTO_RE.search(title)
        is_automated = auto_m and auto_m.group(1).lower() == "automated"

        # A section heading ("1.1 Local AAA Rules") is a container, not a
        # recommendation. Recommendations carry an (Automated)/(Manual) tag.
        if auto_m is None and num.count(".") < 2:
            continue

        entries.append(
            CatalogEntry(
                framework=Framework.CIS,
                id=num,
                # local reference only -- see the module docstring
                title=title,
                license=License.IDENTIFIER_ONLY,
                automatable=(
                    Automatability.CONFIG if is_automated
                    else Automatability.PROCEDURAL if auto_m
                    else Automatability.UNKNOWN
                ),
                source_document=doc_title,
                source_file=path.name,
                platform=vendor,
                page=int(page),
                extra={
                    "level": level,
                    "assessment": (auto_m.group(1) if auto_m else None),
                    "redistributable": False,   # honoured by report + RAG layers
                },
            )
        )
    return entries


def load(cis_dir: str | Path, *, latest_only: bool = True) -> Catalog:
    """Load every CIS benchmark PDF under ``cis_dir``.

    CIS keeps every historical version (Cisco alone ships 21 benchmarks, five
    of them IOS 16). ``latest_only`` keeps the highest version per
    product family, which is what a scan should cite. Plan 10.2 defence 5
    requires the chosen version to be pinned into the assessment record.
    """
    root = Path(cis_dir)
    pdfs = sorted(root.rglob("*.pdf"))

    if latest_only:
        best: dict[tuple[str, str], Path] = {}
        for p in pdfs:
            m = re.match(r"(.*?)_v?(\d+(?:\.\d+)*)\.pdf$", p.name, re.I)
            family = (p.parent.name, (m.group(1) if m else p.stem).lower())
            ver = tuple(int(x) for x in m.group(2).split(".")) if m else (0,)
            prev = best.get(family)
            if prev is None:
                best[family] = p
            else:
                pm = re.match(r"(.*?)_v?(\d+(?:\.\d+)*)\.pdf$", prev.name, re.I)
                pver = tuple(int(x) for x in pm.group(2).split(".")) if pm else (0,)
                if ver > pver:
                    best[family] = p
        pdfs = sorted(best.values())

    entries: list[CatalogEntry] = []
    sources: list[str] = []
    for p in pdfs:
        got = _parse_pdf(p, vendor=p.parent.name)
        if got:
            entries += got
            sources.append(str(p))

    return Catalog(framework=Framework.CIS, entries=entries, sources=sources)
