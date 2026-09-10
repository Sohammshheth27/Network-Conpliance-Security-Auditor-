"""Which grammar is this file written in? Answered structurally, not by name.

`engine/fingerprint.py` matches vendor SIGNATURES -- `version 17.9`, `## Last
commit`. That works only for vendors we have already met; an IBM or SONiC file
returns UNKNOWN with no reader, and nothing downstream can even choose a
parser.

Shape survives where signatures do not. Braces-and-semicolons is Junos-like
whatever the badge on the box says, and `config X / set Y / end` is block-
structured whether it came from Fortinet or something nobody here has seen.
Each rule below scores a property of the TEXT, never a vendor string.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field


@dataclass
class Grammar:
    reader: str
    confidence: float
    evidence: list = field(default_factory=list)

    def __repr__(self) -> str:
        return f"<Grammar {self.reader} {self.confidence:.2f}>"


def _lines(text: str) -> list[str]:
    return [l for l in text.splitlines() if l.strip()]


def detect_grammar(text: str) -> list[Grammar]:
    """Rank the reader families this text could belong to."""
    out: list[Grammar] = []
    lines = _lines(text)
    n = max(len(lines), 1)

    # ---- JSON -------------------------------------------------------------
    stripped = text.lstrip()
    if stripped[:1] in "{[":
        try:
            json.loads(text)
            out.append(Grammar("json", 1.0, ["parses as JSON"]))
        except Exception:                              # noqa: BLE001
            pass

    # ---- XML --------------------------------------------------------------
    if re.match(r"^\s*<\?xml|^\s*<[A-Za-z]", text):
        tags = len(re.findall(r"<[A-Za-z/][^>]*>", text))
        if tags > 10:
            out.append(Grammar("xml", min(1.0, tags / 200),
                               [f"{tags} XML tags"]))

    # ---- key=value, one flat blob (SonicOS .exp shape) --------------------
    kv = len(re.findall(r"[A-Za-z_][A-Za-z0-9_]{2,}=", text))
    if kv > 50 and text.count("\n") < kv / 10:
        out.append(Grammar("keyvalue", min(1.0, kv / 500),
                           [f"{kv} key=value pairs, few newlines"]))

    # ---- braces (Junos-like) ----------------------------------------------
    open_braces = sum(1 for l in lines if l.rstrip().endswith("{"))
    semis = sum(1 for l in lines if l.rstrip().endswith(";"))
    if open_braces > 2 and semis > 2:
        out.append(Grammar("braces", min(1.0, (open_braces + semis) / n),
                           [f"{open_braces} lines end '{{'", f"{semis} end ';'"]))

    # ---- block (config/set/end, edit/next) --------------------------------
    cfg = sum(1 for l in lines if re.match(r"^\s*config\s+\S", l, re.I))
    setl = sum(1 for l in lines if re.match(r"^\s*set\s+\S", l, re.I))
    end = sum(1 for l in lines if re.match(r"^\s*(end|next)\s*$", l, re.I))
    if cfg and end:
        out.append(Grammar("fortinet_block", min(1.0, (cfg + end) / n * 3),
                           [f"{cfg} 'config' blocks", f"{end} 'end'/'next'",
                            f"{setl} 'set' statements"]))

    # ---- indented (Cisco-like hierarchy) ----------------------------------
    indented = sum(1 for l in lines if l[:1] in " \t" and l.strip())
    if indented > 2 and open_braces == 0:
        # A leading-space hierarchy with no braces and no `config/end` scaffold.
        out.append(Grammar("indented", min(1.0, 0.3 + indented / n),
                           [f"{indented}/{n} lines indented, no braces"]))

    # ---- menu / path style (`/cfg/sys/ssh/on`) ----------------------------
    paths = sum(1 for l in lines if re.match(r"^\s*/[a-z]+(/[a-z0-9_-]+){2,}", l, re.I))
    if paths > 2:
        out.append(Grammar("pathstyle", min(1.0, paths / n * 2),
                           [f"{paths} '/a/b/c' style lines"]))

    # A flat file of `keyword argument` lines with no structure at all still
    # parses as `indented` with low confidence -- better than refusing, and the
    # confidence is what tells a reviewer to look.
    if not out:
        out.append(Grammar("indented", 0.15, ["no structural markers found"]))

    out.sort(key=lambda g: -g.confidence)
    return out
