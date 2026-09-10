"""Reader 1 -- indented blocks (plan 4.1).

Vendors: Cisco IOS / IOS-XE / NX-OS, Arista EOS, HPE Aruba AOS-CX.

Shape: a parent line at column 0, children indented by whitespace.

    line vty 0 4
     transport input ssh
     exec-timeout 10 0

Library: ciscoconfparse2 (plan 11.3 -- saves roughly a week).

The thing this reader must get right is SCOPE. Plan 2.3.1 is explicit:
``transport input ssh`` under ``line vty`` means something different from the
same line under ``line con``. A flat regex sweep over the file would conflate
them and produce a confident, wrong answer -- so every child match carries the
parent it was found under.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterator

from ..schema.enums import RecordState
from ..schema.evidence import EvidenceRef


class IndentedConfig:
    """A parsed indented configuration plus plan 14.1 accounting."""

    def __init__(self, text: str, source_file: str):
        from ciscoconfparse2 import CiscoConfParse

        self.text = text
        self.source_file = source_file
        self.lines = text.splitlines()
        self.parse = CiscoConfParse(self.lines, syntax="ios")
        self._consumed: set[int] = set()

    # ------------------------------------------------------------------ query
    def find(self, regex: str) -> list[tuple[int, str]]:
        """Top-level (or any) lines matching a regex. Returns [(lineno, text)]."""
        out = []
        for obj in self.parse.find_objects(regex):
            out.append((obj.linenum + 1, obj.text))
            self._consumed.add(obj.linenum)
        return out

    def find_children(self, parent_regex: str, child_regex: str) -> list[tuple[str, int, str]]:
        """Children matching ``child_regex`` under parents matching ``parent_regex``.

        Returns [(parent_text, lineno, child_text)] -- the parent comes back so
        the caller can scope the resulting SBM path.
        """
        out = []
        for parent in self.parse.find_objects(parent_regex):
            self._consumed.add(parent.linenum)
            for child in parent.children:
                if re.search(child_regex, child.text):
                    out.append((parent.text.strip(), child.linenum + 1, child.text))
                    self._consumed.add(child.linenum)
        return out

    def parents(self, parent_regex: str) -> list[tuple[int, str, list[str]]]:
        out = []
        for parent in self.parse.find_objects(parent_regex):
            self._consumed.add(parent.linenum)
            kids = []
            for c in parent.children:
                kids.append(c.text)
                self._consumed.add(c.linenum)
            out.append((parent.linenum + 1, parent.text, kids))
        return out

    # --------------------------------------------------------------- evidence
    def evidence(self, lineno: int, raw: str) -> EvidenceRef:
        return EvidenceRef(file=self.source_file, line=lineno, raw=raw.strip())

    # ------------------------------------------------------------- accounting
    @property
    def significant_lines(self) -> list[int]:
        """Lines that carry configuration. Blank lines and bare ``!`` do not.

        Counting decoration would inflate the denominator and make coverage
        look better than it is -- the opposite of what plan 14.1 is for.
        """
        out = []
        for i, ln in enumerate(self.lines):
            s = ln.strip()
            if not s or s == "!" or s.startswith("!"):
                continue
            out.append(i)
        return out

    @property
    def total_records(self) -> int:
        return len(self.significant_lines)

    def accounting_snapshot(self) -> dict[str, int]:
        sig = set(self.significant_lines)
        consumed = len(self._consumed & sig)
        # PARSED and MAPPED are distinct fates (plan 14.1). ciscoconfparse
        # reads every significant line into the tree, so all of them are
        # PARSED; only the ones a mapping matched are MAPPED.
        return {
            RecordState.MAPPED.value: consumed,
            RecordState.PARSED.value: len(sig) - consumed,
            RecordState.UNKNOWN.value: 0,
        }

    def unrecognised(self) -> list[EvidenceRef]:
        """Lines no mapping rule touched -- these feed the AI helper (plan 3b)."""
        sig = set(self.significant_lines)
        return [
            self.evidence(i + 1, self.lines[i])
            for i in sorted(sig - self._consumed)
        ]


def load(path: str | Path) -> IndentedConfig:
    p = Path(path)
    # errors="replace": a production config can carry stray bytes in a banner
    # or description. Refusing to parse the whole device over one bad byte is
    # worse than flagging that line -- and plan 14.1 will still count it.
    text = p.read_text(encoding="utf-8", errors="replace")
    return IndentedConfig(text, p.name)


def loads(text: str, source_file: str = "<string>") -> IndentedConfig:
    return IndentedConfig(text, source_file)
