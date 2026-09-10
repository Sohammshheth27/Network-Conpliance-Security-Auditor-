"""Reader 2 -- Fortinet block format (plan 4.1).

Vendors: Fortinet FortiOS, SonicWall SonicOS (CLI export).

Shape::

    config system global
        set admin-scp enable
        set admintimeout 10
    end

    config firewall policy
        edit 1
            set srcintf "port1"
            set action accept
        next
    end

Custom lexer, ~80 lines, no dependency. `config` opens a section, `edit` opens a
numbered/named entry inside it, `set` assigns, `next` closes an entry, `end`
closes a section.

Output shape is a PATH -> VALUE map, identical in form to what the braces reader
produces, so one pack applier serves both. Paths look like::

    system global/admintimeout
    firewall policy/1/action
"""
from __future__ import annotations

import re
from pathlib import Path

from ..schema.enums import RecordState
from ..schema.evidence import EvidenceRef

_CONFIG = re.compile(r"^\s*config\s+(.+?)\s*$", re.I)
_EDIT = re.compile(r"^\s*edit\s+\"?(.+?)\"?\s*$", re.I)
_SET = re.compile(r"^\s*set\s+(\S+)\s*(.*)$", re.I)
_UNSET = re.compile(r"^\s*unset\s+(\S+)\s*$", re.I)
_END = re.compile(r"^\s*end\s*$", re.I)
_NEXT = re.compile(r"^\s*next\s*$", re.I)


class BlockConfig:
    """Parsed block config: path -> (value, lineno, raw)."""

    def __init__(self, text: str, source_file: str):
        self.text = text
        self.source_file = source_file
        self.lines = text.splitlines()
        self.values: dict[str, tuple[str, int, str]] = {}
        self._consumed: set[int] = set()
        self._parse()

    def _parse(self) -> None:
        stack: list[str] = []
        for i, raw in enumerate(self.lines):
            line = raw.rstrip()
            s = line.strip()
            if not s or s.startswith("#"):
                continue

            if m := _CONFIG.match(line):
                stack.append(m.group(1).strip().strip('"'))
                continue
            if m := _EDIT.match(line):
                stack.append(m.group(1).strip())
                continue
            if _NEXT.match(line) or _END.match(line):
                if stack:
                    stack.pop()
                continue
            if m := _SET.match(line):
                key = m.group(1)
                val = m.group(2).strip()
                # FortiOS quotes strings and space-separates multi-values
                val = val.strip().strip('"') if val.count('"') == 2 else val
                path = "/".join(stack + [key])
                self.values[path] = (val, i + 1, s)
                continue
            if m := _UNSET.match(line):
                path = "/".join(stack + [m.group(1)])
                self.values[path] = ("", i + 1, s)
                continue

    # ------------------------------------------------------------------ query
    def get(self, path: str) -> tuple[str, int, str] | None:
        """Exact path lookup, falling back to an UNAMBIGUOUS suffix match.

        Vendors wrap their exports differently depending on export scope: a
        full SonicWall backup nests everything under `config sonicos` while a
        section export does not, so `administration/http-management` and
        `sonicos/administration/http-management` are the same setting. Hard-
        coding one prefix into the pack would make it fail on the other export
        mode -- precisely the brittleness the problem statement complains about.

        The fallback fires ONLY when exactly one stored path ends with the
        requested one. Two candidates means the request is genuinely ambiguous,
        and guessing between them would be how a wrong value enters an audit.
        """
        hit = self.values.get(path)
        if hit is None:
            tail = "/" + path
            cands = [p for p in self.values if p.endswith(tail)]
            if len(cands) == 1:
                hit = self.values[cands[0]]
        if hit:
            self._consumed.add(hit[1] - 1)
        return hit

    def glob(self, pattern: str) -> list[tuple[str, str, int, str]]:
        """Wildcard path lookup: ``firewall policy/*/action``.

        Returns [(path, value, lineno, raw)].
        """
        # A TRAILING wildcard matches the remainder of the path, not just one
        # segment: `system/syslog/host/*` must reach
        # `system/syslog/host/10.20.0.50/any`, because Junos nests the object's
        # own settings beneath the name we are scoping by. An interior `*`
        # still matches exactly one segment.
        esc = re.escape(pattern)
        if esc.endswith(r"/\*"):
            body = esc[:-3].replace(r"\*", "[^/]+")
            rx = re.compile("^" + body + "/[^/]+(?:/.*)?$")
        else:
            rx = re.compile("^" + esc.replace(r"\*", "[^/]+") + "$")
        out = []
        for path, (val, ln, raw) in self.values.items():
            if rx.match(path):
                out.append((path, val, ln, raw))
                self._consumed.add(ln - 1)
        if not out:
            # same unambiguous-suffix tolerance as get()
            esc2 = re.escape(pattern)
            if esc2.endswith(r"/\*"):
                body2 = esc2[:-3].replace(r"\*", "[^/]+")
                rx2 = re.compile("^.*/" + body2 + "/[^/]+(?:/.*)?$")
            else:
                rx2 = re.compile("^.*/" + esc2.replace(r"\*", "[^/]+") + "$")
            for path, (val, ln, raw) in self.values.items():
                if rx2.match(path):
                    out.append((path, val, ln, raw))
                    self._consumed.add(ln - 1)
        return out

    # --------------------------------------------------------------- evidence
    def evidence(self, lineno: int, raw: str) -> EvidenceRef:
        return EvidenceRef(file=self.source_file, line=lineno, raw=raw.strip())

    # ------------------------------------------------------------- accounting
    @property
    def significant_lines(self) -> list[int]:
        out = []
        for i, ln in enumerate(self.lines):
            s = ln.strip()
            # Structural keywords carry no configuration value of their own;
            # counting them would inflate the denominator and flatter coverage.
            if not s or s.startswith("#") or _END.match(s) or _NEXT.match(s):
                continue
            out.append(i)
        return out

    @property
    def total_records(self) -> int:
        return len(self.significant_lines)

    def accounting_snapshot(self) -> dict[str, int]:
        sig = set(self.significant_lines)
        consumed = len(self._consumed & sig)
        return {RecordState.PARSED.value: consumed,
                RecordState.UNKNOWN.value: len(sig) - consumed}

    def unrecognised(self) -> list[EvidenceRef]:
        sig = set(self.significant_lines)
        return [self.evidence(i + 1, self.lines[i]) for i in sorted(sig - self._consumed)]


def load(path: str | Path) -> BlockConfig:
    p = Path(path)
    return BlockConfig(p.read_text(encoding="utf-8", errors="replace"), p.name)


def loads(text: str, source_file: str = "<string>") -> BlockConfig:
    return BlockConfig(text, source_file)
