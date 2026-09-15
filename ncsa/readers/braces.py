"""Reader 3 -- curly braces / set-lines (plan 4.1).

Vendors: Juniper Junos, Ubiquiti EdgeOS, VyOS.

Junos exports in TWO forms and both are common:

    hierarchical                        flat set-lines
    ------------                        --------------
    system {                            set system services ssh protocol-version v2
        services {                      set system services ssh root-login deny
            ssh {
                protocol-version v2;
            }
        }
    }

Plan 4.1 is explicit: **normalise both forms to the same path structure before
mapping.** Otherwise a pack would need two rules per field, and half of them
would silently never fire depending on how the operator happened to export.
Both forms here produce identical paths::

    system/services/ssh/protocol-version = v2

Output shape matches the block reader, so both share one pack applier.
"""
from __future__ import annotations

import re
from pathlib import Path

from ..schema.enums import RecordState
from ..schema.evidence import EvidenceRef

_SET_LINE = re.compile(r"^\s*set\s+(.+?)\s*;?\s*$")
_DELETE_LINE = re.compile(r"^\s*delete\s+(.+?)\s*;?\s*$")
_OPEN = re.compile(r"^\s*(\S+(?:\s+\S+)*?)\s*\{\s*$")
_CLOSE = re.compile(r"^\s*\}\s*$")
_LEAF = re.compile(r"^\s*(\S+)(?:\s+(.*?))?\s*;\s*$")

# Junos keywords whose leaf form is `<keyword> <object-name> <value>`.
# Restricted deliberately: promoting the second token on EVERY multi-token leaf
# would mangle ordinary settings like `permit tcp any any`.
_NAMED_LEAF_KEYS = {"address", "address-set", "application", "application-set",
                    "host", "server", "user", "prefix-list", "policer"}


def _strip_trailing_comment(raw: str) -> str:
    """Drop a trailing `## ...` annotation outside quotes.

    Junos prints `## SECRET-DATA` after every secret it displays:

        encrypted-password "$6$..."; ## SECRET-DATA

    The line grammar requires a statement to END in `;`, so every such line
    -- encrypted passwords, RADIUS secrets, NTP authentication keys -- was
    silently dropped and read as absent. A whole-line comment is left alone
    (it is skipped later); a `#` inside a quoted string is not a comment.
    """
    if "#" not in raw or raw.lstrip().startswith("#"):
        return raw
    quoted = False
    for idx, ch in enumerate(raw):
        if ch == '"':
            quoted = not quoted
        elif ch == "#" and not quoted and raw[idx:idx + 2] == "##":
            return raw[:idx].rstrip()
    return raw


def _statements(lines: list[str]):
    """Yield (line_index, statement), splitting a line that holds several.

    `class ops { idle-timeout 5; }` is valid Junos on one line. The line
    grammar expects one statement per line, so it matched neither a block
    opener nor a leaf and the setting was silently dropped -- read as absent,
    which a lockout or timeout control then reports as not configured.

    Splitting happens only when a brace shares its line with other content,
    respects double-quoted strings (`message "a; b { c }";`), and keeps the
    ORIGINAL line index so evidence still points at the line the user sees.
    """
    for i, raw in enumerate(lines):
        raw = _strip_trailing_comment(raw)
        s = raw.strip()
        if ("{" not in s and "}" not in s) or s.startswith(("#", "/*", "set ", "delete ")) \
                or re.fullmatch(r"[^{}]*\{|\}", s):
            yield i, raw
            continue
        buf, quoted = "", False
        for ch in s:
            if ch == '"':
                quoted = not quoted
            if not quoted and ch in "{};":
                piece = (buf + ch).strip()
                if piece and piece not in (";",):
                    yield i, piece
                buf = ""
            else:
                buf += ch
        if buf.strip():
            yield i, buf.strip()


class BracesConfig:
    """Parsed Junos-style config, both syntaxes normalised to one path map."""

    def __init__(self, text: str, source_file: str):
        self.text = text
        self.source_file = source_file
        self.lines = text.splitlines()
        self.values: dict[str, tuple[str, int, str]] = {}
        # Every occurrence of a repeated path. Junos writes sibling leaves with
        # the SAME key -- `address A 10.0.0.0/8;` then `address B 10.1.0.0/16;`
        # -- and a last-write-wins map silently kept one of them. A group whose
        # membership is under-reported produces a confident, wrong finding, so
        # duplicates accumulate here and `values` stays a convenience view.
        self.multi: dict[str, list[tuple[str, int, str]]] = {}
        self.form = "unknown"
        self._consumed: set[int] = set()
        self._open_depth: list[int] = []
        self._parse()

    def _parse(self) -> None:
        has_set = any(_SET_LINE.match(l) for l in self.lines)
        has_brace = any(_OPEN.match(l) for l in self.lines)
        self.form = ("set-lines" if has_set and not has_brace
                     else "hierarchical" if has_brace and not has_set
                     else "mixed" if has_set and has_brace else "unknown")

        stack: list[str] = []
        for i, raw in _statements(self.lines):
            s = raw.strip()
            if not s or s.startswith("#") or s.startswith("/*"):
                continue

            # --- flat form -------------------------------------------------
            if m := _SET_LINE.match(raw):
                tokens = m.group(1).split()
                if len(tokens) >= 3 and tokens[-3] in _NAMED_LEAF_KEYS:
                    # set ... address WEB01 10.10.20.50/32
                    self._record("/".join(tokens[:-1]), tokens[-1], i + 1, s)
                    continue
                if len(tokens) >= 2:
                    # Last token is the value UNLESS the statement is a flag
                    # (`set system services ssh`), in which case presence itself
                    # is the value.
                    path = "/".join(tokens[:-1])
                    value = tokens[-1].strip('"')
                    self._record(path, value, i + 1, s)
                    # also record the flag form so a pack can test presence
                    self._record("/".join(tokens), "", i + 1, s)
                else:
                    self._record(tokens[0], "", i + 1, s)
                continue

            if m := _DELETE_LINE.match(raw):
                self.values["/".join(m.group(1).split())] = ("<deleted>", i + 1, s)
                continue

            # --- hierarchical form -----------------------------------------
            if m := _OPEN.match(raw):
                # A Junos block header can carry an ARGUMENT naming the object:
                #     host 10.20.0.50 {      -> host / 10.20.0.50
                #     community public {     -> community / public
                # Keeping "host 10.20.0.50" as a single segment made every
                # wildcard path like system/syslog/host/* unmatchable, so
                # syslog servers and SNMP communities silently read as absent.
                header = m.group(1).strip().strip('"')
                stack.extend(part.strip('"') for part in header.split())
                self._open_depth.append(len(header.split()))
                continue
            if _CLOSE.match(raw):
                n = self._open_depth.pop() if self._open_depth else 1
                for _ in range(min(n, len(stack))):
                    stack.pop()
                continue
            if m := _LEAF.match(raw):
                key, val = m.group(1), (m.group(2) or "").strip().strip('"')
                parts = val.split()
                # A Junos leaf of the form `<keyword> <name> <value>` declares a
                # NAMED OBJECT: `address WEB01 10.10.20.50/32`. Promoting the
                # name into the path is both the correct data model and what
                # stops siblings colliding.
                if len(parts) >= 2 and key in _NAMED_LEAF_KEYS:
                    path = "/".join(stack + [key, parts[0]])
                    val = " ".join(parts[1:])
                else:
                    path = "/".join(stack + [key])
                self._record(path, val, i + 1, s)
                continue

    def _record(self, path: str, val: str, lineno: int, raw: str) -> None:
        entry = (val, lineno, raw)
        self.values[path] = entry
        self.multi.setdefault(path, []).append(entry)

    def get_all(self, path: str) -> list[tuple[str, int, str]]:
        """Every occurrence of a repeated path, in file order."""
        if path in self.multi:
            return self.multi[path]
        tail = "/" + path
        cands = [p for p in self.multi if p.endswith(tail)]
        return self.multi[cands[0]] if len(cands) == 1 else []

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
        for path, entries in self.multi.items():
            if rx.match(path):
                for val, ln, raw in entries:
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
            for path, entries in self.multi.items():
                if rx2.match(path):
                    for val, ln, raw in entries:
                        out.append((path, val, ln, raw))
                        self._consumed.add(ln - 1)
        return out

    def has(self, path: str) -> bool:
        return path in self.values

    # --------------------------------------------------------------- evidence
    def evidence(self, lineno: int, raw: str) -> EvidenceRef:
        return EvidenceRef(file=self.source_file, line=lineno, raw=raw.strip())

    # ------------------------------------------------------------- accounting
    @property
    def significant_lines(self) -> list[int]:
        out = []
        for i, ln in enumerate(self.lines):
            s = ln.strip()
            # Block openers and closers are STRUCTURE, not configuration.
            # Their content is captured in the paths they scope, so counting
            # them as unread lines understates coverage the same way counting
            # `!` would on Cisco.
            if (not s or s.startswith("#") or s.startswith("/*")
                    or s in ("}", "{") or _OPEN.match(s)):
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


def load(path: str | Path) -> BracesConfig:
    p = Path(path)
    return BracesConfig(p.read_text(encoding="utf-8", errors="replace"), p.name)


def loads(text: str, source_file: str = "<string>") -> BracesConfig:
    return BracesConfig(text, source_file)
