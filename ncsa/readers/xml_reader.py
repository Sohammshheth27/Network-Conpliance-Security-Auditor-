"""Reader 4: XML configuration exports.

This is the structured-input tier, and it matters more than it looks. A CLI
config has to be understood before it can be read -- indentation, context
stacks, `no` prefixes, line continuations, per-firmware spelling drift. An XML
export has already been parsed by the device that wrote it: the hierarchy is
explicit, values are attributes or text, and there is no ambiguity left to
resolve. Accuracy at this tier is a mapping problem, not a parsing problem.

Two vendors in the brief publish exactly this, and both are first-class:

    PAN-OS      the running config IS XML -- `<config><devices>...`
    Junos       `show configuration | display xml` emits `<rpc-reply>`

The path syntax is the same slash-separated one the braces and block readers
use, so the packs, `apply_path_pack`, the accounting and the evidence anchors
all work unchanged:

    devices/entry/deviceconfig/system/service/disable-telnet
    system/services/ssh/protocol-version

Namespaces are stripped. Junos wraps its output in the JUNOS namespace, and a
pack author writing `system/services/ssh` should not have to know that. Two
elements that differ only by namespace are vanishingly rare in device configs
and would be a poor trade for making every path unreadable.

`entry` elements are the vendor's list idiom (PAN-OS names every rule, zone and
address object with `<entry name="...">`). The `name` attribute is folded into
the path, so a pack can address one rule by name rather than by position --
position changes when a rule is inserted, and a mapping keyed on it would
silently start reading a different rule.
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path

from ..schema.evidence import EvidenceRef

# `{urn:...}tag` -> `tag`
_NS = re.compile(r"^\{[^}]*\}")


def _tag(el) -> str:
    return _NS.sub("", el.tag)


class XmlConfig:
    """An XML config exposing the same contract as the other path readers."""

    def __init__(self, text: str, source_file: str):
        self.source_file = source_file
        self.lines = text.splitlines()
        self._consumed: set[int] = set()
        # path -> list[(value, lineno, raw)]
        self._paths: dict[str, list] = {}
        # (line, raw) -> structural path, for EvidenceRef.record_id
        self._rec_of: dict = {}
        self._parse(text)

    # ------------------------------------------------------------------ parse
    def _parse(self, text: str) -> None:
        """Streamed with expat, for the line numbers.

        ElementTree does not record source positions, and the documented
        recipe for adding them (overriding `XMLParser._start`) is silently
        inert on CPython's C accelerator -- the hook is never called, so every
        element reported line 1.

        The first attempt instead indexed the first textual occurrence of each
        tag name. That collapsed repeated elements: both `<host><name>` entries
        in a Junos syslog block cited the same line, so the evidence for the
        SECOND syslog server pointed at the FIRST. Evidence that points at the
        wrong line is worse than none -- a reviewer checks it, sees a different
        value, and stops trusting every other finding in the report.

        expat reports `CurrentLineNumber` natively, and since this reader
        builds a flat path map rather than a tree, the parser is all we need.
        """
        import xml.parsers.expat

        trail: list = []
        text_buf: list = []
        # Elements that turned out to have children are not flags; the buffer
        # lets us decide that only when the element closes.
        has_child: list = []

        p = xml.parsers.expat.ParserCreate(namespace_separator=None)

        def start(tag, attrs):
            tag = _NS.sub("", tag)
            if has_child:
                has_child[-1] = True
            ident = attrs.get("name")
            if ident is not None:
                # An entry name may legitimately contain the path separator.
                # PAN-OS names every interface `ethernet1/1` and every address
                # `81.81.0.1/24`, so folding the raw name in split
                # `entry[ethernet1/1]` into `entry[ethernet1` + `1]` and
                # mangled the path of every interface and every IP on the
                # device. Encoding keeps the segment atomic; `%2F` is the
                # conventional escape and round-trips through `unquote`.
                ident = ident.replace("%", "%25").replace("/", "%2F")
            trail.append((f"{tag}[{ident}]" if ident else tag,
                          p.CurrentLineNumber, tag))
            has_child.append(False)
            text_buf.append([])
            path = self._path(trail)
            for k, v in attrs.items():
                k = _NS.sub("", k)          # attributes carry namespaces too
                if k == "name":
                    continue
                self._add(f"{path}/@{k}", v, p.CurrentLineNumber,
                          f"{tag} @{k}={v}")

        def chars(data):
            if text_buf:
                text_buf[-1].append(data)

        def end(_tag):
            seg, line, name = trail[-1]
            body = "".join(text_buf.pop()).strip()
            had_children = has_child.pop()
            path = self._path(trail)
            if body and not had_children:
                self._add(path, body, line, f"<{name}>{body[:60]}</{name}>")
            elif not body and not had_children:
                # An empty element is a FLAG, not a missing value. Junos writes
                # `<telnet/>` to mean telnet is ENABLED; reading that as absent
                # inverts the meaning of every boolean the vendor expresses
                # this way, which is most of them.
                self._add(path, "<present>", line, f"<{name}/>")
            trail.pop()

        p.StartElementHandler = start
        p.EndElementHandler = end
        p.CharacterDataHandler = chars
        try:
            p.Parse(text.encode("utf-8", errors="replace"), True)
        except xml.parsers.expat.ExpatError as exc:
            raise ValueError(f"{self.source_file}: not well-formed XML ({exc})")

    @staticmethod
    def _path(trail) -> str:
        return "/".join(seg for seg, _l, _n in trail[1:]) or (
            trail[0][0] if trail else "")

    def _add(self, path: str, value: str, line: int, raw: str) -> None:
        self._paths.setdefault(path, []).append((value, line, raw))
        self._rec_of[(line, raw)] = path

    # -------------------------------------------------------------- accessors
    def get_all(self, path: str) -> list:
        return list(self._paths.get(path, []))

    def get(self, path: str):
        hits = self._paths.get(path)
        if not hits:
            return None
        self._consumed.add(hits[0][1] - 1)
        return hits[0]

    def glob(self, pattern: str) -> list:
        """Wildcard path match. `*` spans one segment, and an indexed segment
        (`entry[name]`) matches a bare `*` so a pack need not know the names."""
        rx = re.compile(
            "^" + "/".join(
                r"[^/]+" if seg == "*" else re.escape(seg) + r"(\[[^\]]*\])?"
                for seg in pattern.split("/")) + "$")
        out = []
        for path, hits in self._paths.items():
            if not rx.match(path):
                continue
            for value, line, raw in hits:
                self._consumed.add(line - 1)
                out.append((path, value, line, raw))
        return out

    def evidence(self, lineno: int, raw: str) -> EvidenceRef:
        """Anchor a finding back into the export.

        `record_id` exists on EvidenceRef for exactly this -- "structural path
        for non-line formats" -- so an XML finding cites both the line a human
        can scroll to AND the path a machine can re-query. A line number alone
        is fragile here: an XML export is often re-serialised with different
        whitespace, and the path survives that where the line does not.
        """
        return EvidenceRef(file=self.source_file, line=lineno,
                           raw=raw.strip()[:200],
                           record_id=self._rec_of.get((lineno, raw)))

    # ------------------------------------------------------------- accounting
    @property
    def significant_lines(self) -> list:
        return [i + 1 for i, l in enumerate(self.lines)
                if l.strip() and not l.strip().startswith("<!--")]

    @property
    def total_records(self) -> int:
        """Records are ELEMENTS, not lines. An XML export is frequently one
        very long line, and counting lines there would report a 40,000-element
        config as a single record."""
        return sum(len(v) for v in self._paths.values())

    def accounting_snapshot(self) -> dict:
        from ..schema.enums import RecordState
        mapped = len(self._consumed)
        return {RecordState.MAPPED.value: mapped,
                RecordState.PARSED.value: max(self.total_records - mapped, 0),
                RecordState.UNKNOWN.value: 0}

    def unrecognised(self, limit: int = 500) -> list:
        out = []
        for path, hits in self._paths.items():
            for value, line, raw in hits:
                if line - 1 not in self._consumed:
                    out.append(self.evidence(line, f"{path}={value}"))
        return out[:limit]

    @property
    def paths(self) -> list:
        return sorted(self._paths)


def load(path, **_kw) -> XmlConfig:
    p = Path(path)
    return XmlConfig(p.read_text(encoding="utf-8", errors="replace"), p.name)


def loads(text: str, source_file: str = "<string>") -> XmlConfig:
    return XmlConfig(text, source_file)
