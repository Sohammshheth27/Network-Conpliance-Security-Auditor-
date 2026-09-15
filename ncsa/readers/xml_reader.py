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
pack author writing `system/services/ssh` should not have to know that.

REPEATED ELEMENTS ARE KEYED BY THEIR OWN IDENTITY
-------------------------------------------------
A list element's identity is folded into its path segment, so each item keeps
its own settings:

    PAN-OS   <entry name="rule-1">              -> entry[rule-1]
    Junos    <class><name>ops</name>            -> class[ops]
    Junos    <policy><from-zone-name>trust</..>
                     <to-zone-name>untrust</..> -> policy[trust>untrust]

Junos carries the name in a CHILD element rather than an attribute, and this
reader used to key only on attributes. Every <policy>, <class>, <user> and
<host> then shared one path: a policy graph built from it gave every rule the
first rule's action and the union of every rule's addresses, and refused
outright when a device had more than one zone pair.

Exact-path lookups stay backward compatible: `get`/`get_all` fall back to the
path with the keys removed, which returns the old collapsed view. Wildcard
`glob` patterns already match a keyed segment with its bare name.
"""
from __future__ import annotations

import re
from pathlib import Path

from ..schema.evidence import EvidenceRef

# `{urn:...}tag` -> `tag`
_NS = re.compile(r"^\{[^}]*\}")
_INDEX = re.compile(r"\[[^\]]*\]")


def _tag(el) -> str:
    return _NS.sub("", el.tag)


def _escape(ident: str) -> str:
    # An identity may contain the path separator: PAN-OS names interfaces
    # `ethernet1/1`, Junos names them `ge-0/0/0`. Encoding keeps the segment
    # atomic; `%2F` is the conventional escape and round-trips through unquote.
    return ident.replace("%", "%25").replace("/", "%2F").replace("]", "%5D")


class _Node:
    __slots__ = ("tag", "attrs", "line", "text", "children")

    def __init__(self, tag, attrs, line):
        self.tag, self.attrs, self.line = tag, attrs, line
        self.text: list = []
        self.children: list = []

    def leaf_text(self, tag: str) -> str | None:
        for c in self.children:
            if c.tag == tag and not c.children:
                t = "".join(c.text).strip()
                return t or None
        return None


class XmlConfig:
    """An XML config exposing the same contract as the other path readers."""

    def __init__(self, text: str, source_file: str):
        self.source_file = source_file
        self.lines = text.splitlines()
        self._consumed: set[int] = set()
        # path -> list[(value, lineno, raw)], in document order
        self._paths: dict[str, list] = {}
        # the same entries under the path with every [key] removed
        self._plain: dict[str, list] = {}
        # (line, raw) -> structural path, for EvidenceRef.record_id
        self._rec_of: dict = {}
        self._parse(text)

    # ------------------------------------------------------------------ parse
    def _parse(self, text: str) -> None:
        """Build a light tree with expat (for true line numbers), then walk it.

        Two passes because an element's key can depend on its CHILDREN -- a
        Junos <class> is named by the <name> inside it -- so its path is only
        known once the element has closed. expat reports `CurrentLineNumber`
        natively; ElementTree records no positions at all.
        """
        import xml.parsers.expat

        stack: list[_Node] = []
        root: list[_Node] = []
        p = xml.parsers.expat.ParserCreate(namespace_separator=None)

        def start(tag, attrs):
            n = _Node(_NS.sub("", tag),
                      {_NS.sub("", k): v for k, v in attrs.items()},
                      p.CurrentLineNumber)
            (stack[-1].children if stack else root).append(n)
            stack.append(n)

        def chars(data):
            if stack:
                stack[-1].text.append(data)

        def end(_tag):
            stack.pop()

        p.StartElementHandler = start
        p.EndElementHandler = end
        p.CharacterDataHandler = chars
        try:
            p.Parse(text.encode("utf-8", errors="replace"), True)
        except xml.parsers.expat.ExpatError as exc:
            raise ValueError(f"{self.source_file}: not well-formed XML ({exc})")

        for r in root:
            self._walk(r, [], is_root=True)

    @staticmethod
    def _segment(n: _Node) -> str:
        ident = n.attrs.get("name")
        if ident is None:
            ident = n.leaf_text("name")
        if ident is None:
            src, dst = n.leaf_text("from-zone-name"), n.leaf_text("to-zone-name")
            if src and dst:
                ident = f"{src}>{dst}"
        return f"{n.tag}[{_escape(ident)}]" if ident is not None else n.tag

    def _walk(self, n: _Node, prefix: list, *, is_root: bool = False) -> None:
        # The root element is not part of child paths (`system/...`, not
        # `rpc-reply/configuration/...` for its first level) but its own
        # attributes and text are addressed by its tag: `config/@version`.
        seg = n.tag if is_root else self._segment(n)
        segs = [] if is_root else prefix + [seg]
        own = "/".join(segs) or n.tag
        for k, v in n.attrs.items():
            if k == "name":
                continue
            self._add(f"{own}/@{k}", v, n.line, f"{n.tag} @{k}={v}")
        body = "".join(n.text).strip()
        if not n.children:
            if body:
                self._add(own, body, n.line, f"<{n.tag}>{body[:60]}</{n.tag}>")
            elif not is_root:
                # An empty element is a FLAG, not a missing value. Junos writes
                # `<telnet/>` to mean telnet is ENABLED; reading that as absent
                # inverts the meaning of every boolean expressed this way.
                self._add(own, "<present>", n.line, f"<{n.tag}/>")
            return
        for c in n.children:
            self._walk(c, segs)

    def _add(self, path: str, value: str, line: int, raw: str) -> None:
        entry = (value, line, raw)
        self._paths.setdefault(path, []).append(entry)
        self._plain.setdefault(_INDEX.sub("", path), []).append(entry)
        self._rec_of[(line, raw)] = path

    # -------------------------------------------------------------- accessors
    def get_all(self, path: str) -> list:
        return list(self._paths.get(path) or self._plain.get(path) or [])

    def get(self, path: str):
        hits = self._paths.get(path) or self._plain.get(path)
        if not hits:
            return None
        self._consumed.add(hits[0][1] - 1)
        return hits[0]

    def glob(self, pattern: str) -> list:
        """Wildcard path match. `*` spans one segment, and a keyed segment
        (`entry[name]`, `class[ops]`) matches its bare name so a pack need not
        know the keys."""
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

        `record_id` carries the structural path, so an XML finding cites both
        the line a human can scroll to AND the path a machine can re-query --
        a re-serialised export changes the line but not the path.
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

    def iter_paths(self) -> list:
        """Every path in DOCUMENT order -- rule order on a firewall matters."""
        return list(self._paths)


def load(path, **_kw) -> XmlConfig:
    p = Path(path)
    return XmlConfig(p.read_text(encoding="utf-8", errors="replace"), p.name)


def loads(text: str, source_file: str = "<string>") -> XmlConfig:
    return XmlConfig(text, source_file)
