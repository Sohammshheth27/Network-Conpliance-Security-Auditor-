"""Reader 5 -- JSON (plan 4.1).

Vendors: AWS Security Groups, Azure NSG, GCP Firewall Rules, SONiC config_db.

Plan 4.1 calls this the cheapest reader, and it is: the data is already
structured, so there is no parsing problem, only a mapping problem. Build it
first.

Two things this reader must get right anyway:

  * **Evidence.** A JSON document has no line numbers in the useful sense, so
    evidence carries the JSONPath as ``record_id`` plus a compact rendering of
    the matched node as ``raw``. Plan 14.3 still applies -- a FAIL without
    traceable evidence is not a finding.
  * **Accounting.** Plan 14.1's invariant is about *source records*, not lines.
    For JSON we count leaf nodes, so "no silent loss" still means something.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..schema.enums import RecordState
from ..schema.evidence import EvidenceRef


class JsonDocument:
    """A loaded JSON config plus the accounting needed by plan 14.1."""

    def __init__(self, data: Any, source_file: str):
        self.data = data
        self.source_file = source_file
        self._leaf_paths = set(_leaf_paths(data))
        self._leaves = len(self._leaf_paths)
        self.consumed_paths: set[str] = set()
        self.consumed_leaves: set[str] = set()

    # ------------------------------------------------------------------ query
    def query(self, expr: str, *, count: bool = True) -> list[tuple[str, Any]]:
        """Run a JSONPath expression. Returns [(full_path, value), ...]."""
        from jsonpath_ng.ext import parse

        try:
            jp = parse(expr)
        except Exception as exc:  # a malformed pack expression is a pack bug
            raise ValueError(f"invalid JSONPath {expr!r}: {exc}") from exc

        out: list[tuple[str, Any]] = []
        for m in jp.find(self.data):
            # jsonpath_ng renders nested paths wrapped in parentheses --
            # "([0].GroupId)" -- which never matches our own leaf addressing.
            # Normalise before any comparison.
            path = str(m.full_path).replace("(", "").replace(")", "")
            self.consumed_paths.add(path)
            if count:
                # Mark the actual leaves under this node. Counting whole
                # subtrees as "consumed" made coverage read 100% on every file,
                # which would defeat the point of plan 14.1 -- the number exists
                # to reveal what we did NOT read.
                self.consumed_leaves.update(
                    lp for lp in self._leaf_paths if lp == path or lp.startswith(path + ".") or lp.startswith(path + "[")
                )
            out.append((path, m.value))
        return out

    def first(self, expr: str, default: Any = None) -> Any:
        hits = self.query(expr)
        return hits[0][1] if hits else default

    # --------------------------------------------------------------- evidence
    def evidence(self, path: str, value: Any) -> EvidenceRef:
        return EvidenceRef(
            file=self.source_file,
            line=None,                 # JSON has no meaningful line for a node
            raw=_render(value),
            record_id=path,            # the JSONPath IS the location
        )

    # ------------------------------------------------------------- accounting
    @property
    def total_records(self) -> int:
        return self._leaves

    def accounting_snapshot(self) -> dict[str, int]:
        """Leaves a mapping actually read, vs leaves nothing ever looked at.

        Plan 14.1: TOTAL == PARSED + MAPPED + QUARANTINED + UNKNOWN. Only
        field mappings count as reading a leaf; derivations analyse structure
        and deliberately do not (they pass count=False), otherwise a single
        ``$[*]`` scan would mark the whole file consumed and the coverage
        figure would always be 100%.
        """
        consumed = len(self.consumed_leaves)
        return {
            RecordState.PARSED.value: consumed,
            RecordState.UNKNOWN.value: max(self._leaves - consumed, 0),
        }

    def unread_paths(self) -> list[str]:
        """Leaves nothing in the pack ever read -- the 14.5 appendix."""
        return sorted(self._leaf_paths - self.consumed_leaves)


def load(path: str | Path) -> JsonDocument:
    p = Path(path)
    # encoding is explicit everywhere: Windows Python defaults to cp1252 and
    # config exports routinely carry non-ASCII in descriptions and tags.
    with p.open(encoding="utf-8") as fh:
        data = json.load(fh)
    return JsonDocument(data, p.name)


def loads(text: str, source_file: str = "<string>") -> JsonDocument:
    return JsonDocument(json.loads(text), source_file)


# ---------------------------------------------------------------- internals
def _count_leaves(node: Any) -> int:
    if isinstance(node, dict):
        return sum(_count_leaves(v) for v in node.values()) or 1
    if isinstance(node, list):
        return sum(_count_leaves(v) for v in node) or 1
    return 1


def _leaf_paths(node: Any, prefix: str = "") -> list[str]:
    """Every scalar position in the document, addressed like jsonpath_ng does."""
    if isinstance(node, dict):
        if not node:
            return [prefix or "$"]
        out = []
        for k, v in node.items():
            out += _leaf_paths(v, f"{prefix}.{k}" if prefix else k)
        return out
    if isinstance(node, list):
        if not node:
            return [prefix or "$"]
        out = []
        for i, v in enumerate(node):
            out += _leaf_paths(v, f"{prefix}.[{i}]" if prefix else f"[{i}]")
        return out
    return [prefix or "$"]


def _render(value: Any, limit: int = 300) -> str:
    if isinstance(value, (dict, list)):
        s = json.dumps(value, separators=(",", ":"))
    else:
        s = str(value)
    return s if len(s) <= limit else s[: limit - 3] + "..."


def _resolve(data: Any, dotted: str) -> Any:
    """Best-effort walk of a jsonpath_ng full_path string."""
    import re

    node = data
    for part in re.findall(r"\[(\d+)\]|([^.\[\]]+)", dotted):
        idx, key = part
        try:
            node = node[int(idx)] if idx else node[key]
        except (KeyError, IndexError, TypeError):
            return None
    return node
