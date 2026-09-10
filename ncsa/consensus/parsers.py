"""Parser-level cross-check: two implementations reading the same file.

The consensus we already had compares two METHODS (a pack mapping against a
vendor-agnostic detector) on the same device. This compares two PARSERS on the
same syntax, which catches a different class of error entirely -- one where
both methods agree because they are reading the same wrong tree.

WHY JUNOS SPECIFICALLY. `readers/braces.py` is hand-written, and it produced
four separate bugs during this project: block-header arguments kept as one
segment, repeated leaf keys overwriting each other, `default-policy permit-all`
hardcoded as deny (a false PASS), and a Junos grammar recalled wrongly in four
places. Every one was found by reading a real config and noticing, which is not
a repeatable process.

`ciscoconfparse2` ships a `junos` syntax written by other people. Running both
and comparing turns "somebody noticed" into a test.

WHAT IS AND IS NOT A DISAGREEMENT
The two produce different path VOCABULARIES -- ours records `a/b/c` for a leaf
with a value, theirs flattens the tree its own way -- so raw path-count
differences are noise and are not reported. What matters is narrower and
decidable: for every path a MAPPING PACK actually reads, do both parsers find
it? A path our packs never consult is not worth a finding, and a path we find
that the library does not may simply be a representation difference.

A disagreement here does not say which parser is right. It says one of them is
wrong about a real device, which is the only thing worth interrupting a human
for.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ParserAgreement:
    checked: bool = False
    reason: str = ""
    ours: int = 0
    theirs: int = 0
    pack_paths_checked: int = 0
    both_found: list = field(default_factory=list)
    only_ours: list = field(default_factory=list)
    only_theirs: list = field(default_factory=list)

    @property
    def agrees(self) -> bool:
        """Agreement requires something to have been agreed ON.

        Without the `both_found` term this returned True for a config where
        NEITHER parser found any path a pack reads -- vacuous agreement
        reported as a positive result, which is the same shape as every other
        empty-answer-as-clean-bill-of-health this project has caught.
        """
        return (self.checked and bool(self.both_found)
                and not (self.only_ours or self.only_theirs))

    @property
    def comparable(self) -> bool:
        """Was there any shared coverage to compare at all?"""
        return self.checked and bool(self.both_found)

    def summary(self) -> dict:
        return {"checked": self.checked, "reason": self.reason,
                "our_paths": self.ours, "library_paths": self.theirs,
                "pack_paths_checked": self.pack_paths_checked,
                "agreed": len(self.both_found),
                "only_ours": len(self.only_ours),
                "only_library": len(self.only_theirs)}

    def explain(self) -> str:
        if not self.checked:
            return f"parser cross-check not run: {self.reason}"
        if not self.comparable:
            return (f"nothing to compare: neither parser found any of the "
                    f"{self.pack_paths_checked} path(s) our packs read in this "
                    "file. That is a fact about the config, not agreement "
                    "between the parsers.")
        if self.agrees:
            return (f"two independent parsers agree on all "
                    f"{len(self.both_found)} shared path(s), of "
                    f"{self.pack_paths_checked} the packs read")
        out = [f"PARSER DISAGREEMENT on {len(self.only_ours) + len(self.only_theirs)}"
               f" of {self.pack_paths_checked} pack path(s):"]
        for p in self.only_ours[:8]:
            out.append(f"   only OUR reader found : {p}")
        for p in self.only_theirs[:8]:
            out.append(f"   only ciscoconfparse2  : {p}")
        out.append("   One of the two is wrong about this device. Neither is "
                   "assumed correct.")
        return "\n".join(out)


def _library_paths(text: str) -> set:
    """Leaf paths as ciscoconfparse2's junos mode sees them."""
    from ciscoconfparse2 import CiscoConfParse

    parse = CiscoConfParse(text.splitlines(), syntax="junos")

    def walk(obj, trail):
        seg = obj.text.strip().rstrip(";").strip()
        trail = trail + [seg]
        if not obj.children:
            yield "/".join(trail)
        for child in obj.children:
            yield from walk(child, trail)

    out: set = set()
    for obj in parse.find_objects(r".*"):
        if obj.parent is obj:               # roots only; walk() does the rest
            out.update(walk(obj, []))
    return out


def _pack_paths(platform="juniper_srx", packs_dir="packs") -> set:
    """The paths a mapping pack actually reads. The only ones worth comparing."""
    from ..pipeline import load_packs

    out: set = set()
    for p in load_packs(packs_dir):
        if p.platform != platform:
            continue
        for m in p.mappings:
            if m.path:
                out.add(m.path.split("*")[0].rstrip("/"))
    return out


def _found_by(paths: set, prefix: str) -> bool:
    """Does either vocabulary contain this pack path?

    Prefix matching, because the two parsers spell leaves differently: ours
    records `system/services/ssh/protocol-version`, the library may stop at
    `system/services/ssh/protocol-version v2`. Requiring exact equality would
    report a disagreement on every single path and mean nothing.
    """
    return any(p == prefix or p.startswith(prefix + "/") or p.startswith(prefix)
               for p in paths)


def crosscheck_braces(config_path, platform="juniper_srx") -> ParserAgreement:
    """Compare our braces reader with ciscoconfparse2 on one Junos config."""
    rep = ParserAgreement()
    path = Path(config_path)
    if not path.exists():
        rep.reason = f"{config_path} does not exist"
        return rep

    try:
        from ..readers import load_braces
        ours = set(load_braces(path).values)
    except Exception as exc:                           # noqa: BLE001
        rep.reason = f"our braces reader failed: {type(exc).__name__}: {exc}"
        return rep

    try:
        theirs = _library_paths(path.read_text(encoding="utf-8", errors="replace"))
    except Exception as exc:                           # noqa: BLE001
        # The library being unavailable is not a finding about the device.
        rep.reason = f"ciscoconfparse2 junos parse failed: {type(exc).__name__}"
        return rep

    rep.ours, rep.theirs = len(ours), len(theirs)
    pack_paths = _pack_paths(platform)
    rep.pack_paths_checked = len(pack_paths)

    for p in sorted(pack_paths):
        a, b = _found_by(ours, p), _found_by(theirs, p)
        if a and b:
            rep.both_found.append(p)
        elif a:
            rep.only_ours.append(p)
        elif b:
            rep.only_theirs.append(p)
        # Neither found it: the setting is absent from THIS config, which is
        # a fact about the device rather than a disagreement between parsers.
    rep.checked = True
    return rep
