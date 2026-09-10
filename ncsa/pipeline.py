"""One call: a configuration file in, a complete assessment out.

Until now this chain existed only as something a caller re-assembled by hand --
fingerprint, pick a pack, pick a reader, apply, build the object graph, merge,
load rules, evaluate. Twelve lines and five imports, rewritten slightly
differently every time, which is how two runs of "the same" assessment end up
disagreeing with each other.

That is also why there was nothing for a UI to call. A library becomes a
product at the point where one function does the whole job, and bulk ingestion
(deliverable 1) is then just this function in a loop.

An UNKNOWN vendor is not an error here. It returns an assessment whose state
says so and whose `unrecognised` list carries the raw lines, because that list
is exactly the input the training loop and the parser bootstrapper need.
"""
from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from pathlib import Path

from .engine.evaluate import Assessment, evaluate_all
from .engine.fingerprint import Fingerprint, fingerprint_file
from .engine.rules import load_rules
from .readers import (Pack, apply_indented_pack, apply_json_pack,
                      apply_path_pack, load_block, load_braces, load_exp,
                      load_indented, load_pack, load_xml)
from .readers import load as load_json
from .schema.enums import ResultState

_log = logging.getLogger(__name__)


@dataclass
class DeviceIdentity:
    """Deliverable 4: device identification.

    Every field is optional and stays None when the configuration does not
    state it. A serial number is not derivable from a config that never
    contains one, and inventing "UNKNOWN-01" would put a fabricated identifier
    on an audit report.
    """

    vendor: str = "UNKNOWN"
    platform: str = "UNKNOWN"
    os: str | None = None
    version: str | None = None
    hostname: str | None = None
    serial: str | None = None
    model: str | None = None
    source_file: str = ""
    sha256: str = ""

    @property
    def is_identified(self) -> bool:
        return self.vendor != "UNKNOWN"


@dataclass
class DeviceAssessment:
    identity: DeviceIdentity
    assessment: Assessment | None = None
    fingerprint: Fingerprint | None = None
    graph: object | None = None
    unrecognised: list = field(default_factory=list)
    notes: list = field(default_factory=list)
    supported: bool = True
    # Plan 14.1's completeness invariant, carried out of the reader:
    # total == parsed + unknown. Reported, never silently dropped.
    records: dict = field(default_factory=dict)
    total_records: int = 0
    # The parsed document, retained so the training queue can see exactly what
    # the pack AND the graph consumed. Rebuilding it separately misses pack
    # consumption and re-offers settings that are already mapped -- the queue
    # was proposing `minPasswordLength`, which the pack has mapped all along.
    document: object | None = None
    # Vendor-agnostic detections and their cross-check against the pack.
    # Computed for EVERY device, including unsupported ones -- the universal
    # layer is the floor under a vendor nobody has described to us.
    universal: list = field(default_factory=list)
    consensus: object | None = None
    # Two independent PARSERS on the same syntax. Distinct from `consensus`,
    # which compares two methods over one parse tree -- this catches the case
    # where both methods agree because they read the same wrong tree.
    parser_agreement: object | None = None

    def counts(self) -> dict:
        return self.assessment.counts() if self.assessment else {}

    def coverage(self) -> dict:
        """Honest coverage -- plan 14.2.

        Two numbers, deliberately. `score_pct` is the pass rate over controls
        we could actually decide; `assessed_pct` is how much of the control set
        that was. Reporting the first without the second is how a tool claims
        100% compliance on a device it could barely read.
        """
        c = self.counts()
        decided = c.get("PASS", 0) + c.get("FAIL", 0) + c.get("PARTIAL", 0)
        total = sum(c.values()) or 1
        undecided = c.get("UNKNOWN", 0) + c.get("ERROR", 0)
        return {
            "controls_total": sum(c.values()),
            "controls_decided": decided,
            "controls_undecided": undecided,
            "not_applicable": c.get("NOT_APPLICABLE", 0),
            "assessed_pct": round(100 * decided / total, 1),
            "score_pct": round(100 * c.get("PASS", 0) / decided, 1) if decided else None,
        }

    def failures(self):
        return self.assessment.by_state(ResultState.FAIL) if self.assessment else []

    def training_gap(self) -> int:
        """Distinct security-relevant setting NAMES we parse but cannot interpret.

        The unit matters. 84,214 unmapped records is a number that makes people
        give up; the same gap counted in distinct names is 841, because one
        setting recurs once per interface, per rule, per zone. One approval in
        the training GUI covers every instance of a name, on every device of
        that platform -- so names, not records, is the honest size of the work.
        """
        try:
            from .training.queue import build_queue
            return len(build_queue(self))
        except Exception:                              # noqa: BLE001
            return 0

    def _consensus_row(self) -> str:
        if self.consensus is None:
            return "n/a"
        s = self.consensus.summary()
        return (f"{s['confirmed']}/{s['total']}"
                + (f" ({s['disputed']} disputed)" if s["disputed"] else ""))

    def graph_size(self) -> tuple:
        """(objects, relationships) the object graph reconstructed.

        Zero is a legitimate answer, not a missing number: we hold graph
        builders for SonicOS and Junos only, so a Cisco run genuinely
        reconstructs no objects. Printing a figure here for a platform with no
        builder would be inventing one.
        """
        g = self.graph
        if g is None:
            return 0, 0
        objects = len(getattr(g, "nodes", {}) or {})
        rels = sum(len(getattr(n, "members", []) or [])
                   for n in (getattr(g, "nodes", {}) or {}).values())
        rels += len(getattr(g, "rules", []) or [])
        return objects, rels

    def summary(self) -> str:
        """The one-screen result block."""
        c = self.counts()
        cov = self.coverage()
        objects, rels = self.graph_size()
        i = self.identity
        mapped = self.records.get("MAPPED", 0)
        parsed = self.records.get("PARSED", 0)
        unknown_rec = self.records.get("UNKNOWN", 0)

        from .engine.risk import score_assessment
        risk = score_assessment(self) if self.assessment else {"worst": None,
                                                               "total_risk": 0}

        def row(label, value):
            return f"{label:<28}{value:>10}"

        lines = [f"Device: {i.hostname or i.source_file}"]
        ident = [x for x in (i.vendor, i.model, i.os, i.version) if x and x != "UNKNOWN"]
        if ident:
            lines.append("  " + "  ".join(ident))
        if i.serial:
            lines.append(f"  serial {i.serial}")
        lines.append("")
        lines += [
            row("Source records:", f"{self.total_records:,}"),
            row("Parsed records:", f"{self.total_records - unknown_rec:,}"),
            row("Unreadable records:", f"{unknown_rec:,}"),
            row("Mapped to schema:", f"{mapped:,}"),
            row("Parsed, not mapped:", f"{parsed:,}"),
            row("Objects reconstructed:", f"{objects:,}"),
            row("Relationships resolved:", f"{rels:,}"),
            row("Security-relevant, unmapped:", f"{self.training_gap():,}"),
            row("Corroborated findings:", self._consensus_row()),
            "",
            row("Applicable controls:", cov["controls_total"] - cov["not_applicable"]),
            row("Evaluated controls:", cov["controls_decided"]),
            row("Unknown controls:", cov["controls_undecided"]),
            row("Not applicable:", cov["not_applicable"]),
            "",
            row("PASS:", c.get("PASS", 0)),
            row("FAIL:", c.get("FAIL", 0)),
            row("PARTIAL:", c.get("PARTIAL", 0)),
            row("UNKNOWN:", c.get("UNKNOWN", 0)),
            "",
            row("Assessment Coverage:", f"{cov['assessed_pct']}%"),
            row("Compliance Score:",
                f"{cov['score_pct']}%" if cov["score_pct"] is not None else "n/a"),
            row("Risk Score:", risk["worst"] or "NONE"),
            row("Total Risk:", risk["total_risk"]),
        ]
        # The invariant is asserted in the output, not just in a test: a report
        # that quietly loses records is the failure this whole panel exists to
        # make impossible.
        if self.total_records and mapped + parsed + unknown_rec != self.total_records:
            lines.append("")
            lines.append(f"!! record accounting does not balance: "
                         f"{mapped}+{parsed}+{unknown_rec} != {self.total_records}")
        return "\n".join(lines)


#: Packs that failed to load on the most recent `load_packs()` call.
#:
#: Module-level rather than returned, because `load_packs` has many callers and
#: threading a second return value through all of them would be the kind of
#: change that gets reverted. It is repopulated on every call, so it always
#: describes the current state of the packs directory.
PACK_LOAD_ERRORS: list[dict] = []


def load_packs(packs_dir="packs") -> list:
    """Every pack on disk, with learned mappings merged in.

    `<platform>.learned.yaml` holds mappings approved through the training
    interface. They are merged here rather than appended to the hand-authored
    pack for two reasons: a human owns `cisco.yaml` and machine proposals
    should not be mixed into it, and deleting the learned file must be enough
    to return a device to its pre-approval coverage.

    Learned mappings are appended AFTER the authored ones, so a hand-written
    mapping for the same field wins -- a human decision outranks an approved
    proposal about the same setting.
    """
    root = Path(packs_dir)
    out = []
    PACK_LOAD_ERRORS.clear()
    for p in sorted(root.glob("*.yaml")):
        if p.name.endswith((".draft.yaml", ".learned.yaml")):
            continue
        try:
            pack = load_pack(p)
        except Exception as exc:                       # noqa: BLE001
            # A pack that will not load USED to vanish silently. The failure
            # mode is brutal and was observed for real: a pack referencing a
            # derivation the running code does not have raised here, was
            # swallowed, and the device was then assessed with NO pack at all
            # -- 50 UNKNOWN controls instead of 20, no error anywhere, and
            # nothing to distinguish it from a genuinely unreadable device.
            #
            # A broken pack is our bug. It is recorded and surfaced (see
            # /health and the assessment notes) rather than being allowed to
            # masquerade as a device we could not understand.
            PACK_LOAD_ERRORS.append({
                "pack": p.name,
                "error": f"{type(exc).__name__}: {exc}",
            })
            _log.error("pack %s failed to load and was SKIPPED: %s", p.name, exc)
            continue
        learned = root / f"{pack.platform}.learned.yaml"
        if learned.exists():
            try:
                extra = load_pack(learned)
                # A later mapping OVERWRITES an earlier one for the same field,
                # so simply appending let an approval silently replace a
                # hand-authored mapping -- and degrade it: a generated
                # `console timeout` rule with no capture group turned a
                # working integer read into UNPARSED. Learned mappings may
                # only ADD fields the authored pack does not already cover.
                authored = {m.field.split("[")[0] for m in pack.mappings}
                new = [m for m in extra.mappings
                       if m.field.split("[")[0] not in authored]
                if new:
                    pack = pack.model_copy(
                        update={"mappings": list(pack.mappings) + new})
            except Exception:                          # noqa: BLE001
                pass
        out.append(pack)
    return out


def select_pack(packs, fp: Fingerprint):
    """Choose the pack for this device AND this file format.

    Platform alone is not enough. SonicWall ships two export formats and we
    hold a pack for each -- `sonicwall.yaml` reads the CLI export,
    `sonicwall_exp.yaml` reads the `.exp` backup -- and both declare
    `platform: sonicwall_sonicos`. Keying on platform picked whichever sorted
    first, so a `.exp` file was silently handed to the CLI reader: it still
    produced an SBM and an 81-control assessment, just from the wrong parser,
    with an empty object graph and ten fewer decided controls. Nothing failed;
    the numbers were simply wrong.

    So the reader the fingerprint identified is part of the key.
    """
    same_platform = [p for p in packs if p.platform == fp.platform]
    if fp.reader:
        exact = [p for p in same_platform if getattr(p, "reader", None) == fp.reader]
        if exact:
            return exact[0]
    if same_platform:
        return same_platform[0]
    by_vendor = [p for p in packs if p.vendor == fp.vendor]
    return by_vendor[0] if by_vendor else None


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _read_and_apply(path: Path, pack: Pack, *, aid: str, sha: str, redact: bool):
    """Dispatch on the pack's declared reader. Returns (sbm, parsed_doc)."""
    reader = getattr(pack, "reader", None) or "indented"
    if reader == "sonicos_exp":
        doc = load_exp(path, redact=redact)
        return apply_path_pack(doc, pack, assessment_id=aid, sha256=sha), doc
    if reader == "json":
        doc = load_json(path)
        return apply_json_pack(doc, pack, assessment_id=aid, sha256=sha), doc
    if reader == "xml":
        doc = load_xml(path)
        return apply_path_pack(doc, pack, assessment_id=aid, sha256=sha), doc
    if reader == "braces":
        doc = load_braces(path)
        return apply_path_pack(doc, pack, assessment_id=aid, sha256=sha), doc
    if reader in ("fortinet_block", "block"):
        doc = load_block(path)
        return apply_path_pack(doc, pack, assessment_id=aid, sha256=sha), doc
    doc = load_indented(path)
    return apply_indented_pack(doc, pack, assessment_id=aid, sha256=sha), doc


#: Platform-prefix -> object-graph builder. A table rather than a chain of
#: ifs because the API has to be able to TELL a caller which platforms can
#: answer a reachability or recertification question. Prose in a docstring
#: goes stale; this is read at runtime by /health and by the 422 those
#: endpoints raise, so the claim and the code cannot drift apart.
#: Keyed on the EXACT platform, not a prefix.
#:
#: A prefix of "juniper" also matched `juniper_srx_xml`, whose reader produces
#: an XmlConfig -- and junos_builder reads `cfg.multi`, which XmlConfig does not
#: have. Every Juniper XML device therefore raised AttributeError inside the
#: builder and silently got no object graph, which read downstream as "this
#: platform has no rule-graph builder". The exception was invisible until the
#: bare `except` here was replaced with a logged one.
GRAPH_BUILDERS = {
    "sonicwall_sonicos": ("ncsa.graph.sonicos_builder", "SonicOS"),
    "juniper_srx": ("ncsa.graph.junos_builder", "Junos / SRX"),
    "panos": ("ncsa.graph.panos_builder", "PAN-OS"),
    "fortios": ("ncsa.graph.fortios_builder", "FortiOS"),
}


def graph_platforms() -> list:
    """Platform prefixes that yield an object graph, for honest error text."""
    return sorted(GRAPH_BUILDERS)


def _build_graph(platform: str, doc):
    """Object graph, where a builder exists for this platform.

    Returns None when no builder is registered -- that is an ordinary,
    expected outcome and callers must treat it as "cannot answer", never as
    "nothing wrong". A builder that RAISES is different: that is our bug, and
    it is recorded on the module logger instead of vanishing, because a
    swallowed exception here presents as a device that simply has no rules.
    """
    import importlib

    # EXACT match. `startswith` matched juniper_srx_xml against the
    # juniper_srx entry, handing an XmlConfig to a builder that reads
    # cfg.multi -- which XmlConfig does not have.
    for key, (module, _label) in GRAPH_BUILDERS.items():
        if platform != key:
            continue
        try:
            return importlib.import_module(module).build(doc)
        except Exception:                                  # noqa: BLE001
            _log.exception("graph builder %s failed for platform %r",
                           module, platform)
            return None
    return None
def enrich_identity(identity: DeviceIdentity, show_text: str) -> list:
    """Fill serial / model / version from `show version` output.

    Deliverable 4 asks for "serial numbers and hardware details". A running
    configuration does not contain them -- which is why NCSA reported
    `serial=None` for every Cisco and Juniper device. They live in operational
    output, and ntc-templates parses that for 41 platforms.

    Config-derived values WIN on conflict. The config is the artifact being
    audited and the one the findings cite; `show` output is supplementary, may
    be older, and may come from a different device entirely if someone pasted
    the wrong file. Returns the notes describing what changed, so a report can
    say where each field came from.
    """
    from .readers.show_output import identity_from, ntc_platform, parse

    plat = ntc_platform(identity.platform)
    rows = parse(show_text, plat)
    if not rows:
        return [f"no `show version` template for platform {plat!r}; "
                "device identity limited to what the configuration states"]

    facts = identity_from(rows)
    notes = []
    for attr in ("serial", "model", "version", "os", "hostname"):
        new = facts.get(attr)
        if not new:
            continue
        current = getattr(identity, attr, None)
        if current is None:
            setattr(identity, attr, new)
            notes.append(f"{attr}={new} (from show version)")
        elif str(current) != str(new):
            notes.append(
                f"{attr}: config says {current!r}, show version says {new!r} "
                "-- keeping the config value")
    if facts.get("serial_all") and len(facts["serial_all"]) > 1:
        notes.append("stacked/chassis device: serials " +
                     ", ".join(facts["serial_all"]))

    # Several independent fields disagreeing is not drift, it is two different
    # devices -- somebody pasted the wrong `show version`. Reported as three
    # separate field notes that reads like pedantry; stated once, it is the
    # warning that stops a serial number from the wrong box being printed on
    # an audit report.
    conflicts = [a for a in ("hostname", "model", "version")
                 if facts.get(a) and getattr(identity, a, None)
                 and str(getattr(identity, a)) != str(facts[a])]
    if len(conflicts) >= 2:
        notes.insert(0, (
            "WARNING: the `show version` output disagrees with the "
            f"configuration on {', '.join(conflicts)}. These are probably two "
            "different devices -- identity fields were taken from the "
            "configuration and the show output was NOT used."))
        # Undo any enrichment: a serial from the wrong device is worse than
        # no serial at all.
        for attr in ("serial", "model"):
            if f"{attr}=" in " ".join(notes):
                setattr(identity, attr, None)
    return notes



def _parser_crosscheck(path: Path, device_assessment) -> None:
    """Cross-check the hand-written braces reader against ciscoconfparse2.

    Only for Junos: `readers/braces.py` is the one grammar we implemented by
    hand, and it produced four separate bugs during this project. A second
    implementation turns "somebody noticed" into something the suite can run.
    """
    plat = device_assessment.identity.platform or ""
    if not plat.startswith("juniper_srx") or plat.endswith("_xml"):
        return
    try:
        from .consensus import crosscheck_braces
        device_assessment.parser_agreement = crosscheck_braces(path, plat)
    except Exception:                                  # noqa: BLE001
        pass


def _universal_pass(path: Path, device_assessment) -> None:
    """Run the vendor-agnostic detectors and cross-check them against the pack.

    Deliberately unconditional. On an UNSUPPORTED vendor this is the only
    analysis that runs at all, and on a supported one it is the second opinion
    -- the layer that found a cleartext credential on ASA line 97 that the
    vendor pack itself missed.
    """
    try:
        from .consensus import reconcile
        from .universal import scan
        text = path.read_text(encoding="utf-8", errors="replace")
        device_assessment.universal = scan(text)
        if device_assessment.assessment is not None:
            device_assessment.consensus = reconcile(
                device_assessment, device_assessment.universal)
    except Exception:                                  # noqa: BLE001
        pass


def assess(path, *, packs_dir="packs", rules_dir="rules", redact=True,
           assessment_id=None, tiers=None, show_output=None) -> DeviceAssessment:
    p = Path(path)
    sha = _sha256(p)
    aid = assessment_id or sha[:12]
    fp = fingerprint_file(p)

    identity = DeviceIdentity(
        vendor=fp.vendor, platform=fp.platform, os=fp.os, version=fp.version,
        hostname=fp.hostname, serial=fp.serial,
        model=getattr(fp, "model", None),
        source_file=p.name, sha256=sha)

    identity_notes: list = []
    if show_output is not None:
        sp = Path(show_output)
        text = (sp.read_text(encoding="utf-8", errors="replace")
                if sp.exists() else str(show_output))
        identity_notes = enrich_identity(identity, text)

    pack = select_pack(load_packs(packs_dir), fp)

    if pack is None:
        # Not a failure -- the bootstrap path. The raw lines are the training
        # loop's input, so they are carried out rather than discarded.
        unsupported = DeviceAssessment(
            identity=identity, fingerprint=fp, supported=False,
            unrecognised=_raw_lines(p),
            notes=identity_notes + [
                "no mapping pack for vendor={!r} platform={!r}; this device "
                "needs a pack before it can be assessed".format(
                    fp.vendor, fp.platform)])
        _universal_pass(p, unsupported)
        return unsupported

    sbm, doc = _read_and_apply(p, pack, aid=aid, sha=sha, redact=redact)

    graph = _build_graph(pack.platform, doc)
    if graph is not None:
        from .graph.bridge import merge
        merge(sbm, graph)

    controls = load_rules(rules_dir, platform=pack.platform, tiers=tiers)
    assessment = evaluate_all(
        controls, sbm, device=identity.hostname or p.stem,
        platform=pack.platform,
        not_applicable_domains=getattr(pack, "not_applicable_domains", None),
        not_applicable_fields=getattr(pack, "not_applicable_fields", None))

    # Record accounting, and the lines no mapping touched. Those lines are the
    # training loop's input, so they are carried out for SUPPORTED devices too
    # -- not only for unknown vendors. A recognised vendor with an incomplete
    # pack is exactly the case where new mappings are worth learning.
    records, total, unrecognised = {}, 0, []
    try:
        records = doc.accounting_snapshot()
        total = doc.total_records
        unrecognised = [str(getattr(e, "raw", e)) for e in doc.unrecognised()]
    except Exception:                                  # noqa: BLE001
        pass

    out = DeviceAssessment(identity=identity, assessment=assessment,
                           fingerprint=fp, graph=graph, records=records,
                           total_records=total, unrecognised=unrecognised,
                           document=doc, notes=identity_notes)
    _universal_pass(p, out)
    _parser_crosscheck(p, out)
    return out


def assess_many(paths, **kw) -> list:
    """Deliverable 1: bulk ingestion. One unreadable file must not stop a batch."""
    out = []
    for p in paths:
        try:
            out.append(assess(p, **kw))
        except Exception as exc:                       # noqa: BLE001
            out.append(DeviceAssessment(
                identity=DeviceIdentity(source_file=Path(p).name),
                supported=False,
                notes=["{}: {}".format(type(exc).__name__, exc)]))
    return out


def _raw_lines(path: Path, limit: int = 4000) -> list:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except Exception:                                  # noqa: BLE001
        return []
    return [l.rstrip() for l in text.splitlines()[:limit] if l.strip()]
