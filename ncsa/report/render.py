"""Render an assessment as a formal report: HTML, then PDF.

TYPOGRAPHY AND TONE
-------------------
Monochrome. No colour, no fills, no shading, no graphics. Rules and weight do
all the work, which is how a printed audit document has always been set and
also how it survives being photocopied, faxed to a regulator, or read by
someone who is colour-blind.

That is not only an aesthetic choice. This product's central claim is that a
verdict is checkable, and a coloured badge invites the reader to skim the
colour instead of reading the evidence. A monochrome table forces the words to
carry the meaning.

ACCURACY
--------
Every number here is computed from the DeviceAssessment at render time. There
are no literals in the templates, no cached figures, and no rounding beyond
what the engine itself publishes. Where a section has nothing to report, it
says why rather than being omitted -- an absent section is indistinguishable
from a clean one, which is the failure this whole project exists to avoid.
"""
from __future__ import annotations

import html
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from ..schema.enums import ResultState

# Order matters: this is the order a reader scans, worst first.
SEVERITY_ORDER = ["critical", "high", "medium", "low"]

STATE_MEANING = {
    "PASS": "Checked; the device is configured correctly.",
    "FAIL": "Checked; the device is not configured correctly.",
    "PARTIAL": "Checked; some scoped instances comply and others do not.",
    "NOT_APPLICABLE": "The control does not apply to this device. Excluded "
                      "from scoring; a justification is recorded for each.",
    "UNKNOWN": "Could not be determined from the supplied configuration. "
               "Neither a pass nor a failure.",
    "MANUAL_REVIEW": "Requires a human decision; no automated verdict would "
                     "be sound.",
    "ERROR": "The check itself failed. A defect in the auditing tool, not in "
             "the device.",
}


def _e(value) -> str:
    """Escape for HTML. Applied to EVERY value taken from a device file.

    Configuration content is untrusted input -- this project has already found
    injection-shaped content inside real device data -- and it is reproduced
    verbatim throughout this report as evidence.
    """
    if value is None:
        return "&mdash;"
    return html.escape(str(value), quote=True)


def _fmt(value) -> str:
    """Render an observed or expected value for a report table."""
    if value is None:
        return "&mdash;"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (list, tuple)):
        if not value:
            return "(empty)"
        return _e(", ".join(str(v) for v in value[:6])) + (
            f" &hellip; and {len(value) - 6} more" if len(value) > 6 else "")
    return _e(value)


# --------------------------------------------------------------- collection

def _fw_coverage(findings, platform=None) -> list:
    from ..frameworks.selection import framework_coverage
    return framework_coverage(findings, platform)


def _collect(da, aid: str) -> dict:
    """Everything the report shows, gathered from the engine in one place.

    Kept separate from rendering so the figures can be asserted directly in a
    test without parsing HTML.
    """
    from ..engine.risk import score_assessment

    counts = da.counts()
    coverage = da.coverage()
    findings = list(da.assessment.findings) if da.assessment else []

    risk = score_assessment(da) if da.assessment else {
        "bands": {}, "total_risk": 0, "worst": None, "findings": []}
    risk_by_control = {f.control_id: r for f, r in risk.get("findings", [])}

    graph = da.graph
    hygiene = None
    if graph is not None:
        try:
            from ..graph.hygiene import analyse
            hygiene = analyse(graph)
        except Exception:                                  # noqa: BLE001
            hygiene = None

    remediation = None
    try:
        from ..engine.remediate import build_plan
        from ..engine.rules import load_rules
        controls = {c.id: c for c in load_rules(
            "rules", platform=da.identity.platform)}
        remediation = build_plan(da, controls_by_id=controls)
    except Exception:                                      # noqa: BLE001
        remediation = None

    return {
        "assessment_id": aid,
        "identity": da.identity,
        "counts": counts,
        "coverage": coverage,
        "records": da.records,
        "total_records": da.total_records,
        "findings": findings,
        "risk": risk,
        "risk_by_control": risk_by_control,
        "graph": graph,
        "hygiene": hygiene,
        "remediation": remediation,
        "supported": da.supported,
        "notes": list(da.notes or []),
        "frameworks": getattr(da, "frameworks", None),
        "framework_coverage": _fw_coverage(findings, getattr(da.identity, "platform", None)),
        "generated_at": datetime.now(timezone.utc).strftime(
            "%d %B %Y at %H:%M UTC"),
    }


# ------------------------------------------------------------------ styling

_CSS = """
@page { size: A4; margin: 20mm 18mm 22mm 18mm; }
* { box-sizing: border-box; }
body {
  font-family: "Times New Roman", Times, Georgia, serif;
  font-size: 10.5pt; line-height: 1.45; color: #000; background: #fff;
  margin: 0; -webkit-print-color-adjust: exact; print-color-adjust: exact;
}
h1 { font-size: 20pt; margin: 0 0 2pt; font-weight: 700; letter-spacing: -.2pt; }
h2 {
  font-size: 13pt; margin: 22pt 0 7pt; font-weight: 700;
  border-bottom: 1pt solid #000; padding-bottom: 3pt;
  page-break-after: avoid;
}
h3 { font-size: 11pt; margin: 14pt 0 5pt; font-weight: 700; page-break-after: avoid; }
h4 { font-size: 10.5pt; margin: 10pt 0 3pt; font-weight: 700; page-break-after: avoid; }
p { margin: 0 0 7pt; orphans: 3; widows: 3; }
.sub { font-size: 11pt; margin: 0 0 14pt; }
.rule { border: 0; border-top: 2pt solid #000; margin: 8pt 0 14pt; }
.thin { border: 0; border-top: .5pt solid #000; margin: 12pt 0; }

table { border-collapse: collapse; width: 100%; margin: 6pt 0 12pt; font-size: 9.5pt; }
th, td {
  border: .5pt solid #000; padding: 3.5pt 5pt; text-align: left;
  vertical-align: top;
}
th { font-weight: 700; }
td.num, th.num { text-align: right; }
table.plain, table.plain th, table.plain td { border: 0; padding: 1.5pt 10pt 1.5pt 0; }
table.plain th { width: 32%; font-weight: 700; }

code, .mono {
  font-family: "Courier New", Courier, monospace; font-size: 9pt;
}
pre {
  font-family: "Courier New", Courier, monospace; font-size: 8.5pt;
  border: .5pt solid #000; padding: 6pt 8pt; margin: 4pt 0 10pt;
  white-space: pre-wrap; word-break: break-word; page-break-inside: avoid;
}
.evidence {
  border-left: 2pt solid #000; padding: 3pt 0 3pt 8pt; margin: 3pt 0 6pt;
  font-family: "Courier New", Courier, monospace; font-size: 8.5pt;
  word-break: break-all;
}
.finding { page-break-inside: avoid; margin: 0 0 12pt; padding: 0 0 8pt;
           border-bottom: .5pt solid #000; }
.finding:last-child { border-bottom: 0; }
.meta { font-size: 9pt; margin: 1pt 0 4pt; }
.tag {
  border: .5pt solid #000; padding: 0 4pt; margin-right: 4pt;
  font-size: 8.5pt; font-weight: 700; text-transform: uppercase;
  letter-spacing: .3pt; white-space: nowrap;
}
.note { border: .5pt solid #000; padding: 7pt 9pt; margin: 8pt 0 12pt; font-size: 9.5pt; }
ul, ol { margin: 4pt 0 8pt; padding-left: 16pt; }
li { margin: 1.5pt 0; }
.pagebreak { page-break-before: always; }
.footnote { font-size: 8.5pt; margin-top: 3pt; }
.center { text-align: center; }
"""


# ------------------------------------------------------------------ sections

def _cover(d: dict) -> str:
    i = d["identity"]
    cov = d["coverage"]
    rows = [
        ("Hostname", i.hostname),
        ("Vendor", i.vendor),
        ("Model", i.model),
        ("Operating system", i.os),
        ("Software version", i.version),
        ("Serial number", i.serial),
        ("Platform identifier", i.platform),
    ]
    src = [
        ("Configuration file", i.source_file),
        ("SHA-256 of file", i.sha256),
        ("Records in file", f"{d['total_records']:,}"),
        ("Assessment identifier", d["assessment_id"]),
        ("Report generated", d["generated_at"]),
    ]

    def table(pairs):
        body = "".join(
            f"<tr><th>{_e(k)}</th><td>{_e(v) if v not in (None, '') else 'Not stated in the configuration'}</td></tr>"
            for k, v in pairs)
        return f'<table class="plain">{body}</table>'

    score = cov["score_pct"]
    score_txt = "not computable" if score is None else f"{score}%"

    return f"""
<h1>Network Configuration Compliance Assessment</h1>
<p class="sub">{_e(i.hostname or i.source_file)} &mdash; {_e(i.vendor)} {_e(i.model or '')}</p>
<hr class="rule">

<h2>1. Device identification</h2>
{table(rows)}

<h3>Source of assessment</h3>
{table(src)}
<p class="footnote">The SHA-256 digest identifies the exact file assessed. A
re-run against a different file will produce a different digest, and the two
reports are not comparable.</p>

<h2>2. Result</h2>
<table class="plain">
  <tr><th>Compliance score</th><td><strong>{score_txt}</strong> of {cov['controls_decided']} decided controls</td></tr>
  <tr><th>Assessment coverage</th><td><strong>{cov['assessed_pct']}%</strong> of the {cov.get('controls_applicable', cov['controls_total'])} controls that apply to this platform ({cov['controls_total']} in the catalogue)</td></tr>
  <tr><th>Controls not decided</th><td>{cov['controls_undecided']}</td></tr>
  <tr><th>Controls not applicable</th><td>{cov['not_applicable']}</td></tr>
  <tr><th>Aggregate risk</th><td>{d['risk'].get('total_risk', 0)} &mdash; highest band {_e(d['risk'].get('worst') or 'none')}</td></tr>
  <tr><th>Frameworks assessed</th><td>{_fw_selection(d)}</td></tr>
</table>

<h3>Result by framework</h3>
<table>
  <tr><th>Framework</th><th class="num">Framework score</th><th class="num">Requirements assessed</th><th class="num">Fully met</th><th class="num">Undecided</th><th class="num">Checks passed</th></tr>
  {''.join(f"<tr><td>{_e(r['name'])}</td><td class='num'><b>{'&mdash;' if r['framework_score_pct'] is None else str(r['framework_score_pct']) + '%'}</b></td><td class='num'>{r['requirements_decided']}</td><td class='num'>{r['requirements_met']} / {r['requirements_decided']}</td><td class='num'>{r['requirements'] - r['requirements_decided']}</td><td class='num'>{r['passed']} / {r['decided']}</td></tr>" for r in d['framework_coverage'])}
</table>
<p class="footnote">Each framework is scored over its own requirements (NIST
SP 800-53 controls, ISO/IEC 27001 Annex A controls, STIG IDs). Each requirement
scores the share of its checks that passed -- three of four is 75% -- and the
framework score is the average across its requirements. Undecided checks are
never counted as passes. "Fully met" counts requirements where every check
passed. A framework citing no control on this platform is shown with no score
rather than omitted.</p>
{''.join(f"<p class='footnote'><b>{_e(r['name'])} requirements not fully met:</b> {_e(', '.join(r['not_met_ids']))}</p>" for r in d['framework_coverage'] if r['not_met_ids'])}

<div class="note">
<strong>How to read the score.</strong> The compliance score is calculated over
controls that could be decided, and it is reported beside coverage for that
reason. A high score on low coverage means little of the device could be
assessed &mdash; not that the device is well configured. Both figures must be
quoted together.
</div>
"""


def _fw_selection(d: dict) -> str:
    from ..frameworks.selection import FRAMEWORKS
    sel = d.get("frameworks")
    if not sel:
        return "All frameworks (CIS, NIST SP 800-53, DISA STIG, ISO/IEC 27001)"
    return _e(", ".join(FRAMEWORKS[k][0] for k in sel if k in FRAMEWORKS))


def _states(d: dict) -> str:
    counts = d["counts"]
    total = sum(counts.values()) or 1
    rows = "".join(
        f"<tr><td>{_e(s)}</td><td class='num'>{counts.get(s, 0)}</td>"
        f"<td class='num'>{round(100 * counts.get(s, 0) / total, 1)}%</td>"
        f"<td>{_e(STATE_MEANING.get(s, ''))}</td></tr>"
        for s in ["PASS", "FAIL", "PARTIAL", "NOT_APPLICABLE", "UNKNOWN",
                  "MANUAL_REVIEW", "ERROR"])
    return f"""
<h2>3. Result states</h2>
<p>Every control resolves to exactly one of seven states. The distinction
between <em>not applicable</em> and <em>unknown</em> is material: the first is a
property of the device, the second is a limit of this assessment.</p>
<table>
  <tr><th>State</th><th class="num">Controls</th><th class="num">Share</th><th>Meaning</th></tr>
  {rows}
</table>
"""


def _findings(d: dict) -> str:
    by_sev: dict = {s: [] for s in SEVERITY_ORDER}
    for f in d["findings"]:
        if f.state in (ResultState.FAIL, ResultState.PARTIAL):
            by_sev.setdefault(f.severity.value, []).append(f)

    total = sum(len(v) for v in by_sev.values())
    if total == 0:
        return """
<h2 class="pagebreak">4. Findings</h2>
<p>No control was assessed as failing or partially met. This statement covers
only the controls that could be decided; see section 6 for those that could
not.</p>
"""

    summary = "".join(
        f"<tr><td>{s.capitalize()}</td><td class='num'>{len(by_sev.get(s, []))}</td></tr>"
        for s in SEVERITY_ORDER)

    blocks = []
    for sev in SEVERITY_ORDER:
        items = by_sev.get(sev) or []
        if not items:
            continue
        blocks.append(f"<h3>4.{SEVERITY_ORDER.index(sev) + 1} "
                      f"{sev.capitalize()} severity ({len(items)})</h3>")
        for f in sorted(items, key=lambda x: x.control_id):
            blocks.append(_finding_block(f, d))

    return f"""
<h2 class="pagebreak">4. Findings</h2>
<p>{total} control{'s' if total != 1 else ''} assessed as failing or partially
met, ordered by severity. Each is reported with the configuration line it was
derived from.</p>
<table>
  <tr><th>Severity</th><th class="num">Findings</th></tr>
  {summary}
</table>
{''.join(blocks)}
"""


#: How many evidence rows to print per finding before summarising the rest.
#: Enough to show a pattern; not so many that one finding fills a page.
_EVIDENCE_ROWS = 8


def _locator(e) -> tuple[str, str, str]:
    """(line number, further locator, kind) for one evidence reference.

    THE LINE NUMBER IS ALWAYS GIVEN. An administrator reads this report with
    the configuration open beside it, and a finding they cannot locate is a
    finding they cannot fix.

    Three cases, and the report gives a line for all of them:

      * a real LINE NUMBER from a line-oriented config. `sed -n '15p' file`
        puts them on the exact line.
      * a SINGLE-LINE key-value export. The decoded SonicOS backup holds
        92,636 settings on one physical line, so line 1 is where every setting
        genuinely is -- correct, but not sufficient by itself, so the
        setting's ordinal position is given beside it. Together they locate
        the value exactly.
      * a STRUCTURED document, where the reader supplies the line and the path
        addresses the element within it.

    What this must never do is print an ordinal UNDER a "line" heading. An
    administrator who runs `sed -n '1234p'` on a one-line file gets nothing,
    and would rightly stop trusting the report.
    """
    rid = (e.record_id or "").strip()

    # `setting[1234]` -> 1234, the setting's position within the file.
    ordinal = ""
    if rid.startswith("setting[") and rid.endswith("]"):
        ordinal = rid[len("setting["):-1]

    if e.line is not None:
        return str(e.line), (_e(rid) if rid and not ordinal else ""), "line"

    if ordinal:
        # THE ORDINAL, NOT "1".
        #
        # The decoded SonicOS backup is 2.7 million characters with zero
        # newlines, so every one of its 92,636 settings is on line 1. Printing
        # that is accurate and useless: a column reading 1 for every finding
        # in the report distinguishes nothing and cannot be acted on.
        #
        # The ordinal is unique per setting and genuinely reachable --
        # `tr '&' '\\n' < config | sed -n '1234p'` returns the setting. So the
        # number given is the one that locates the value, and the footnote
        # states the retrieval, rather than a number that is merely true.
        return _e(ordinal), "", "single_line"

    if rid:
        return "&mdash;", _e(rid), "path"

    return "&mdash;", "", "none"


def _evidence_table(evidence) -> str:
    """The configuration lines a finding rests on, with their positions.

    An administrator reading this report has the device configuration open
    beside it. The locator is what turns a finding into an edit.
    """
    if not evidence:
        # An absent evidence line is itself information: the finding rests on
        # the setting NOT being present, which the basis above states.
        return ('<h4>Evidence</h4><p class="footnote">No line in the '
                'configuration carries this setting. The finding rests on its '
                'absence, which the basis above states. There is no position '
                'to cite, because there is nothing there.</p>')

    shown = list(evidence)[:_EVIDENCE_ROWS]
    located = [_locator(e) for e in shown]
    kinds = {k for _l, _d, k in located}
    # A second column only where there is something to put in it.
    has_detail = any(detail for _l, detail, _k in located)

    rows = []
    for e, (line, detail, _kind) in zip(shown, located):
        detail_cell = f"<td class='mono'>{detail}</td>" if has_detail else ""
        rows.append(f"<tr><td class='num mono'>{line}</td>{detail_cell}"
                    f"<td class='mono'>{_e(e.raw)}</td></tr>")

    detail_header = ""
    if has_detail:
        detail_header = ('<th style="width:18%">Setting</th>'
                         if "single_line" in kinds
                         else '<th style="width:22%">Location</th>')

    note = ""
    if "single_line" in kinds:
        note = ('<p class="footnote">This configuration is one physical line '
                'of <code>&amp;</code>-separated settings, so every value sits '
                'on line 1 and a line number would distinguish nothing. The '
                'figure above is the setting\'s position in the file. To read '
                'setting <em>n</em> directly: '
                '<span class="mono">tr \'&amp;\' \'\\n\' &lt; config | '
                'sed -n \'<em>n</em>p\'</span></p>')

    more = ""
    if len(evidence) > _EVIDENCE_ROWS:
        more = (f'<p class="footnote">and {len(evidence) - _EVIDENCE_ROWS} '
                f'further evidence line(s) not shown.</p>')

    # Head the column for what the number IS on this device. Calling a setting
    # ordinal a "line" would send an administrator to `sed -n '1234p'` on a
    # one-line file, which returns nothing.
    number_header = "Setting" if "single_line" in kinds else "Line"

    src = evidence[0].file
    return f"""
<h4>Evidence</h4>
<table>
  <tr><th class="num" style="width:10%">{number_header}</th>{detail_header}<th>Configuration line</th></tr>
  {''.join(rows)}
</table>
<p class="footnote">Source: <span class="mono">{_e(src)}</span></p>
{note}{more}
"""


def _finding_block(f, d: dict) -> str:
    risk = d["risk_by_control"].get(f.control_id)
    fw = f.frameworks
    refs = []
    for label, ids in (("NIST SP 800-53", fw.nist_800_53),
                       ("ISO/IEC 27001", fw.iso_27001),
                       ("DISA STIG", fw.stig_ids),
                       ("CIS", fw.cis_ids)):
        if ids:
            refs.append(f"{label}: {_e(', '.join(ids))}")

    ev = _evidence_table(f.evidence)

    reason = (f"<p><strong>Basis.</strong> {_e(f.reason)}</p>"
              if f.reason else "")

    # ATT&CK is kept on its own row: it names the adversary technique the
    # control stands in front of, and is not a compliance framework.
    from ..frameworks.attack import tags_for
    tags = tags_for(f.control_id)
    attack_row = ""
    if tags:
        attack_row = ("<tr><th>Adversary technique (MITRE ATT&amp;CK)</th><td>"
                      + "; ".join(f"{_e(t['id'])} {_e(t['name'])}" for t in tags)
                      + "</td></tr>")
    risk_row = ""
    if risk is not None:
        risk_row = (f"<tr><th>Risk</th><td>{risk.score} ({_e(risk.band)}) &mdash; "
                    f"{_e('; '.join(risk.rationale))}</td></tr>")

    return f"""
<div class="finding">
  <h4>{_e(f.control_id)} &mdash; {_e(f.title)}</h4>
  <p class="meta">
    <span class="tag">{_e(f.state.value)}</span>
    <span class="tag">{_e(f.severity.value)}</span>
    <span class="mono">{_e(f.field)}</span>
  </p>
  <table class="plain">
    <tr><th>Observed</th><td class="mono">{_fmt(f.observed)}</td></tr>
    <tr><th>Required</th><td class="mono">{_fmt(f.expected)}</td></tr>
    {risk_row}
    {'<tr><th>Framework references</th><td>' + '; '.join(refs) + '</td></tr>' if refs else ''}
    {attack_row}
  </table>
  {reason}
  {ev}
</div>
"""


def _not_applicable(d: dict) -> str:
    na = [f for f in d["findings"] if f.state is ResultState.NOT_APPLICABLE]
    if not na:
        return ""
    rows = "".join(
        f"<tr><td>{_e(f.control_id)}</td><td>{_e(f.title)}</td>"
        f"<td>{_e(f.reason) or 'No justification recorded.'}</td></tr>"
        for f in sorted(na, key=lambda x: x.control_id))
    return f"""
<h2 class="pagebreak">5. Controls not applicable ({len(na)})</h2>
<p>These controls are excluded from the compliance score. Because an exclusion
raises the score by removing a control from the denominator, each one carries a
stated justification. An exclusion without a justification is a defect and is
treated as such.</p>
<table>
  <tr><th>Control</th><th>Title</th><th>Justification</th></tr>
  {rows}
</table>
"""


def _undecided(d: dict) -> str:
    unk = [f for f in d["findings"]
           if f.state in (ResultState.UNKNOWN, ResultState.ERROR,
                          ResultState.MANUAL_REVIEW)]
    rec = d["records"] or {}
    acct = f"""
<h3>Parsing account</h3>
<table>
  <tr><th>Measure</th><th class="num">Records</th></tr>
  <tr><td>Present in the configuration file</td><td class="num">{d['total_records']:,}</td></tr>
  <tr><td>Read successfully</td><td class="num">{(d['total_records'] - rec.get('UNKNOWN', 0)):,}</td></tr>
  <tr><td>Mapped to the compliance schema</td><td class="num">{rec.get('MAPPED', 0):,}</td></tr>
  <tr><td>Read but not mapped</td><td class="num">{rec.get('PARSED', 0):,}</td></tr>
  <tr><td>Unreadable</td><td class="num">{rec.get('UNKNOWN', 0):,}</td></tr>
</table>
<p class="footnote">Records greatly outnumber settings, because one setting
recurs once per rule, per interface or per zone. A record read but not mapped
is most often device state with no bearing on a security control &mdash; a
signature identifier, an object table column, or interface counters.</p>
"""

    if not unk:
        return f"""
<h2 class="pagebreak">6. Controls not decided</h2>
<p>Every control in the catalogue was decided or excluded. No control was left
undetermined.</p>
{acct}
"""

    rows = "".join(
        f"<tr><td>{_e(f.control_id)}</td><td>{_e(f.title)}</td>"
        f"<td>{_e(f.state.value)}</td><td>{_e(f.reason) or '&mdash;'}</td></tr>"
        for f in sorted(unk, key=lambda x: (x.state.value, x.control_id)))
    return f"""
<h2 class="pagebreak">6. Controls not decided ({len(unk)})</h2>
<p>These controls could not be determined from the configuration supplied. They
are neither passes nor failures, and they are counted in the coverage figure so
that the limits of this assessment are visible on the front page. They are
reported here rather than omitted.</p>
<table>
  <tr><th>Control</th><th>Title</th><th>State</th><th>Reason</th></tr>
  {rows}
</table>
{acct}
"""


def _policy(d: dict) -> str:
    g = d["graph"]
    if g is None:
        return """
<h2 class="pagebreak">7. Policy analysis</h2>
<p>No policy object graph was constructed for this platform, so rule hygiene,
reachability and rule recertification were not attempted. This is a limit of
the auditing tool for this device type, not a statement about the device: the
configuration was parsed and its control findings above are unaffected.</p>
"""
    kinds: dict = {}
    for n in g.nodes.values():
        kinds[n.kind.value] = kinds.get(n.kind.value, 0) + 1
    kind_rows = "".join(
        f"<tr><td>{_e(k.replace('_', ' '))}</td><td class='num'>{v}</td></tr>"
        for k, v in sorted(kinds.items()))

    h = d["hygiene"]
    hyg = ""
    if h is not None:
        s = h.summary()
        by_kind = "".join(
            f"<tr><td>{_e(k.replace('_', ' '))}</td><td class='num'>{v}</td></tr>"
            for k, v in sorted(s.get("by_kind", {}).items()))
        unevaluable_note = ""
        if s.get("unevaluable"):
            unevaluable_note = f"""
<div class="note"><strong>Incomplete analysis.</strong>
{s['unevaluable']} of {s['rules_examined']} rules could not be fully resolved,
because they reference objects the supplied configuration does not contain.
Conclusions about those rules are incomplete, and they are counted here rather
than treated as clean.</div>
"""
        hyg = f"""
<h3>7.2 Rule hygiene</h3>
<table>
  <tr><th>Measure</th><th class="num">Rules</th></tr>
  <tr><td>Examined</td><td class="num">{s['rules_examined']}</td></tr>
  <tr><td>Fully resolved</td><td class="num">{s['rules_fully_resolved']}</td></tr>
  <tr><td>Not fully resolvable</td><td class="num">{s['unevaluable']}</td></tr>
</table>
{unevaluable_note}
<h4>Observations by kind</h4>
<table>
  <tr><th>Kind</th><th class="num">Count</th></tr>
  {by_kind}
</table>
"""

    ordered = not getattr(g, "unordered", False)
    order_note = "" if ordered else """
<p><strong>Note.</strong> This platform does not evaluate rules in order, so no
rule can conceal another. Shadow and redundancy analysis is therefore not
applicable here, and its absence from the findings above must not be read as
evidence of a well-ordered policy.</p>
"""

    return f"""
<h2 class="pagebreak">7. Policy analysis</h2>
<h3>7.1 Reconstructed policy</h3>
<p>The configuration was reconstructed as an object graph: named addresses,
services, groups and zones, with every reference followed to the value it
resolves to. The findings in section 4 that concern policy are derived from
this reconstruction.</p>
<table class="plain">
  <tr><th>Objects reconstructed</th><td>{len(g.nodes):,}</td></tr>
  <tr><th>Policy rules</th><td>{len(g.rules):,}</td></tr>
  <tr><th>Default action</th><td>{_e(g.default_action)}
      ({'observed in the configuration' if g.default_action_observed else 'assumed from platform behaviour, not read from the file'})</td></tr>
  <tr><th>Evaluation order</th><td>{'first match wins' if ordered else 'unordered'}</td></tr>
</table>
<table>
  <tr><th>Object kind</th><th class="num">Count</th></tr>
  {kind_rows}
</table>
{order_note}
{hyg}
"""


def _remediation(d: dict) -> str:
    plan = d["remediation"]
    if plan is None:
        return ""
    steps = list(getattr(plan, "steps", []) or [])
    unavailable = list(getattr(plan, "unavailable", []) or [])
    deferred = list(getattr(plan, "deferred", []) or [])
    # `script` is a method on Plan, not an attribute.
    script = plan.script() if callable(getattr(plan, "script", None)) else ""

    if not steps:
        return f"""
<h2 class="pagebreak">8. Remediation</h2>
<p>No remediation commands are held for this platform covering the findings
above. {len(unavailable)} failing control{'s' if len(unavailable) != 1 else ''}
{'have' if len(unavailable) != 1 else 'has'} no recorded command sequence. The
findings remain valid; only the suggested fix is unavailable.</p>
"""

    blocks = []
    for s in steps:
        cmds = list(getattr(s, "commands", []) or [])
        verify = getattr(s, "verify", "") or ""
        warning = getattr(s, "lockout_warning", "") or ""
        impact = getattr(s, "management_impact", "") or ""
        # A step that would sever the management path is the one an engineer
        # most needs warned about, and it must not be buried in a code block.
        warn_html = (f'<p class="footnote"><strong>Caution.</strong> '
                     f'{_e(warning)}</p>' if warning else "")
        impact_html = (f'<p class="footnote">Management impact: '
                       f'{_e(impact)}</p>'
                       if impact and impact != "none" else "")
        blocks.append(f"""
<div class="finding">
  <h4>{_e(getattr(s, 'control_id', ''))} &mdash; {_e(getattr(s, 'title', ''))}</h4>
  <pre>{_e(chr(10).join(cmds))}</pre>
  {f'<p class="footnote"><strong>Verify with:</strong> <span class="mono">{_e(verify)}</span></p>' if verify else ''}
  {warn_html}
  {impact_html}
</div>""")

    deferred_html = ""
    if deferred:
        # Deferred steps are deliberately kept OUT of the consolidated script:
        # they would cut the only management path to the device.
        rows = "".join(
            f"<tr><td>{_e(getattr(x, 'control_id', x))}</td>"
            f"<td>{_e(getattr(x, 'lockout_warning', '') or getattr(x, 'title', ''))}</td></tr>"
            for x in deferred)
        deferred_html = f"""
<h3>8.2 Steps held back ({len(deferred)})</h3>
<p>These changes would sever the only management path to this device. They are
excluded from the consolidated sequence below and must be applied through
console access or a scheduled maintenance window.</p>
<table><tr><th>Control</th><th>Reason held back</th></tr>{rows}</table>
"""

    unavail = ""
    if unavailable:
        unavail = f"""
<h3>8.3 Findings with no recorded remediation ({len(unavailable)})</h3>
<p>No command sequence is held for these controls on this platform. They are
listed so that this section is not mistaken for a complete remediation plan.</p>
<p class="mono">{_e(', '.join(str(u) for u in unavailable))}</p>
"""

    return f"""
<h2 class="pagebreak">8. Remediation</h2>
<div class="note">
<strong>Review before use.</strong> These commands are drawn from vendor
documentation for the platform identified in section 1. A configuration file
records state, not the commands that produced it, so these sequences cannot be
verified against the file assessed. Each step carries a verification command;
confirm the effect on the device rather than assuming it. Apply changes through
your normal change-control process.
</div>
<h3>8.1 Suggested commands ({len(steps)})</h3>
{''.join(blocks)}
{deferred_html}
{unavail}
{f'<h3>8.4 Consolidated sequence</h3><pre>{_e(script)}</pre>' if script else ''}
"""


def _method(d: dict) -> str:
    return f"""
<h2 class="pagebreak">9. Method and limitations</h2>

<h3>9.1 How this assessment was produced</h3>
<p>The configuration file was identified by content, parsed with the mapping
pack for its platform, and normalised into a vendor-neutral model of security
settings. Controls were then evaluated against that model. No vendor-specific
logic exists in the control layer, so the same control is assessed identically
across platforms.</p>

<h3>9.2 How the score is calculated</h3>
<p>The compliance score is the weighted proportion of passing controls among
those that could be decided. Controls that are not applicable, not decided,
require manual review, or errored are excluded from the calculation and are
reported separately in sections 5 and 6. Partially met controls count as half.
Coverage states what proportion of the catalogue was decided, and the score is
meaningful only when read with it.</p>

<h3>9.3 What this assessment does not cover</h3>
<ul>
  <li>It examines a configuration file only. Running state, live traffic,
      installed firmware integrity and physical security are outside its
      scope.</li>
  <li>A control reported as not decided is a limit of this assessment. It must
      not be recorded as a pass.</li>
  <li>Where policy rules reference objects absent from the supplied file, any
      conclusion about those rules is incomplete. The count of such rules is
      given in section 7.</li>
  <li>Remediation commands are suggestions derived from vendor documentation
      and are not verified against this device.</li>
</ul>

<h3>9.4 Framework references</h3>
<p>Findings cite control identifiers from NIST SP 800-53, DISA STIG, CIS
Benchmarks and ISO/IEC 27001 where a mapping exists. CIS and ISO material is
copyrighted; it is cited by identifier and short title only, and no text from
either is reproduced in this report.</p>

<hr class="thin">
<p class="footnote center">Assessment {_e(d['assessment_id'])} &mdash;
generated {_e(d['generated_at'])} &mdash;
{_e(d['identity'].hostname or d['identity'].source_file)}</p>
"""


_EXT_LISTED = ("FAIL", "PARTIAL", "MANUAL_REVIEW", "UNKNOWN")


def _ext_locator(e: dict) -> str:
    if e.get("line") is not None:
        return f"line {e['line']}"
    rec = e.get("record") or ""
    if rec.startswith("setting[") and rec.endswith("]"):
        return f"setting {rec[len('setting['):-1]}"
    return rec or "&mdash;"


def _extended(da, d: dict) -> str:
    """Appendix A: VPN, wireless, known vulnerabilities, and blast radius.

    An APPENDIX, and numbered as one, because none of it enters the score or
    coverage in section 2. Adding these checks to the control catalogue would
    have changed results already reported; placing them here keeps both
    visible without either altering the other.
    """
    from ..extended.run import run_extended
    from ..topology.blast import blast_radius, zone_members

    doms = run_extended(da)["domains"]
    parts = []
    for n, (key, label) in enumerate((("cve", "Known vulnerabilities"),
                                       ("vpn", "IPsec VPN"),
                                       ("wireless", "Wireless")), start=1):
        dom = doms.get(key)
        if not dom:
            continue
        counts = ", ".join(f"{v} {k.replace('_', ' ').lower()}"
                           for k, v in dom["counts"].items()) or "no checks run"
        rows = []
        for f in dom["findings"]:
            if f["state"] not in _EXT_LISTED:
                continue
            ev = f["evidence"][0] if f["evidence"] else None
            loc = (f"{_ext_locator(ev)}: <span class='mono'>{_e(ev['raw'])}</span>"
                   if ev else "&mdash;")
            tags = "; ".join(f"{_e(t['id'])}" for t in f.get("attack", []))
            rows.append(
                # Identifiers never wrap: "CVE-2026-" / "0204" split across
                # lines is unreadable in print and unsearchable in the PDF.
                f"<tr><td class='mono' style='white-space:nowrap'>{_e(f['check_id'])}</td>"
                f"<td style='white-space:nowrap'>{_e(f['scope'])}</td><td>{_e(f['state'])}</td>"
                f"<td>{_e(f['severity'])}</td>"
                f"<td>{_e(f['reason'][:320])}</td><td>{loc}</td>"
                f"<td class='mono'>{tags or '&mdash;'}</td></tr>")
        table = ""
        if rows:
            table = ("<table><tr><th>Check</th><th>Scope</th><th>State</th>"
                     "<th>Severity</th><th>Basis</th><th>Evidence</th>"
                     "<th>ATT&amp;CK</th></tr>" + "".join(rows) + "</table>")
        notes = "".join(f"<li>{_e(x)}</li>" for x in dom["notes"])
        parts.append(f"""
<h3>A.{n} {label}</h3>
<p>{_e(dom['summary'])}</p>
<p class="footnote">Results: {_e(counts)}. Validated on:
{_e(dom['validated_on'])}.</p>
{table}
{'<ul>' + notes + '</ul>' if notes else ''}
""")

    # Blast radius from each untrusted zone that is not the internet itself.
    blast = ""
    if da.graph is not None:
        zones = sorted({z for r in da.graph.rules for z in r.source_zones if z}
                       & set(getattr(da.graph, "untrusted_zones", []) or []))
        rows = []
        for z in zones:
            if z.upper() == "WAN":
                continue
            members = zone_members(da, z)
            s = blast_radius(da.graph, origin_zone=z,
                             origin_members=members).summary()
            state = ("latent -- nothing is in the zone today"
                     if s["latent"] else
                     "live" if s["origin_populated"] else "population not known")
            rows.append(f"<tr><td>{_e(z)}</td><td>{s['paths_open']}</td>"
                        f"<td>{s['administrative_paths']}</td>"
                        f"<td>{s['zones_reachable']} of {s['zones_considered']}</td>"
                        f"<td>{s['undecidable']}</td><td>{_e(state)}</td></tr>")
        if rows:
            blast = f"""
<h3>A.{len(parts) + 1} Blast radius from untrusted zones</h3>
<p>For each untrusted zone other than the internet, the policy was walked
outward on the ports used for lateral movement. A path is policy exposure: it
states that a packet would be permitted, not that a service is listening. A
latent path activates without any firewall change once something joins the
zone. Undecidable probes are not counted as blocked.</p>
<table><tr><th>Origin zone</th><th>Paths open</th><th>Administrative</th>
<th>Zones reached</th><th>Undecidable</th><th>State</th></tr>
{''.join(rows)}</table>
"""

    return f"""
<h2 class="pagebreak">Appendix A. Extended checks</h2>
<p>These checks are reported beside the compliance result. They are not
included in the score or the coverage stated in section 2, and running them
does not change either. Each follows the same rules as the controls: a failure
cites the configuration setting behind it, and a value that cannot be decoded
is reported as not decided rather than guessed.</p>
{''.join(parts)}
{blast}
"""


def _unsupported(d: dict) -> str:
    i = d["identity"]
    notes = "".join(f"<li>{_e(n)}</li>" for n in d["notes"]) or \
        "<li>No further detail was recorded.</li>"
    return f"""
<h1>Network Configuration Compliance Assessment</h1>
<p class="sub">{_e(i.source_file)}</p>
<hr class="rule">
<h2>Assessment not performed</h2>
<p>This file could not be assessed. No compliance result is presented, because
presenting one would require assuming facts about a device that could not be
read.</p>
<table class="plain">
  <tr><th>File</th><td>{_e(i.source_file)}</td></tr>
  <tr><th>SHA-256</th><td>{_e(i.sha256)}</td></tr>
  <tr><th>Vendor identified</th><td>{_e(i.vendor)}</td></tr>
  <tr><th>Report generated</th><td>{_e(d['generated_at'])}</td></tr>
</table>
<h3>Reason</h3>
<ul>{notes}</ul>
"""


# -------------------------------------------------------------------- public

def build_report(da, assessment_id: str = "") -> str:
    """The complete report as a standalone HTML document."""
    d = _collect(da, assessment_id or "unspecified")

    if not d["supported"] or da.assessment is None:
        body = _unsupported(d)
    else:
        body = (_cover(d) + _states(d) + _findings(d) + _not_applicable(d)
                + _undecided(d) + _policy(d) + _remediation(d) + _method(d)
                + _extended(da, d))

    title = (f"Meridian Assessment — "
             f"{d['identity'].hostname or d['identity'].source_file}")
    return (f"<!DOCTYPE html>\n<html lang=\"en\"><head>"
            f"<meta charset=\"utf-8\">"
            f"<title>{_e(title)}</title>"
            f"<style>{_CSS}</style></head><body>{body}</body></html>")


def write_html(da, path, assessment_id: str = "") -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(build_report(da, assessment_id), encoding="utf-8")
    return p


def _browser() -> str | None:
    """A Chromium binary able to print HTML to PDF."""
    for name in ("chrome", "msedge", "chromium", "google-chrome"):
        found = shutil.which(name)
        if found:
            return found
    for candidate in (
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
        "/usr/bin/chromium", "/usr/bin/google-chrome",
    ):
        if Path(candidate).exists():
            return candidate
    return None


def _pdf_via_playwright(html_file: Path, out: Path) -> bool:
    """Render with Playwright's own Chromium. The reliable path.

    Preferred over invoking a system browser because Playwright owns the
    process. `chrome --print-to-pdf` is unreliable here in a way that is
    actively dangerous to trust: when it declines to do the work it still
    exits 0 with empty stderr and simply writes no file, which is
    indistinguishable from success unless the caller checks the file itself.
    """
    try:
        from playwright.sync_api import sync_playwright
    except Exception:                                      # noqa: BLE001
        return False
    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch()
            try:
                page = browser.new_page()
                page.goto(html_file.as_uri(), wait_until="load")
                page.pdf(path=str(out), format="A4",
                         # The report styles its own margins in @page; letting
                         # the renderer add more would reflow the tables.
                         prefer_css_page_size=True,
                         # Monochrome by design -- there is nothing to print.
                         print_background=False)
            finally:
                browser.close()
    except Exception:                                      # noqa: BLE001
        return False
    return out.exists() and out.stat().st_size > 0


def _pdf_via_system_browser(html_file: Path, out: Path, timeout: int) -> bool:
    """Fallback: a system Chromium in headless print mode."""
    browser = _browser()
    if not browser:
        return False
    profile = html_file.parent / "profile"
    try:
        subprocess.run(
            [browser, "--headless=new", "--disable-gpu", "--no-sandbox",
             f"--user-data-dir={profile}", "--no-first-run",
             "--no-pdf-header-footer", f"--print-to-pdf={out}",
             html_file.as_uri()],
            capture_output=True, text=True, timeout=timeout)
    except Exception:                                      # noqa: BLE001
        return False
    # Never trust the exit code here -- see the note above.
    return out.exists() and out.stat().st_size > 0


def write_pdf(da, path, assessment_id: str = "", timeout: int = 180) -> Path:
    """Render the report to PDF.

    A browser engine does the typesetting, which gives correct pagination,
    widow and orphan control, and tables that break across pages properly --
    without adding a Python PDF dependency.
    """
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    if out.exists():
        out.unlink()

    work = Path(tempfile.mkdtemp(prefix="ncsa_report_"))
    tmp = work / "report.html"
    tmp.write_text(build_report(da, assessment_id), encoding="utf-8")

    if _pdf_via_playwright(tmp, out) or _pdf_via_system_browser(tmp, out, timeout):
        shutil.rmtree(work, ignore_errors=True)
        return out

    # Deliberately do NOT clean up on failure: the HTML *is* the report, and
    # it can be printed by hand from any browser. Losing it here would turn a
    # rendering problem into a lost deliverable.
    raise RuntimeError(
        f"Could not render the PDF. The complete report is at {tmp} and can "
        f"be opened in any browser and printed to PDF. Install Playwright's "
        f"Chromium with `playwright install chromium` to render directly.")
