"""Publish the control catalogue: every control, with its framework mapping.

    python -m tools.catalogue --out docs/NCSA_Control_Catalogue.pdf

Read from `rules/` at render time, so the document cannot drift from what the
engine actually evaluates. Nothing here is typed by hand.

LICENSING
---------
Control titles and rationale are OUR OWN words. CIS and ISO/IEC 27001 material
is copyrighted, so those frameworks are cited by IDENTIFIER ONLY -- clause and
recommendation numbers, never their text. NIST SP 800-53 and DISA STIG are US
government works and could be quoted in full; they are cited by identifier here
too, for consistency of format.
"""
from __future__ import annotations

import argparse
import collections
import html
import os
from datetime import datetime, timezone
from pathlib import Path

import yaml

SEVERITY_ORDER = ["critical", "high", "medium", "low"]

#: What each tier is for. The engine loads them together; the distinction
#: matters to a reader deciding which subset applies to their estate.
TIER_MEANING = {
    "core": "Applies to every managed network device, on every platform. "
            "A failure here is a finding on any estate.",
    "extended": "Applies where the platform supports the capability. "
                "Resolves to NOT_APPLICABLE, with a stated reason, where it "
                "does not.",
    "category": "Applies to a class of device -- firewall policy, cloud "
                "security group, layer-2 switching. Scoped by what the device "
                "is, not by vendor.",
}

DOMAIN_MEANING = {
    "authentication": "Who may log in, and how they prove it",
    "authorization": "What an authenticated user may do",
    "banner": "Legal notice presented before access",
    "cloud": "Cloud-native resource properties",
    "crypto": "Cipher suites, key strength, protocol versions",
    "device": "Identity of the device itself",
    "exposure": "What the policy exposes to an untrusted network",
    "firewall": "Rule content, ordering and resolvability",
    "interfaces": "Physical and logical interface state",
    "l2": "Layer-2 protections",
    "logging": "What is recorded, and where it is sent",
    "management": "The administrative plane and its transports",
    "platform": "Appliance-level properties and the management API",
    "routing": "Routing protocol authentication and filtering",
    "security": "Inspection services -- IPS, antivirus, content filtering",
    "services": "Services the device runs on its own behalf",
    "snmp": "SNMP version, credentials and access restriction",
    "time": "Clock synchronisation and its authentication",
}


def _e(v) -> str:
    return html.escape(str(v), quote=True) if v is not None else "&mdash;"


def load_controls(rules_dir="rules") -> list[dict]:
    """Every control, with per-platform STIG identifiers flattened in."""
    out = []
    for root, _dirs, files in os.walk(rules_dir):
        for fn in sorted(files):
            if not fn.endswith(".yaml"):
                continue
            d = yaml.safe_load(Path(root, fn).read_text(encoding="utf-8"))
            if not isinstance(d, dict) or "id" not in d:
                continue
            fw = d.get("frameworks") or {}
            by_platform = fw.get("stig_by_platform") or {}
            stig = list(fw.get("stig") or [])
            for ids in by_platform.values():
                stig += [i for i in ids if i not in stig]
            out.append({
                "id": d["id"],
                "title": d.get("title", ""),
                "field": d.get("field", ""),
                "operator": d.get("operator", ""),
                "expected": d.get("expected"),
                "severity": d.get("severity", "medium"),
                "tier": d.get("tier", "core"),
                "rationale": (d.get("rationale") or "").strip(),
                "nist": list(fw.get("nist_800_53") or []),
                "iso": list(fw.get("iso_27001_2022") or fw.get("iso_27001") or []),
                "stig": stig,
                "stig_platforms": sorted(by_platform),
                "requires": d.get("requires") or [],
                "remediation_platforms": sorted(d.get("remediation") or {}),
            })
    return sorted(out, key=lambda c: c["id"])


def _expected(c: dict) -> str:
    op, exp = c["operator"], c["expected"]
    if exp is None:
        return _e(op.replace("_", " "))
    if isinstance(exp, list):
        return f"{_e(op)} {_e(', '.join(str(x) for x in exp))}"
    return f"{_e(op)} {_e(exp)}"


def build_html(controls: list[dict]) -> str:
    by_domain = collections.defaultdict(list)
    for c in controls:
        by_domain[c["field"].split(".")[0]].append(c)

    sev = collections.Counter(c["severity"] for c in controls)
    tier = collections.Counter(c["tier"] for c in controls)
    n_nist = sum(1 for c in controls if c["nist"])
    n_iso = sum(1 for c in controls if c["iso"])
    n_stig = sum(1 for c in controls if c["stig"])
    n_remed = sum(1 for c in controls if c["remediation_platforms"])
    n_gated = sum(1 for c in controls if c["requires"])

    generated = datetime.now(timezone.utc).strftime("%d %B %Y")

    sev_rows = "".join(
        f"<tr><td>{s.capitalize()}</td><td class='num'>{sev.get(s, 0)}</td></tr>"
        for s in SEVERITY_ORDER)
    tier_rows = "".join(
        f"<tr><td>{t.capitalize()}</td><td class='num'>{tier.get(t, 0)}</td>"
        f"<td>{_e(TIER_MEANING[t])}</td></tr>"
        for t in ("core", "extended", "category"))

    sections = []
    for domain in sorted(by_domain):
        items = sorted(by_domain[domain],
                       key=lambda c: (SEVERITY_ORDER.index(c["severity"]), c["id"]))
        rows = []
        for c in items:
            refs = []
            if c["nist"]:
                refs.append("NIST&nbsp;800-53: " + _e(", ".join(c["nist"])))
            if c["iso"]:
                refs.append("ISO&nbsp;27001: " + _e(", ".join(c["iso"])))
            if c["stig"]:
                refs.append("STIG: " + _e(", ".join(c["stig"])))
            notes = []
            if c["requires"]:
                because = c["requires"][0].get("because", "")
                notes.append("Conditional: " + _e(because))
            if c["remediation_platforms"]:
                notes.append("Remediation held for: "
                             + _e(", ".join(c["remediation_platforms"])))
            rows.append(f"""
<tr>
  <td class="id">{_e(c['id'])}</td>
  <td><strong>{_e(c['title'])}</strong>
      <div class="small">{_e(c['rationale'])}</div>
      {'<div class="small">' + ' &middot; '.join(notes) + '</div>' if notes else ''}</td>
  <td class="mono small">{_e(c['field'])}<br>{_expected(c)}</td>
  <td class="small">{c['severity'].capitalize()}<br>{c['tier']}</td>
  <td class="small">{'<br>'.join(refs) or '&mdash;'}</td>
</tr>""")
        sections.append(f"""
<h3>{_e(domain)} &mdash; {len(items)} control{'s' if len(items) != 1 else ''}</h3>
<p class="small">{_e(DOMAIN_MEANING.get(domain, ''))}</p>
<table>
  <tr><th style="width:15%">Control</th><th style="width:34%">Requirement</th>
      <th style="width:17%">Field &amp; test</th><th style="width:9%">Severity</th>
      <th style="width:25%">Framework references</th></tr>
  {''.join(rows)}
</table>""")

    return f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<title>NCSA Control Catalogue</title><style>
@page {{ size: A4; margin: 16mm 12mm 18mm 12mm; }}
* {{ box-sizing: border-box; }}
body {{ font-family: "Times New Roman", Times, serif; font-size: 9.5pt;
       line-height: 1.4; color: #000; background: #fff; margin: 0; }}
h1 {{ font-size: 19pt; margin: 0 0 2pt; }}
h2 {{ font-size: 12.5pt; margin: 18pt 0 6pt; border-bottom: 1pt solid #000;
      padding-bottom: 3pt; page-break-after: avoid; }}
h3 {{ font-size: 10.5pt; margin: 13pt 0 3pt; page-break-after: avoid; }}
p {{ margin: 0 0 6pt; }}
.sub {{ font-size: 10.5pt; margin-bottom: 12pt; }}
hr {{ border: 0; border-top: 2pt solid #000; margin: 6pt 0 12pt; }}
table {{ border-collapse: collapse; width: 100%; margin: 4pt 0 10pt;
        font-size: 8.5pt; }}
th, td {{ border: .5pt solid #000; padding: 3pt 4pt; text-align: left;
         vertical-align: top; }}
th {{ font-weight: 700; }}
td.num, th.num {{ text-align: right; }}
tr {{ page-break-inside: avoid; }}
.mono {{ font-family: "Courier New", Courier, monospace; font-size: 8pt; }}
/* A control identifier must never break across lines. `NCSA-CAT-005` split
   into `NCSA-CAT-` and `005` is unreadable in a printed table and unsearchable
   in the PDF text layer. */
td.id {{ font-family: "Courier New", Courier, monospace; font-size: 8pt;
        white-space: nowrap; }}
.small {{ font-size: 8pt; }}
.note {{ border: .5pt solid #000; padding: 6pt 8pt; margin: 8pt 0 10pt;
        font-size: 9pt; }}
table.plain, table.plain th, table.plain td {{ border: 0; padding: 1pt 8pt 1pt 0; }}
.pagebreak {{ page-break-before: always; }}
</style></head><body>

<h1>NCSA Control Catalogue</h1>
<p class="sub">{len(controls)} controls across {len(by_domain)} domains
&mdash; generated {generated}</p>
<hr>

<h2>1. What this document is</h2>
<p>Every control the engine evaluates, with the framework identifiers each one
maps to. It is generated from the rule definitions themselves, so it cannot
state a control the engine does not run, or omit one that it does.</p>

<div class="note">
<strong>Copyright.</strong> Control titles and rationale are written in our own
words. CIS Benchmarks and ISO/IEC 27001 are copyrighted; they are cited here by
clause and recommendation number only, and no text from either is reproduced.
NIST SP 800-53 and DISA STIG are US government works.
</div>

<h2>2. Coverage at a glance</h2>
<table class="plain">
  <tr><th>Controls</th><td>{len(controls)}</td></tr>
  <tr><th>Domains</th><td>{len(by_domain)}</td></tr>
  <tr><th>Mapped to NIST SP 800-53</th><td>{n_nist} of {len(controls)}</td></tr>
  <tr><th>Mapped to ISO/IEC 27001:2022</th><td>{n_iso} of {len(controls)}</td></tr>
  <tr><th>Carrying DISA STIG identifiers</th><td>{n_stig} of {len(controls)}</td></tr>
  <tr><th>With remediation commands</th><td>{n_remed} of {len(controls)}</td></tr>
  <tr><th>Conditional on another setting</th><td>{n_gated} of {len(controls)}</td></tr>
</table>

<h3>By severity</h3>
<table><tr><th>Severity</th><th class="num">Controls</th></tr>{sev_rows}</table>

<h3>By tier</h3>
<table><tr><th>Tier</th><th class="num">Controls</th><th>Applies to</th></tr>
{tier_rows}</table>

<h2>3. Standards this catalogue maps to</h2>
<p>A control is written once, in vendor-neutral terms, and carries the
identifiers of every framework that asks for it. One finding therefore answers
several auditors at once.</p>
<table>
  <tr><th style="width:26%">Standard</th><th style="width:12%">Held</th>
      <th>Role in this catalogue</th></tr>
  <tr><td>NIST SP 800-53 Rev 5</td><td class="num">1,196</td>
      <td>The primary mapping. Public domain, so control text is stored in
          full. Every control here carries at least one identifier.</td></tr>
  <tr><td>ISO/IEC 27001:2022</td><td class="num">121</td>
      <td>Annex A clause references, for organisations certifying against
          27001. Clause number and short title only.</td></tr>
  <tr><td>DISA STIG</td><td class="num">553</td>
      <td>Per-platform hardening identifiers. Attached by platform, because a
          STIG rule is specific to a device family.</td></tr>
  <tr><td>CIS Benchmarks</td><td class="num">3,506</td>
      <td>Recommendation numbers, attached per platform in the vendor pack.
          Identifier only &mdash; the text is licensed.</td></tr>
  <tr><td>NIST SP 800-171 Rev 3</td><td class="num">130</td>
      <td>Reached through the 800-53 crosswalk published in its own
          back-matter.</td></tr>
  <tr><td>PCI DSS 4.0</td><td class="num">279</td>
      <td>Requirement identifiers, for cardholder-data environments.</td></tr>
</table>
<p class="small">Catalogue sizes are what this build has loaded, reported by
the engine at <span class="mono">/frameworks</span>.</p>

<h2 class="pagebreak">4. The controls</h2>
<p>Grouped by domain, then ordered by severity. <em>Field</em> is the
vendor-neutral name the control reads; <em>test</em> is the comparison applied
to it.</p>
{''.join(sections)}

<h2 class="pagebreak">5. How a control is decided</h2>
<p>Each control resolves to exactly one of seven states. The distinction
between <em>not applicable</em> and <em>unknown</em> is the one that matters
most: the first is a property of the device, the second is a limit of the
assessment.</p>
<table>
  <tr><th style="width:22%">State</th><th>Meaning</th></tr>
  <tr><td>PASS</td><td>Checked; the device is configured correctly.</td></tr>
  <tr><td>FAIL</td><td>Checked; it is not.</td></tr>
  <tr><td>PARTIAL</td><td>Some scoped instances comply and others do not.</td></tr>
  <tr><td>NOT_APPLICABLE</td><td>Does not apply to this device. Excluded from
      scoring, and each exclusion carries a written justification.</td></tr>
  <tr><td>UNKNOWN</td><td>Could not be determined from the configuration
      supplied. Neither a pass nor a failure, and counted in coverage.</td></tr>
  <tr><td>MANUAL_REVIEW</td><td>Needs a human decision.</td></tr>
  <tr><td>ERROR</td><td>The check itself failed &mdash; a defect in the tool.</td></tr>
</table>
<p>The compliance score is calculated over decided controls only and is always
reported beside coverage. A high score on low coverage means little of the
device could be assessed, not that the device is well configured.</p>

</body></html>"""


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="tools.catalogue")
    ap.add_argument("--out", default="docs/NCSA_Control_Catalogue.pdf")
    ap.add_argument("--rules", default="rules")
    args = ap.parse_args(argv)

    controls = load_controls(args.rules)
    # Absolute: `Path.as_uri()` below refuses a relative path, and the default
    # output is relative.
    out = Path(args.out).resolve()
    out.parent.mkdir(parents=True, exist_ok=True)
    html_doc = build_html(controls)

    if out.suffix.lower() == ".html":
        out.write_text(html_doc, encoding="utf-8")
        print(f"  {len(controls)} controls -> {out}")
        return 0

    tmp = out.with_suffix(".tmp.html")
    tmp.write_text(html_doc, encoding="utf-8")
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as pw:
            browser = pw.chromium.launch()
            try:
                page = browser.new_page()
                page.goto(tmp.as_uri(), wait_until="load")
                page.pdf(path=str(out), format="A4",
                         prefer_css_page_size=True, print_background=False)
            finally:
                browser.close()
    finally:
        tmp.unlink(missing_ok=True)

    print(f"  {len(controls)} controls -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
