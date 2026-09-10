# Brief — Build the SIH 2026 Idea Submission PPT for NCSA

Paste this whole file into Claude Code. It contains the task, the hard
constraints, and all the source material needed. **Do not invent facts that are
not in section 5.**

---

## 1. The task

Produce the Smart India Hackathon 2026 **Idea Submission** deck for **NCSA —
Network Compliance & Security Auditor**, using the official template at:

```
E:\SIH2026-IDEA-Presentation-Format.pptx
```

Deliver:

| File | Purpose |
|---|---|
| `E:\NCSA\docs\NCSA_SIH_Idea.pptx` | Editable deck, built on the official template |
| `E:\NCSA\docs\NCSA_SIH_Idea.pdf` | **The upload artefact.** SIH accepts PDF only |

Build it with `python-pptx` against a copy of the template. Do not rebuild the
template from scratch — the portal expects its layout.

---

## 2. Hard constraints — read before writing a single slide

These come from the template's own instruction slide. Breaking them risks the
submission.

1. **Maximum six slides, including the title slide.** You have exactly five
   content slides. This is the single most important constraint.
2. **Do not change the idea-detail pointers** already printed on each template
   slide (the grey prompt text describing what belongs there). Add content
   around them; do not rewrite the template's own headings.
3. **No paragraphs.** Points, diagrams, infographics and pictures only. If a
   thought needs three lines of prose, it is a diagram instead.
4. Keep explanations precise and easy to understand. A judge reads a slide in
   under a minute.
5. **Delete the final "Important Instructions" slide** before export.
6. Export to PDF. The `.pptx` is a working file; the PDF is the deliverable.

Template slide order, which you must keep:

| # | Template heading | What goes there |
|---|---|---|
| 1 | TITLE PAGE | Problem statement ID/title, theme, category, team ID, team name |
| 2 | IDEA TITLE | Proposed solution, how it addresses the problem, innovation |
| 3 | TECHNICAL APPROACH | Technologies, methodology, working diagram |
| 4 | FEASIBILITY AND VIABILITY | Feasibility, risks, mitigations |
| 5 | IMPACT AND BENEFITS | Impact on target audience, benefits |
| 6 | RESEARCH AND REFERENCES | Links and reference work |

Leave the title-slide placeholders (Problem Statement ID, Team ID, Team Name)
as clearly-marked blanks for the user to fill — **do not invent them.**

---

## 3. What must NOT go in the deck

- **No test results.** No pass counts, no benchmark tables, no before/after
  measurements, no F1 or accuracy figures, no coverage percentages from a
  specific device run. This deck is about capability, not evaluation.
- **No third-party tool or library names** for anything used internally as a
  cross-check or helper. Describe the *capability* ("an independent second
  method re-derives each finding"), never the dependency's name.
- **No CIS Benchmark prose.** CIS content is copyrighted. Cite only the
  recommendation number and the benchmark title, in your own words.
- **No ISO/IEC 27001 clause text.** Clause number and short title only.
- **No invented numbers.** Every figure must come from section 5. If a number
  is not there, do not state one.
- No stock "cyber" imagery — no padlocks, no matrix rain, no hooded figures.

---

## 4. What makes NCSA unique — lead with this

SIH scores on novelty. These are the differentiators; they should shape slides
2 and 3 rather than being a footnote.

**1. It can say "I don't know", and that is the core design decision.**
Most compliance tools return a single percentage. NCSA has a first-class
`UNKNOWN` result for "the configuration does not state this". It carries no risk
score, is never coloured as a pass, and the **coverage** figure travels beside
the **compliance** figure everywhere both appear. A device that could barely be
read can therefore never look like a device that mostly passed.

**2. AI proposes, deterministic code decides.**
The language model never issues a pass or a fail. It assists with mapping
unknown vendor settings and with explanation. Every compliance verdict comes
from deterministic rule code. This is the inverse of most "AI security" tools
and is the claim a judge should remember.

**3. Local *inference*, not merely local operation.**
Offline operation on its own is table stakes in this market — a serious
competitor already ships an air-gapped tier, so **do not pitch "runs offline" as
the novelty.** The claim that holds is narrower and stronger: NCSA runs a
*language model* on-device. No hosted endpoint, no API key, no telemetry, and
the models are not fine-tuned on customer configurations, so nothing audited is
ever absorbed into a weight. Comparable tools do not claim on-device AI at all.

**4. Adding a vendor is a data file, not a code change.**
Grammar-family readers plus one declarative mapping pack per platform. A new
platform reuses an existing reader and supplies only its mapping. Parsers are
generated as **data, never as code**, so there is no execution path from an
attacker-supplied configuration file.

**5. Learning is regression-gated.**
When a human approves a new mapping, a corpus of already-verified results is
re-run first. If the change would alter a known-good result, the approval is
**refused and leaves nothing behind**. This stops the training loop from
becoming a way to poison the tool.

**6. Absence is reported as absence.**
Every finding cites the file and the line that produced it — necessary, but not
by itself unique; a direct competitor does this too, so state it as a principle
rather than as a differentiator. What *is* distinctive is the other half: a
setting that is simply not present is never scored as passing. It becomes an
explicit `UNKNOWN`, which is what differentiator 1 is built on.

**7. Real provenance between frameworks.**
A control maps through published crosswalks — STIG → CCI → NIST → ISO — not
through text-similarity guessing. Every citation can be followed back to source.

**8. Findings are corroborated.**
Each finding is re-derived by an independent method. Where the two disagree, the
dispute is **surfaced** rather than silently resolved in favour of whichever ran
last.

**9. Remediation that cannot lock you out.**
Generated fixes are ordered and rollback-wrapped. Any step that would sever the
only live management path is deferred and flagged, never shipped silently inside
the script.

**10. The model is the last resort, not the first.**
Mapping an unknown setting escalates through **five tiers**, cheapest first:

| Tier | Method | Cost | Used for |
|---|---|---|---|
| 0 | Exact pattern from the mapping pack | ~1 ms | Known vendors |
| 1 | Registry of previously approved mappings | ~1 ms | Already learned |
| 2 | Local NLP pipeline | ~50 ms | Unknown vendor, familiar vocabulary |
| 3 | Local model + retrieval | ~5 s | Genuinely novel |
| 4 | Human approval | — | Below every confidence threshold |

The language model runs only when everything cheaper has failed. This is why the
tool is fast on a real estate, and it is the honest answer to "where does the AI
actually get used?"

**11. Retrieval where retrieval works; derivation where it does not.**
Framework mappings are authored per baseline field. STIG and CIS entries are
**retrieved** — their text is long and contains the actual vendor command. NIST
and ISO entries are **derived** instead, through the published CCI and OLIR
crosswalks, because their catalogue text is far too short and abstract for
retrieval to rank meaningfully. Choosing a different method per framework —
rather than applying one technique everywhere — is what makes the citations
trustworthy.

**12. Risk is computed, not looked up.**
`Risk = Severity × Exposure × Confidence × Asset Criticality`, where **exposure
is derived from the configuration itself**. An insecure setting on an
unreachable interface does not outrank one on the edge.

---

## 4b. The capability matrix — put this on slide 2

This is the strongest single argument in the deck. Draw it as a real table with
tick marks, not as bullets. The top rows establish parity with serious tooling;
the accented rows at the bottom are the ones only NCSA ticks.

| Capability | Network modelling tools | Firewall orchestration suites | Commercial config managers | Nipper *(Titania)* | **NCSA** |
|---|:---:|:---:|:---:|:---:|:---:|
| Config auditing vs frameworks | — | partial | ✓ | ✓ | **✓** |
| **Evidence per finding** | — | — | — | **✓** | **✓** |
| Vendor-specific remediation | — | partial | partial | ✓ | **✓** |
| Runs air-gapped / offline | ✓ | ✓ | partial | ✓ | **✓** |
| Rule hygiene | ✓ | ✓ | ✓ | not stated | **✓** |
| Reachability analysis | ✓ | — | — | partial | **✓** |
| Change tracking | ✓ | ✓ | ✓ | not stated | **✓** |
| Recertification workflow | — | ✓ | ✓ | not stated | **✓** |
| Log correlation | — | — | ✓ | not stated | **✓** |
| Multi-device topology | ✓ | ✓ | ✓ | partial | **✓** |
| **Framework provenance chains** | — | partial | partial | not stated | **✓** |
| **Honest coverage (UNKNOWN state)** | — | — | — | not stated | **✓** |
| **Local AI assistance** | — | — | — | not stated | **✓** |
| **Human-approved learning loop** | — | — | — | not stated | **✓** |

**Legend — and use it on the slide.** `✓` stated capability · `partial`
partially stated · `—` not offered · **`not stated`** *not claimed in the
vendor's public documentation*.

That last distinction is not pedantry. "Not stated" is verifiable and
unattackable; a dash is a claim about someone else's product that you would have
to defend. Print the legend so a judge sees you were careful.

### Two claims that did NOT survive checking — do not make them

These were in an earlier draft of the pitch and are **wrong**:

1. **"Only we cite evidence per finding."** Nipper states that findings "trace
   to the exact line or setting that failed" and that it links findings to the
   configuration statements that caused them. **They do this. Concede the row.**
2. **"Only we run air-gapped."** Nipper ships an air-gapped tier for offline
   operation in restricted networks. Offline operation is table stakes in this
   market, not a differentiator.

Conceding both makes the deck *stronger*. A matrix where you tick every row and
every competitor is blank reads as marketing and a knowledgeable judge will
discount the whole thing. Winning four rows honestly beats winning fourteen
implausibly.

### What genuinely remains yours

- **Honest coverage** — a first-class `UNKNOWN` result and a coverage figure
  that travels beside every score. No comparator claims an equivalent.
- **Local AI assistance with deterministic verdicts** — Nipper's materials do
  not claim AI or ML at all. Ours assists with mapping and explanation while
  never issuing a pass or fail.
- **Human-approved, regression-gated learning loop** — and with it, a defined
  answer for an unsupported vendor. Nipper's public materials do not address
  unknown-device handling.
- **Framework provenance chains** — mappings that resolve through published
  crosswalks and can be followed back to source, rather than a list of supported
  frameworks.

**Caption the table with the takeaway:**
> *Parity on the table stakes. What is left is the difference between a report
> you read and a report you can check.*

**Sources for the Nipper column** (cite these on slide 6, not on the matrix):
titania.com product pages for Nipper InfraSight and Nipper OmniSight, and their
NERC CIP compliance page. Every mark above comes from Titania's own published
wording — **re-verify before submission, because vendor pages change.**

---

## 5. Complete feature inventory — source material

Compress this; do not paste it. Slides 2 and 3 should carry it as grouped
bullets and diagrams.

### Ingestion and parsing
- Grammar-family readers: indented CLI, brace-delimited, block-structured,
  exported-settings, XML, JSON, and host firewall.
- Single-file and bulk ingestion. One unreadable file never aborts a batch.
- Device fingerprinting and identity extraction (hostname, vendor, platform,
  model, serial, OS/version). A serial the config does not state is reported as
  "not stated", never as a placeholder.
- Redaction is **on by default** — real exports carry password hashes and live
  addressing.
- Uploads are treated as untrusted: written to a temp path, never executed,
  never interpolated into a prompt.

### Normalisation
- **Security Baseline Model (SBM)** — a vendor-neutral schema of **119 fields**
  in a flat dotted namespace.
- Every value is an *observation* carrying its source, its confidence, its
  evidence, and whether it was **observed**, **assumed from a documented
  default**, **not observed**, or **unparsed**.
- Object graph construction with reference resolution and cycle detection. An
  unresolvable reference is marked unresolved — never silently emptied.

### Evaluation
- Deterministic control engine over the baseline model.
- Result states: **PASS · FAIL · PARTIAL · NOT_APPLICABLE · MANUAL_REVIEW ·
  UNKNOWN · ERROR**.
- **Honest coverage**: the compliance score is computed over *decided* controls
  only and is always displayed beside the assessed percentage.
- Preconditions, so a control that genuinely does not apply is marked
  not-applicable rather than failed.

### Policy analysis
- **Rule hygiene**: shadowed, redundant, unused, overly permissive, disabled and
  orphaned rules — cross-checked against live hit counters, with disputes
  surfaced rather than assumed.
- **Reachability**: first-match-wins evaluation across the rule base.
- **Topology**: multi-device fabric with per-hop verdicts, and a stated caveat
  on every answer.
- **Change tracking**: device change is distinguished from analysis change, so a
  new engine version does not masquerade as a configuration drift.
- **Recertification** and rule-ownership register.
- **Log correlation** to confirm whether an unused rule is genuinely unused or
  whether its counter was merely reset.

### Frameworks
- **NIST SP 800-53**, **DISA STIG**, **CIS Benchmarks**, **ISO/IEC 27001:2022**.
- Provenance chains STIG → CCI → NIST → ISO through published crosswalks.
- **Licence enforcement in the type system**: catalogues are tagged
  public-domain or identifier-only, and identifier-only content cannot be
  emitted as text by construction.

### Remediation
- Ordered, phased command generation (prepare → enable → harden → disable-last).
- Per-platform rollback wrapper.
- Lockout guard: a step disabling the only live management transport is
  returned as *deferred*, never placed in the runnable script.

### The AI layer
- **Local inference only**, via an on-device model runtime.
- Retrieval-augmented; **no fine-tuning on customer configurations**.
- Assists with: mapping unseen vendor settings to baseline fields, ranking
  candidate mappings, and drafting human-readable explanation.
- **Never issues a verdict.**
- **Five-tier escalation router** — pack pattern → approved registry → NLP
  pipeline → local model with retrieval → human. Each tier has a confidence
  threshold; work falls through only when the cheaper tier is not confident.
- **Constrained-decoding re-ranker.** When the model chooses among candidate
  baseline fields, the permitted field names are a **decoder enum**: an
  off-schema name is not merely rejected afterwards, it is *ungeneratable*.
  `null` is always a permitted answer, so **"none of these" is a first-class
  outcome** rather than a forced wrong guess.
- **Framework mapping authoring.** For every baseline field the system proposes
  candidate controls in all four frameworks. Nothing is written to the rule set:
  a proposal stays *proposed* until a person approves it.
- Type gate: a candidate mapping's *value type* constrains the search before any
  model runs. The type prior is a **multiplier, never a hard filter** — a hard
  filter that is wrong is unrecoverable.
- Human-in-the-loop approval queue, deduplicated by setting name, so one
  approval covers every instance of that name on every device of the platform.
- Approvals are **regression-gated and hash-chained**.
- Guardrails: **NIST AI RMF · MITRE ATLAS · OWASP LLM Top 10 · ISO/IEC 42001**.
- AI-security content is kept strictly out of the parser corpus by an automated
  tripwire, so guardrail material can never leak into mapping suggestions.

### Verified capability figures — use only these

| Figure | Value |
|---|---|
| SBM schema fields | **119** |
| Framework controls loaded | **5,785** |
| — NIST SP 800-53 | 1,196 |
| — CIS Benchmarks | 3,506 |
| — DISA STIG | 553 |
| — PCI DSS 4.0.1 | 279 *(identifiers only)* |
| — NIST SP 800-171 Rev 3 | 130 |
| — ISO/IEC 27001:2022 | 121 |
| Compliance frameworks, populated | **6** |
| Frameworks supported *(2 awaiting a source catalogue)* | **8** |
| Platform mapping packs | **7** |
| Grammar-family readers | **6** (plus a host-firewall reader) |
| Vendor setting mappings | **253** |
| Automated controls | **81** |
| — reaching NIST 800-171 via crosswalk | **79** |
| Result states | **7** |
| Bytes leaving the network | **0** |

**On the two frameworks at zero.** CMMC and NERC CIP are wired in and load from a
source catalogue when one is present; neither is populated today. **Do not put
them on a slide as supported.** If framework breadth is claimed, say "six
frameworks" — the honest number — and mention CMMC only as roadmap, never as
current capability. The engine reports *why* each is empty rather than showing a
bare zero.

**Worth a bullet on slide 3:** 800-171 is not maintained by hand. NIST's own
OSCAL catalogue embeds the 800-53 crosswalk, so **79 of the 81 controls reach
800-171 automatically, with no rule changes** — the same derive-don't-retrieve
pattern used for ISO.

> **Consistency note.** The marketing website in `E:\NCSA\web` states *12
> platforms / 60 controls / ~600 framework controls* as forward-looking targets.
> The table above is what the engine currently reports. **Pick one set and use it
> throughout the deck.** Do not mix them. If the roadmap numbers are used, label
> them as targets.

---

## 6. Tech stack — for slide 3

- **Engine**: Python. Deterministic rule evaluation, no execution path from
  configuration input.
- **Schema**: declarative YAML mapping packs, one per platform.
- **AI runtime**: local on-device inference with a small instruct model for
  reasoning and an embedding model for retrieval.
- **Retrieval**: vector search over framework catalogues, retrieval-augmented
  only.
- **API**: FastAPI, serving both the operator console and the programmatic
  interface from one process.
- **Console**: single-page operator UI — ingest, results, rule hygiene, training
  queue, remediation.
- **Marketing site**: Next.js, TypeScript, Tailwind, static export.

---

## 7. Diagrams to draw — these carry the deck

Because paragraphs are banned, the diagrams *are* the explanation. Draw them as
native PowerPoint shapes (`python-pptx` autoshapes and connectors) so they stay
crisp and editable. **Do not embed screenshots of code or of the console.**

**Diagram A — the pipeline (slide 3, the centrepiece).**
A left-to-right flow of six labelled stages:
`Config Ingest → Grammar Reader → Security Baseline Model → Rule Engine →
Framework Mapping → Findings & Remediation`
Annotate underneath: *"AI assists at Grammar Reader and Framework Mapping.
Verdicts are issued only by the Rule Engine."*

**Diagram B — the air-gap (slide 2 or 3).**
A boundary line labelled **AIR-GAP**. Everything — config files, the model
runtime, the rule engine — sits inside. Outside is empty, labelled **0 BYTES**.
This diagram is the strongest single visual in the deck.

**Diagram C — vendor fan-in (slide 2).**
Many vendor syntaxes converging on one SBM box, then fanning out to the four
framework logos/labels. Shows "many in, one truth, four out" without prose.

**Diagram D — the risk product (slide 5 or 3).**
Four small dials multiplying into one score:
`Severity × Exposure × Confidence × Asset Criticality`.
Label exposure *"computed from the configuration itself"*.

**Diagram E — the honest-coverage figure (slide 2).**
A ring where the compliance arc is nested *inside* the coverage arc, so the
compliance arc can never be drawn longer than the part of the device that was
actually read. Caption: *"score, and how much of the device it covers"*.

---

## 8. Slide-by-slide content plan

**Slide 1 — Title.** Fill the template fields. Leave Problem Statement ID, Team
ID and Team Name as visible blanks for the user.

**Slide 2 — Idea Title / Proposed Solution.**
- One-line definition of NCSA.
- Diagram C (vendor fan-in) and Diagram E (honest coverage).
- Four to six bullets drawn from section 4, led by *"AI proposes, deterministic
  code decides"* and *"fully local"*.
- **The capability matrix from section 4b** — this is the slide's anchor.

**Slide 3 — Technical Approach.**
- Diagram A (pipeline) as the dominant element.
- Diagram B (air-gap) beside it.
- A compact tech-stack strip from section 6.
- Two or three bullets on the AI layer and its guardrails.

**Slide 4 — Feasibility and Viability.**
- Feasibility: working engine; declarative packs mean linear cost per new
  vendor; runs on commodity hardware with no cloud dependency.
- Risks and the mitigation already built for each — state them as pairs:
  - *Unknown vendor syntax* → vendor-agnostic detectors plus a human-approved
    training queue.
  - *Model error* → the model never issues verdicts; deterministic code does.
  - *Bad learned mapping* → approvals are regression-gated and refused if they
    break a verified result.
  - *Untrusted input* → parsers are data, not code; nothing is executed.
  - *Remediation causing an outage* → rollback-wrapped, lockout-guarded.
  - *Licensing of benchmark content* → identifier-only enforcement in the type
    system.

**Slide 5 — Impact and Benefits.**
- Audience: network and security teams, auditors, defence and public-sector
  operators who cannot use cloud tooling.
- Benefits, as points: weeks of manual review compressed; evidence that survives
  an auditor's questions; one auditor across a mixed estate; usable in
  air-gapped environments; remediation that is safe to run.
- Note the honest-coverage principle as a *trust* benefit, not a feature.

**Slide 6 — Research and References.**
- NIST SP 800-53 Rev. 5 (control catalogue)
- NIST SP 800-53B / OLIR crosswalk to ISO/IEC 27001
- DISA STIGs and the CCI list (STIG → NIST mapping)
- CIS Benchmarks (cited by identifier and benchmark title only)
- ISO/IEC 27001:2022 (clause identifiers only)
- NIST AI Risk Management Framework
- MITRE ATLAS
- OWASP Top 10 for LLM Applications
- ISO/IEC 42001 (AI management systems)

---

## 9. Visual style

- Dark slides. Near-black background, one cyan accent, white text.
- Headline type heavy and tight; labels in monospace uppercase with wide
  letter-spacing.
- Colour on **data only** — a state colour never used decoratively.
- Generous spacing. A judge should see structure before reading a word.
- Every slide readable when projected: minimum 14pt body, high contrast.

---

## 10. Before you finish — check each of these

- [ ] Exactly six slides; the instructions slide deleted.
- [ ] No paragraph longer than two lines anywhere.
- [ ] No test results, benchmark numbers or evaluation metrics.
- [ ] No third-party tool or library names for internal helpers.
- [ ] No CIS or ISO prose — identifiers and titles only.
- [ ] Every number traceable to section 5, and one number set used throughout.
- [ ] The capability matrix is present, with its legend printed.
- [ ] The deck does NOT claim evidence-per-finding or air-gapped operation as
      unique — both were checked and both are matched by a competitor.
- [ ] Title-slide blanks left for the user, not invented.
- [ ] Exported to PDF, and the PDF opens and is the correct page count.
- [ ] Report to the user what you left blank and any figure you had to choose
      between.
