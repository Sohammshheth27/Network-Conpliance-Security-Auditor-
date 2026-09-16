# NCSA Application Design System

## 1. DOCUMENT STATUS
- **Document Name:** NCSA_APP_DESIGN_SYSTEM.md
- **Purpose:** The definitive visual, UX, and operational design specification for the NCSA frontend.
- **Current Status:** Final / Active
- **Source of Truth:** 6 reference images, `frontend/Design/design.md`, and the current React frontend implementation.
- **Last Audited Date:** September 2026
- **Intended Audience:** Future AI agents, Antigravity, Claude, GPT, and human developers.

---

## NCSA DESIGN CONTRACT
**This document governs all future NCSA UI/UX work.**

Any AI agent or developer modifying the frontend **must read this document before implementation.** 

Future work must extend the existing system rather than creating a competing design language. When a request conflicts with an established design rule, the contributor must identify the conflict before implementation and seek explicit approval. 

**Terminology Used in this Document:**
- **ESTABLISHED:** Currently implemented and confirmed in the frontend code.
- **REFERENCE / INTENDED:** Supported by the supplied visual references but not necessarily fully implemented yet.
- **IMPLEMENTATION GAP:** Desired/established behavior that current code does not yet fully satisfy.
- **PROHIBITED:** Behavior future contributors must not introduce.

---

## DESIGN INVARIANTS — DO NOT CHANGE WITHOUT EXPLICIT APPROVAL

The following established elements must be preserved. Future agents must preserve these unless explicitly asked to change them.

1. **Overall Visual Language (ESTABLISHED):** Restrained, professional, high-density. *Why:* NCSA is an operational auditing tool, not a consumer SaaS app.
2. **Color System (ESTABLISHED):** Navy Ink (`--color-ink-navy`), Signal Blue (`--color-signal-blue`), Cloud (`--color-cloud`), Paper (`--color-paper`), Pebble (`--color-pebble`), Hairline (`--color-hairline`). *Why:* Prevents competing brand identities and guarantees AAA contrast while providing editorial warmth.
3. **Typography System (ESTABLISHED):** Highly structured bold headings with clean geometric body text (Gilroy/Inter). *Why:* Ensures data scanability and editorial weight.
4. **Spacing Rhythm (ESTABLISHED):** Strict 8px base unit multiples (4px micro, 8px tight, 16px related, 24px internal, etc.). *Why:* Maintains vertical alignment and predictable visual clustering.
5. **Sidebar Geometry (ESTABLISHED):** Fixed rail on the left. *Why:* Predictable, constant spatial orientation for navigation.
6. **Navigation Structure (ESTABLISHED):** Linear, left-side rail with active highlighting. *Why:* Prevents deep nested menus from hiding operational views.
7. **Active Navigation Indicator (ESTABLISHED):** Smooth vertical translation. *Why:* Provides continuity rather than jumpy unmounting state changes.
8. **Header Structure (ESTABLISHED):** Top header for global actions (Search, Export, Settings). *Why:* Keeps global actions out of the page-level workflow.
9. **Card Language (ESTABLISHED):** White (`bg-white`), 1px hairline border, `shadow-sm`, with specific radii (16px or 24px). *Why:* Maintains consistent elevation and bounding boxes for complex data.
10. **Border Language (ESTABLISHED):** 1px solid `--color-hairline`. *Why:* Keeps separators crisp without visual noise.
11. **Shadow Language (ESTABLISHED):** Blue-tinted shadow stacks (`--shadow-sm`, etc.). *Why:* Pure black drop shadows break the cool-stone aesthetic of the UI.
12. **Table Language (ESTABLISHED):** Dense, bordered rows with hover states, distinct column headers. *Why:* NCSA is an auditing tool; data density is critical.
13. **Semantic Status Colors (ESTABLISHED):** Pass=Green (`emerald-600`), Fail=Red (`rose-600`), Partial=Amber. *Why:* Modifying these breaks the user's operational mental model.
14. **Information Hierarchy (ESTABLISHED):** Dashboard → Assessments → Assessment Detail → Findings. *Why:* Preserves the drill-down investigative flow.
15. **Dashboard Composition (ESTABLISHED):** Asymmetric grid splits with top-level stats, trending data, and recent audits. *Why:* Surfaces critical posture changes immediately.
16. **Assessment Detail Architecture (ESTABLISHED):** Overview stats at the top, tabbed navigation for specific analyses (Graph, Topology, Blast, etc.). *Why:* Consolidates all evidence for a single audit in one workspace.
17. **Page Transition Philosophy (ESTABLISHED):** Opacity & scale-up transitions. *Why:* Smooth, continuous perceived performance without harsh rendering jumps.
18. **Marquee Behavior (ESTABLISHED):** CSS linear infinite transform. *Why:* Hardware-accelerated continuous movement for log/activity streams without layout thrashing.
19. **Performance Principles (ESTABLISHED):** No scroll-linked React rerenders, CSS transforms over layout animations. *Why:* A laggy interface destroys trust in an enterprise tool.
20. **Data-Truthfulness Principles (ESTABLISHED):** Real data only. Honest empty states over mock data. *Why:* Faking metrics or findings destroys the credibility of a security product.

---

## REFERENCE ASSET INVENTORY

Located in `frontend/Design/`:

| Asset | What it establishes | Priority |
|---|---|---|
| `image.png` | Primary Dashboard layout, asymmetric grid splits, marquee behavior, top header search bar placement, overall typography. | 1 |
| `image copy.png` | Assessment Detail view layout, active tab indicator style, timeline/logs UI placement, full-width card stretching. | 1 |
| `image copy 2.png` | Findings table layout, severity badges (Critical, High, Medium, Low), search/filter input styling on data tables. | 1 |
| `image copy 3.png` | Compliance framework tab layouts, progress bars for coverage, score cards, and semantic compliance mapping statuses. | 1 |
| `image copy 4.png` | New Audit/Upload workflow, drag-and-drop zone styling, file upload state presentation, primary action buttons. | 1 |
| `image copy 5.png` | Expanded rule evaluation views, specific code evidence blocks, monospace typography usage for configuration excerpts. | 1 |

---

## DESIGN DECISION HIERARCHY

When deciding how something should look, use this exact order of precedence:

1. Explicit user instruction for the current task
2. `NCSA_APP_DESIGN_SYSTEM.md`
3. Current established implementation
4. `design.md`
5. Supplied reference images
6. Existing reusable component patterns
7. General design conventions

Generic AI design preferences must **NOT** override NCSA-specific rules.

---

## SPACING SPECIFICATION

**ESTABLISHED:**
The spacing scale is strictly based on an 8px base unit. 

| Size | Usage | Example |
|---|---|---|
| **4px** | Micro alignment | Icons next to text (`gap-1`) |
| **8px** | Tightly related elements | Between label and value (`gap-2`, `space-y-2`), input internals |
| **16px** | Related content | Between list items, minor grid gaps, control gaps (`gap-4`, `space-y-4`) |
| **24px** | Card internals | Standard internal padding for Cards (`p-6`) |
| **32px** | Component separation | Separating minor sections or tab spacing (`space-y-8`) |
| **48px+** | Structural sections | Page padding, major section gaps (Dashboard hero to insights) (`space-y-12`, `gap-12`) |

**PROHIBITED:**
- Arbitrary padding values (e.g., `p-[17px]`).
- Do not use `8px` everywhere simply because it is the base unit. Respect the spacing hierarchy.

---

## CARD RULES

**ESTABLISHED:**
Cards in NCSA have strict hierarchical styling based on their role. Do not create a new card style merely because a new feature has been added.

**Data / Standard Card (ESTABLISHED):**
- **Radius:** 24px (`rounded-3xl` or `rounded-[24px]`)
- **Padding:** 24px (`p-6`)
- **Border:** 1px solid `--color-hairline`
- **Shadow:** `--shadow-sm`
- **Content Density:** Standard 16px/24px internal gaps.

**Elevated Product / Feature Card (REFERENCE / INTENDED):**
- **Radius:** 16px (`rounded-2xl` or `rounded-[16px]`)
- **Padding:** 0px (Content/image fills the card)
- **Shadow:** Stacked blue-tinted elevation (`--shadow-sm-2` or `--shadow-sm-3`)
- **Purpose:** Used for highlighting structural UI previews or major features.

**Interactive Card / Row (ESTABLISHED):**
- **Hover Behavior:** `hover:bg-[var(--color-pebble)]` transition for rows/cards that are clickable.

**PROHIBITED:**
- Mixing border radii on standard data cards.
- Heavy black drop shadows (`rgba(0,0,0,...)`).
- Cards without the 1px hairline border.

---

## MOTION SPECIFICATION

**ESTABLISHED:**

| Animation | Trigger | Property | Duration | Easing | Purpose | Constraint |
|---|---|---|---|---|---|---|
| **Page Transition** | Route change | `opacity`, `scale(0.99) -> 1` | 500ms | `cubic-bezier(0.2, 0.8, 0.2, 1)` | Continuity | Hardware accelerated, no layout shift |
| **Sidebar Indicator**| Active route | `transform: translateY()` | 700ms | Smooth ease | Orientation | No DOM remounting |
| **Marquee** | Mount | `transform: translateX()` | Infinite | Linear | Continuity / Activity | CSS animation only |
| **Hover States** | Pointer hover| `background-color`, `color` | 150-200ms | `ease-in-out` | Feedback | No geometry changes |
| **Buttons** | Active press | `scale(0.98)` | 100ms | `ease` | Feedback | Fast response |

*IMPLEMENTATION GAP:* The 700ms vertical sidebar translation indicator is intended but may not be fully implemented as a continuous sliding pill in the current DOM structure.

## MOTION INVARIANTS

Future agents must not:
- Animate layout properties unnecessarily (`height`, `width`, `margin`) which causes layout thrashing.
- Create scroll-linked React animation.
- Use React state every animation frame.
- Introduce competing page transitions.
- Make navigation feel delayed.
- Create excessive motion.
- Make continuous marquee movement dependent on page scrolling.
- Introduce animations merely for decoration.

Motion exists primarily for:
1. **ORIENTATION:** Helping the user understand where they are (Sidebar indicator).
2. **STATE CHANGE:** Moving from one view to another (Page transitions).
3. **CONTINUITY:** Showing background activity without stalling (Marquee).
4. **FEEDBACK:** Confirming user interaction (Button scale, hover).

---

## NEW COMPONENT PROTOCOL

Before creating a new component:
1. Search existing components.
2. Identify the closest existing component.
3. Determine whether it can be reused.
4. Determine whether it can be extended.
5. Only then create a new component.

Before introducing a new:
- radius
- color
- shadow
- spacing value
- button style
- badge style
- card style
- animation
- typography size

The contributor **must verify** that an existing token/pattern cannot satisfy the requirement.

---

## NEW SCREEN PROTOCOL

Every new screen must answer:
1. What is the user's primary goal?
2. What real NCSA data powers it?
3. What existing screen is it most similar to?
4. Which existing components can be reused?
5. What is the information hierarchy?
6. What is the primary action?
7. What are loading states?
8. What are empty states?
9. What are error states?
10. What are unsupported states?
11. What is the responsive behavior?
12. What motion is required?
13. What accessibility requirements exist?

Then require visual QA against the design system.

---

## DATA UI IS NOT DECORATION

**ESTABLISHED:**
NCSA is an auditing product.
Therefore **visual completeness must NEVER take priority over factual correctness.**

- A blank chart with an honest "Insufficient data" state is preferable to fabricated data.
- A disabled capability is preferable to a fake working button.
- An honest empty state is preferable to mock content.
- An unavailable backend capability must never be represented as an implemented product capability.

**This is a product-level invariant.** Show real data, or explicitly state that it is unavailable.

---

## NCSA-SPECIFICITY RULE

Future AI agents must not transform NCSA into a generic:
- SaaS dashboard
- AI dashboard
- cybersecurity marketing site
- analytics template
- admin template

Do not automatically add:
- giant KPI grids
- motivational greetings ("Welcome back!")
- generic AI assistants
- decorative illustrations
- excessive pills
- generic gradient backgrounds
- glass cards
- arbitrary charts
- marketing CTAs

Every UI element must have a reason within NCSA's operational auditing workflow.

---

## INFORMATION ARCHITECTURE & TRACEABILITY

**ESTABLISHED:**
The established NCSA hierarchy flows linearly:
`Dashboard → Assessments → Assessment Detail → Findings / Compliance / Evidence`

Relationships:
- **Assessments** analyze **Devices** against **Frameworks**.
- **Frameworks** consist of **Rules** / **Baselines**.
- **Rules** generate **Findings**.
- **Findings** point to **Evidence** (Configuration Source Lines).

Future UI should reinforce these relationships rather than invent parallel concepts. 

**Traceability as a Visual Principle:**
Traceability should be visually obvious wherever relevant:
`Finding → Rule → Baseline → Evidence → Configuration → Source Line`
Do not bury audit evidence beneath decorative UI. The user must be able to visually trace a failure back to the raw source code line.

---

## RESPONSIVE RULES

**ESTABLISHED:**
The application utilizes full fluid width (`w-full`) expanding up to large desktop monitors rather than fixed constraints.

- **1280px (Minimum Target):** Standard grid layouts.
- **1440px / 1536px (Optimal):** Cards expand fluidly, tables show maximum data density without horizontal scrolling.
- **1920px (Maximum Scale):** Elements stretch dynamically via CSS Grid (e.g. `grid-cols-12`).

For each breakpoint:
- **Content Width:** Fluidly expands. No hard `max-w-7xl` that leaves massive margins.
- **Grids:** Adjust column counts to fill space without stretching cards excessively.
- **Cards / Tables:** Expand to consume horizontal space.
- **Headers / Actions:** Keep aligned to grid edges.
- **Tabs:** Wrap gracefully if needed, but prefer horizontal flow.

**Not Currently Supported:** Mobile viewports (sub-768px) and standard tablets are not primary targets. Operational auditing requires dense data presentation suitable only for desktop environments.

---

## ACCESSIBILITY CONTRACT

Future UI must preserve:
- semantic buttons (`<button>`)
- semantic links (`<a>` with `href`)
- keyboard navigation
- focus-visible states (Custom `focus-visible:ring-2`)
- sufficient contrast (Navy on Cloud)
- reduced motion (respecting `prefers-reduced-motion`)
- accessible forms (proper `<label>` associations)
- accessible tables (`<th>` scopes)
- clear labels (including `aria-label` where text is hidden)

Accessibility cannot be traded for visual similarity.

---

## PERFORMANCE CONTRACT

Future UI work must preserve:
- smooth native scrolling
- stable layout
- compositor-friendly animation
- transform/opacity animation where possible
- no scroll-linked React rerenders
- no animation-frame state updates unless genuinely necessary
- no forced synchronous layout
- no unnecessary DOM measurement
- no unnecessary page remounts
- no expensive decorative effects

Specifically preserve the currently established:
- smooth sidebar indicator
- smooth page transition
- stable CSS marquee

---

## DESIGN VS FUNCTION

Function always wins over decoration.

However, functionality should be implemented using the existing visual language whenever possible.

*Example:*
If a new feature needs a new interaction, first determine whether it can be expressed using:
- an existing card
- an existing table
- existing tabs
- an existing drawer/modal
- an existing button
- the existing status system

before creating a new visual pattern.

---

## DESIGN CHANGE CONTROL

A change to the design system should happen only when:
- a genuine product requirement exists
- an existing pattern cannot solve it
- the new pattern is reusable
- it does not conflict with established principles

When a new reusable pattern is approved:
1. implement it
2. document it
3. update this file
4. check affected existing screens
5. perform visual QA

---

## AI AGENT PRE-FLIGHT CHECKLIST

Before coding:
- [ ] Read `NCSA_APP_DESIGN_SYSTEM.md`
- [ ] Inspect relevant existing screen
- [ ] Inspect reusable components
- [ ] Inspect actual data availability
- [ ] Identify closest existing pattern
- [ ] Confirm no design-system conflict

During coding:
- [ ] Reuse components
- [ ] Reuse tokens
- [ ] Preserve spacing
- [ ] Preserve typography
- [ ] Preserve semantic colors
- [ ] Preserve motion
- [ ] Preserve performance

Before completion:
- [ ] No mock data
- [ ] No fake functionality
- [ ] No arbitrary new styles
- [ ] No dead controls
- [ ] Loading state exists
- [ ] Empty state exists
- [ ] Error state exists
- [ ] Accessibility checked
- [ ] Responsive behavior checked
- [ ] Performance checked
- [ ] Visual consistency checked

---

## FINAL QUICK REFERENCE

**VISUAL**
- **Canvas:** `--color-cloud` `#f8f9fb`
- **Primary Ink:** `--color-ink-navy` `#0b3558`
- **Action Color:** `--color-signal-blue` `#006bff`
- **Surface:** `--color-paper` `#ffffff`
- **Border:** `--color-hairline` `#d4e0ed`
- **Typography:** Gilroy / Inter (Bold for headers, Regular for body)

**LAYOUT**
- **Sidebar:** Fixed left rail
- **Header:** Top bar for global actions
- **Content:** Fluid width up to 1920px
- **Spacing Rhythm:** Strict 8px base multiples (4, 8, 16, 24, 32, 48)
- **Cards:** White, 1px border, 24px radius (`p-6` padding)
- **Tables:** Dense data layouts with visible column headers

**MOTION**
- **Sidebar:** Smooth Y-translation active indicator
- **Page:** 500ms opacity & scale(0.99) transition
- **Marquee:** CSS linear infinite
- **Reduced Motion:** Respect OS preferences

**DATA**
- **Real data only:** No mock payloads.
- **Honest states:** Show empty/loading/error instead of pretending features exist.
- **Semantic compliance:** Pass = Green, Fail = Red.

**ARCHITECTURE**
- Dashboard → Assessments → Assessment Detail → Findings → Compliance → Evidence

**NEVER**
- Fake data
- Generic SaaS styling (glassmorphism, random blobs)
- Decorative complexity
- Competing design language
- Layout-thrashing animation
