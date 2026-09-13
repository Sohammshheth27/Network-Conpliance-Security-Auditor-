# NCSA Application Design System

## 1. DOCUMENT STATUS
- **Document Name:** NCSA_APP_DESIGN_SYSTEM.md
- **Purpose:** The definitive visual, UX, and operational design specification for the NCSA frontend.
- **Current Status:** Final / Active
- **Source of Truth:** 6 reference images, `design.md`, and the current React frontend implementation.
- **Last Audited Date:** September 2026
- **Intended Audience:** Future AI agents, Antigravity, Claude, GPT, and human developers.

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
The following established elements must be preserved. They form the core identity of NCSA:

1. **Overall Visual Language (ESTABLISHED):** Restrained, professional, high-density. Why: NCSA is an operational auditing tool, not a consumer SaaS app.
2. **Color System (ESTABLISHED):** Navy Ink (`--color-ink-navy`), Signal Blue (`--color-signal-blue`), Cloud (`--color-cloud`). Why: Prevents competing brand identities and guarantees AAA contrast.
3. **Typography System (ESTABLISHED):** Highly structured bold headings with clean geometric body text. Why: Ensures data scanability.
4. **Spacing Rhythm (ESTABLISHED):** Strict 4px/8px multiples. Why: Maintains vertical alignment and predictable visual clustering.
5. **Sidebar Geometry (ESTABLISHED):** Fixed rail on the left. Why: Predictable, constant spatial orientation for navigation.
6. **Active Navigation Indicator (ESTABLISHED):** Smooth 700ms vertical translation. Why: Provides continuity rather than jumpy unmounting state changes.
7. **Semantic Status Colors (ESTABLISHED):** Pass=Green, Fail=Red, Partial=Amber. Why: Modifying these breaks the user's operational mental model.
8. **Data-Truthfulness (ESTABLISHED):** Real data only. Why: Faking metrics or findings destroys the credibility of a security product.

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
4. `design/design.md`
5. Supplied reference images
6. Existing reusable component patterns
7. General design conventions

Generic AI design preferences must **NOT** override NCSA-specific rules.

---

## 5. COLOR SYSTEM
**ESTABLISHED:**
| Token | Value | Purpose | Usage |
|---|---|---|---|
| `--color-cloud` | `#f8f9fb` | Page canvas | AppShell background, sidebar base |
| `--color-paper` | `#ffffff` | Primary surface | Cards, elevated panels, buttons |
| `--color-hairline` | `#d4e0ed` | Borders | Card borders, input borders, dividers |
| `--color-ink-navy` | `#0b3558` | Primary text | Headings, active states, icons |
| `--color-slate-gray` | `#476788` | Secondary text | Body copy, muted labels, headers |
| `--color-signal-blue`| `#006bff` | Primary action | Primary CTA fill, active nav indicator |
| `emerald-600` | Tailwind | Semantic success | Pass status, safe configurations |
| `rose-600` | Tailwind | Semantic danger | Fail status, Critical severity |

**PROHIBITED:** Random text coloring, decorative blobs outside of intended design.md patterns, generic gradient backgrounds.

---

## 6. TYPOGRAPHY SYSTEM
**ESTABLISHED:**
- **Headings (H1/H2):** Bold (`font-bold`), tight tracking (`tracking-tight`), Navy Ink.
- **Body:** Regular weight, high contrast, Slate Gray or Navy.
- **Labels (Metadata/Captions):** Uppercase, wide tracking (`tracking-wider`), small (`text-[10px]` or `text-xs`), Slate Gray.

**PROHIBITED:** Thin font weights (below 400), massive decorative display fonts that break grid alignment.

---

## 7. SPACING SPECIFICATION
**ESTABLISHED:**
The spacing scale is strictly based on an 8px rhythm (using Tailwind's 4px multiplier step):
- **4px (micro alignment):** Used for icons next to text (`gap-1`).
- **8px (tightly related):** Used between label and value (`gap-2`, `space-y-2`).
- **16px (related content):** Used between list items or internal card components (`gap-4`, `space-y-4`).
- **24px (card internals):** Standard internal padding for Cards (`p-6`).
- **32px (component separation):** Used to separate minor sections (`space-y-8`).
- **40px+ (structural sections):** Used to separate major sections, like the top hero and bottom insights on the Dashboard (`space-y-10`, `space-y-12`).

**PROHIBITED:** Arbitrary padding values (e.g., `p-[17px]`). Use the established hierarchy.

---

## 8. LAYOUT & RESPONSIVE RULES
**ESTABLISHED:**
- **AppShell:** Fixed sidebar left (`w-20`), scrolling `flex-1` main container right.
- **Responsive Targets:** `1280px` (min), `1440px`, `1536px`, `1920px`.
- **Content Width:** The application utilizes full fluid width (`w-full`). Elements stretch dynamically via CSS Grid (e.g. `grid-cols-12`) rather than using artificial max-widths that leave massive empty margins on 1920px displays.
- **Not Currently Supported:** Mobile viewports (sub-768px) are not primary targets.

---

## 9. CARD RULES
**ESTABLISHED:**
- **Radius:** `rounded-xl` (or 24px per references).
- **Padding:** `p-6` (24px) for standard data cards. 
- **Border:** `border border-[var(--color-hairline)]`.
- **Shadow:** `shadow-sm` (subtle).
- **Background:** Pure white (`bg-white`).

**PROHIBITED:** Creating new card styles just because a new feature is added. Do not mix border radii or drop heavy shadows.

---

## 10. MOTION SPECIFICATION
**ESTABLISHED:**
- **Page Transition:** `opacity` & `scale(0.99) -> 1`, 500ms, `cubic-bezier(0.2, 0.8, 0.2, 1)`. Triggered by route changes.
- **Sidebar Indicator:** `transform: translateY()`, 700ms, smooth ease. Triggered by active route.
- **Marquee:** CSS linear infinite transform.
- **Buttons:** `active:scale-[0.98]`.

**MOTION INVARIANTS (PROHIBITED):**
- Animating layout properties (`height`, `width`, `margin`) which causes layout thrashing.
- Scroll-linked React state animations.
- Introducing full-page slide animations that delay navigation.
- Making continuous marquee movement dependent on page scrolling.
- Motion purely for decoration rather than Orientation, State Change, or Continuity.

---

## 11. DATA UI IS NOT DECORATION
**ESTABLISHED:**
NCSA is an auditing product. Visual completeness must NEVER take priority over factual correctness.
- **REAL DATA:** Show real data.
- **NO DATA:** Show an honest empty state.
- **LOADING:** Show a loading state.
- **UNSUPPORTED:** Communicate the limitation.

**PROHIBITED:**
A blank chart with an honest "Insufficient data" state is preferable to fabricated data. A disabled capability is preferable to a fake working button. An unavailable backend capability must NEVER be represented as an implemented product capability.

---

## 12. NCSA-SPECIFICITY RULE (DO NOT GENERICIZE NCSA)
**PROHIBITED:**
Future AI agents must not transform NCSA into a generic SaaS dashboard, cybersecurity marketing site, or analytics template.
Do not automatically add:
- Giant KPI grids
- Motivational greetings ("Welcome back!")
- Generic AI assistants
- Decorative illustrations or blobs
- Glass cards
- Arbitrary charts

Every UI element must have a reason within NCSA's operational auditing workflow.

---

## 13. INFORMATION ARCHITECTURE & TRACEABILITY
**ESTABLISHED:**
Hierarchy flows linearly:
`Dashboard -> Assessments -> Assessment Detail -> Findings / Compliance / Evidence`

Traceability must be visually obvious:
`Finding -> Rule -> Baseline -> Evidence -> Configuration -> Source Line`

Future UI should reinforce these relationships rather than invent parallel concepts. Do not bury audit evidence beneath decorative UI.

---

## 14. NEW COMPONENT PROTOCOL
Before creating a new component, a contributor MUST:
1. Search existing components (`Button`, `Card`, `Empty`, `States`).
2. Identify the closest existing component.
3. Determine whether it can be reused.
4. Determine whether it can be extended.
5. Only then create a new component.
Verify that an existing radius, color, shadow, spacing value, or badge style cannot satisfy the requirement before inventing a new one.

---

## 15. NEW SCREEN PROTOCOL
Every new screen must answer:
1. What is the user's primary goal?
2. What real NCSA data powers it?
3. What existing screen is it most similar to?
4. Which existing components can be reused?
5. What is the information hierarchy?
6. What is the primary action?
7. What are the loading/empty/error/unsupported states?
8. What is the responsive behavior?
9. What motion is required?
10. What accessibility requirements exist?
Visual QA against this document is required.

---

## 16. DESIGN VS FUNCTION
**ESTABLISHED:**
Function always wins over decoration.
However, functionality should be implemented using the existing visual language whenever possible. If a new feature needs a new interaction, first determine whether it can be expressed using an existing card, table, tab, modal, or status badge before creating a new visual pattern.

---

## 17. ACCESSIBILITY CONTRACT
**ESTABLISHED:**
Future UI must preserve:
- Semantic buttons (`<button>`) and links (`<a>`).
- Keyboard navigation.
- Focus-visible states (Custom `focus-visible:ring-2`).
- Sufficient contrast (Navy on Cloud).
- Reduced motion respecting (`prefers-reduced-motion`).
Accessibility cannot be traded for visual similarity.

---

## 18. PERFORMANCE CONTRACT
**ESTABLISHED:**
Future UI work must preserve:
- Smooth native scrolling.
- Stable layout.
- Compositor-friendly animation (`transform`/`opacity`).
- No scroll-linked React rerenders.
- No animation-frame state updates unless genuinely necessary.
- No forced synchronous layout.

Specifically preserve the smooth sidebar indicator, smooth page transition, and stable CSS marquee.

---

## 19. DESIGN CHANGE CONTROL
A change to the design system should happen ONLY when:
- A genuine product requirement exists.
- An existing pattern cannot solve it.
- The new pattern is reusable.
- It does not conflict with established principles.
When approved: implement it, document it, update this file, check affected existing screens, and perform visual QA.

---

## 20. AI AGENT PRE-FLIGHT CHECKLIST
**Before coding:**
- [ ] Read `NCSA_APP_DESIGN_SYSTEM.md`
- [ ] Inspect relevant existing screens and reusable components
- [ ] Inspect actual data availability
- [ ] Confirm no design-system conflict

**During coding:**
- [ ] Reuse components and tokens
- [ ] Preserve spacing and typography hierarchy
- [ ] Preserve semantic colors and motion performance

**Before completion:**
- [ ] No mock data / fake functionality / dead controls
- [ ] Loading, Empty, and Error states exist
- [ ] Accessibility, Responsive, and Performance checked

---

## 21. FINAL QUICK REFERENCE
- **VISUAL:** Canvas = Cloud. Primary = Navy Ink. Action = Signal Blue. Borders = Hairline.
- **LAYOUT:** Fixed sidebar, top header, fluid width main content (stretching to 1920px). Strict 8px spacing rhythm. White cards with 1px borders.
- **MOTION:** Transform/opacity only. 700ms sidebar, 500ms page transitions. No scroll-linked React animations.
- **DATA:** Real data only. Honest empty/unsupported states over faked capabilities. Semantic compliance (Pass=Green, Fail=Red).
- **ARCHITECTURE:** Dashboard -> Assessments -> Assessment Detail -> Findings.
- **NEVER:** Fake data, generic SaaS marketing styling, decorative complexity, layout-thrashing animations, or changing established design tokens without approval.

**FINAL DESIGN PRINCIPLE:**
New UI additions must feel like they were designed as part of the core NCSA product from the very beginning — purposeful, data-driven, and seamlessly integrated, rather than bolted on later.
