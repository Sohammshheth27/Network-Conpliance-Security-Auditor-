# NCSA — FULL-STACK FEATURE, UI, UX & INFORMATION ARCHITECTURE AUDIT

This document is the definitive master audit of the NCSA application's current state, comparing the actual backend capabilities (FastAPI/engine) against the frontend implementation (React/Vite).

## 1. BACKEND CAPABILITY INVENTORY

The backend engine is highly capable and heavily analysis-driven. It exposes the following major capabilities via `ncsa/api/app.py`:

- **Core Ingestion:** `/assess` (bulk upload configs) and `/collect` (live SSH collection from devices).
- **Scheduled Monitoring:** `/monitor` (scheduled re-collection and drift alerts).
- **Assessments & Reporting:** `/assessments` (fleet view), `/assessment/{aid}` (device details), `/assessment/{aid}/report` (PDF/HTML generation), `/report-signing-key`, `/verify-report` (cryptographic report verification), `/fleet.csv` (CSV export).
- **Topology & Reachability:** `/topology` (multi-device fabric), `/assessment/{aid}/topology-map`, `/assessment/{aid}/topology-map.svg`, `/assessment/{aid}/reach` (policy query), `/assessment/{aid}/blast-radius` (segment compromise simulation), `/assessment/{aid}/zones`, `/assessment/{aid}/interfaces`.
- **Policy Analysis:** `/assessment/{aid}/graph` (full policy object graph), `/assessment/{aid}/hygiene` (shadowed, redundant, dead rules), `/assessment/{aid}/extended` (VPN/WLAN checks), `/assessment/{aid}/what-if` (change simulation), `/assessment/{aid}/recertification` (rule expiry review), `/assessment/{aid}/logs` (log correlation), `/assessment/{aid}/consensus` (corroboration).
- **Change Tracking:** `/assessment/{aid}/snapshot` (baseline creation), `/assessment/{aid}/diff` (drift detection), `/assessment/{aid}/history` (score over time).
- **Remediation:** `/assessment/{aid}/remediation` (CLI steps with lockout checks).
- **Machine Learning & Training:** `/assessment/{aid}/training` (mapping queue), `/training/approve`, `/training/reject`, `/training/learned`, `/schema/fields`, `/assessment/{aid}/reassess`.
- **Host Firewall:** `/hostfw/iptables`, `/hostfw/local` (agentless OS firewall checking).
- **Metadata & Governance:** `/ai-governance` (MITRE ATLAS / NIST AI RMF), `/attack-coverage` (MITRE ATT&CK coverage), `/frameworks`, `/platforms`.

## 2. FRONTEND CAPABILITY INVENTORY

The frontend (`frontend/src/`) implements the following main pages and components:

- **Dashboard (`Dashboard.tsx`):** Functional. Displays fleet-wide score, active monitors, and recent assessments correctly sourced from the backend.
- **New Audit (`NewAudit.tsx`):** Functional. Ingestion flow for uploading files or live SSH collection. Correctly bounds frameworks and redaction.
- **Assessments List (`Assessments.tsx`):** *Partially functional / Fake Data.* List view works, but contains fake UI tabs ("Policies", "Vulnerabilities", "Alerts", "Reports") and static chart placeholders.
- **Assessment Detail (`AssessmentDetail.tsx`):** *Partially functional / Fake Data.* Shows basic compliance score and findings, but features heavy mock data for topology, blast radius, and historical drift instead of using the real backend data.
- **Frameworks (`Frameworks.tsx`):** Functional. Pulls from `/frameworks`.
- **Training (`Training.tsx`):** Functional. Connects to `/training/learned` and handles mapping approvals.
- **Settings (`Settings.tsx`):** *Fake Data.* Hardcoded placeholder sections ("Profile", "Notifications", "Security", "Design & Appearance") that do no actual configuration.
- **Sidebar & Header:** Contains dead links to "Topology", "Remediation", "Reports", "Settings". Notification bell and profile dropdown in header are inert.
- **Orphaned Components:** `AnalysisTabs.tsx`, `ReportAndHistory.tsx`, `AiGovernance.tsx` contain correct API bindings to the backend analysis tools, but are NEVER rendered in the application.

## 3. GAP ANALYSIS (The "Reality Check")

### 3.1. Orphaned Backend Capabilities (No Frontend Access)
The following backend endpoints have no frontend API binding in `api.ts` and no UI representation:
1. `GET /fleet.csv`
2. `GET /assessment/{aid}/baseline`
3. `GET /report-signing-key`
4. `POST /verify-report`
5. `GET /assessment/{aid}/topology-map` (JSON data)
6. `POST /assessment/{aid}/logs`
7. `POST /hostfw/iptables`
8. `POST /hostfw/local`
9. `GET /attack-coverage`

### 3.2. Orphaned Frontend Bindings (No UI Representation)
The frontend `api.ts` defines bindings for the following endpoints, but the components that use them (`AnalysisTabs.tsx`, `ReportAndHistory.tsx`, `AiGovernance.tsx`) are disconnected from the application routing/render tree:
1. `hygiene` (Policy Hygiene)
2. `graph` (Object Graph)
3. `extended` (Extended Checks)
4. `zones` (Zones)
5. `topologySvg` (Topology SVG)
6. `blastRadius` (Blast Radius)
7. `whatIf` (What-If Simulation)
8. `remediation` (Remediation scripts)
9. `recertification` (Rule Recertification)
10. `consensus` (Corroboration)
11. `reach` (Reachability)
12. `snapshot`, `diff`, `history` (Change tracking)
13. `aiGovernance` (AI Governance metadata)

### 3.3. Fake/Mock Data in UI (The "Illusion of Capability")
The frontend simulates capabilities it actually has backend support for by using hardcoded data instead of the real endpoints:
- `AssessmentDetail.tsx` renders a fake network topology image/div instead of using the `topologySvg` backend route via the orphaned `AnalysisTabs`.
- `AssessmentDetail.tsx` renders fake "Blast Radius" cards.
- `AssessmentDetail.tsx` renders fake historical drift charts.
- `Assessments.tsx` renders fake tabular views for "Vulnerabilities" and "Alerts".
- `Settings.tsx` provides fake controls.
- The `Header` contains a fake notification bell.

## 4. IA & ROUTING DEFICIENCIES
1. **Broken Navigation:** Sidebar links for Topology, Remediation, and Reports are either dead or lead to missing pages, whereas these should be sub-views of a specific Assessment or fleet-wide aggregations.
2. **Hidden Deep Analysis:** The core value of the engine (Hygiene, Blast Radius, What-If, Remediation) is trapped in `AnalysisTabs.tsx`, which is not integrated into `AssessmentDetail.tsx`.
3. **Missing AI Governance:** The `AiGovernance.tsx` component is completely missing from the routing structure.
4. **Missing Fleet Views:** Fleet CSV export and cross-device topology (`POST /topology`) are not exposed anywhere.

## 5. REMEDIATION PLAN

This is the concrete execution plan to rectify the application state.

### PHASE 1: Reconnecting the Disconnected UI (Analysis Tools)
1. **Goal:** Integrate `AnalysisTabs.tsx` and `ReportAndHistory.tsx` into `AssessmentDetail.tsx`.
2. **Action:** Remove the mock data sections (fake blast radius, fake charts, fake topology) in `AssessmentDetail.tsx`.
3. **Action:** Replace the lower half of `AssessmentDetail.tsx` with the `AnalysisTabs` component, passing the current `aid` so the real backend analysis is rendered.
4. **Action:** Integrate `ReportAndHistory.tsx` as a tab or view within the Assessment Detail page to expose the `history` and `reportUrl` features.

### PHASE 2: Route & Sidebar Cleanup
1. **Goal:** Remove dead links and expose missing top-level routes.
2. **Action:** Add a route for `/ai-governance` in `App.tsx` and add a sidebar link for "AI Governance" (perhaps near Frameworks or Settings).
3. **Action:** Remove or repurpose the dead "Topology", "Remediation", and "Reports" sidebar links. (These are assessment-specific, not global, unless we implement the multi-device fabric topology).
4. **Action:** Repurpose the "Settings" page. Remove the fake design/profile toggles. Replace it with real application settings if any exist, or leave it as a minimal placeholder clearly marked.

### PHASE 3: Exposing Missing Backend Features
1. **Goal:** Build UI for the completely orphaned backend endpoints.
2. **Action (Reports):** Create a global "Reports & Verification" page that allows downloading the `/fleet.csv` and provides a UI for `/verify-report` (uploading a PDF to check its cryptographic signature).
3. **Action (Host Firewall):** Add a tab or section in `NewAudit.tsx` to support uploading `/hostfw/iptables` configurations, distinguishing them from network devices.
4. **Action (Log Correlation):** Add a UI section within the Policy Hygiene or Assessment Detail view to upload logs (`POST /assessment/{aid}/logs`) and view corroboration data.
5. **Action (ATT&CK Coverage):** Create an `AttackCoverage.tsx` component to display the `/attack-coverage` data, and link it from the Frameworks or Dashboard page.

### PHASE 4: Visual Consistency & Design System Alignment
1. **Goal:** Ensure all newly integrated and re-exposed components strictly follow `NCSA_APP_DESIGN_SYSTEM.md`.
2. **Action:** Audit `AnalysisTabs.tsx` and its sub-components (`Hygiene`, `BlastRadius`, `Topology`, `Remediation`, `WhatIf`) to ensure they use the correct color tokens, typography, and card styles established in the design system.
3. **Action:** Ensure loading states, error boundaries, and empty states in these restored components match the NCSA standard (e.g., Lucide icons, slate borders, clean typography).

---
**Status:** Audit Complete. Ready for Implementation Phase.
