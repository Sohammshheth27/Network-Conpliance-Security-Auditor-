/**
 * The one place the UI talks to the NCSA engine.
 *
 * Every type here mirrors what `ncsa/api/app.py` actually returns. They were
 * written by reading real responses from the running engine against a real
 * SonicWall NSA 3700 export, not from the endpoint signatures -- so the shapes
 * are what the UI will genuinely receive.
 *
 * ONE RULE ABOVE ALL OTHERS
 * -------------------------
 * The engine reports seven result states. The UI must carry all seven.
 *
 * The temptation is to collapse them to pass/fail for a tidier chart. Doing so
 * would destroy the product's central claim: NOT_APPLICABLE folded into PASS
 * inflates the score, and UNKNOWN folded into either turns "we could not check
 * this" into "we checked". The engine works hard to never present absence as a
 * positive result; the UI must not undo that at the last layer.
 */

/** Requests go to /api/*, which Vite proxies to the engine. See vite.config.ts. */
const BASE = "/api";

// ---------------------------------------------------------------- result states

/** All seven. Never narrow this union. */
export type ResultState =
  | "PASS"
  | "FAIL"
  | "PARTIAL"
  | "NOT_APPLICABLE"
  | "UNKNOWN"
  | "MANUAL_REVIEW"
  | "ERROR";

export type Severity = "critical" | "high" | "medium" | "low";

export const RESULT_STATES: ResultState[] = [
  "PASS", "FAIL", "PARTIAL", "NOT_APPLICABLE", "UNKNOWN", "MANUAL_REVIEW", "ERROR",
];

/**
 * What each state means, in the words a reviewer needs.
 *
 * These are shown in the UI on hover. A state whose meaning is not obvious is
 * a state that will be misread, and UNKNOWN vs NOT_APPLICABLE is exactly the
 * pair people misread.
 */
export const STATE_MEANING: Record<ResultState, string> = {
  PASS: "Checked, and the device is configured correctly.",
  FAIL: "Checked, and the device is not configured correctly.",
  PARTIAL: "Checked; some scoped instances comply and others do not.",
  NOT_APPLICABLE: "This control does not apply to this platform. Not a gap.",
  UNKNOWN: "We could NOT check this. Not a pass, and not a failure.",
  MANUAL_REVIEW: "Needs a human decision; no automated verdict is honest here.",
  ERROR: "The check itself failed. Our fault, not the device's.",
};

/**
 * Colours per state, in the project palette.
 *
 * UNKNOWN and NOT_APPLICABLE use the MUTED colour and must never use the pass
 * green. A grey pill reads as "no verdict"; a green one reads as "fine", and
 * the whole point of these two states is that we did not establish "fine".
 */
export const STATE_STYLE: Record<ResultState, string> = {
  PASS: "bg-[rgba(50,214,168,0.12)] border-[rgba(50,214,168,0.28)] text-[#32D6A8]",
  FAIL: "bg-[rgba(229,72,77,0.12)] border-[rgba(229,72,77,0.28)] text-[#E5484D]",
  PARTIAL: "bg-[rgba(245,184,46,0.12)] border-[rgba(245,184,46,0.28)] text-[#F5B82E]",
  NOT_APPLICABLE: "bg-[rgba(140,160,190,0.10)] border-[rgba(140,160,190,0.22)] text-[#8FA0BC]",
  UNKNOWN: "bg-[rgba(140,160,190,0.10)] border-[rgba(140,160,190,0.22)] text-[#AAB8D0]",
  MANUAL_REVIEW: "bg-[rgba(155,120,255,0.12)] border-[rgba(155,120,255,0.28)] text-[#9B78FF]",
  ERROR: "bg-[rgba(255,138,60,0.12)] border-[rgba(255,138,60,0.28)] text-[#FF8A3C]",
};

export const SEVERITY_STYLE: Record<Severity, string> = {
  critical: "bg-[rgba(229,72,77,0.14)] border-[rgba(229,72,77,0.30)] text-[#E5484D]",
  high: "bg-[rgba(255,138,60,0.14)] border-[rgba(255,138,60,0.30)] text-[#FF8A3C]",
  medium: "bg-[rgba(245,184,46,0.14)] border-[rgba(245,184,46,0.30)] text-[#F5B82E]",
  low: "bg-[rgba(45,140,255,0.14)] border-[rgba(45,140,255,0.30)] text-[#2D8CFF]",
};

// ---------------------------------------------------------------------- types

export interface Identity {
  vendor: string;
  platform: string;
  os: string;
  version: string;
  hostname: string;
  serial: string;
  model: string;
  source_file: string;
  sha256: string;
}

/**
 * Coverage, as the engine computes it.
 *
 * `score_pct` is over DECIDED controls only. It must never be rendered without
 * `assessed_pct` beside it: a device where we could read 40% of the settings
 * and all of them passed scores 100% on 40% coverage, and showing only the
 * first number is a lie of omission.
 */
export interface Coverage {
  controls_total: number;
  controls_decided: number;
  controls_undecided: number;
  not_applicable: number;
  assessed_pct: number;
  score_pct: number;
}

export interface RecordAccounting {
  source_records: number;
  parsed_records: number;
  unreadable_records: number;
  mapped_to_schema: number;
  parsed_not_mapped: number;
  security_relevant_unmapped: number;
}

export interface EvidenceRef {
  file: string;
  /** null where the source format has no meaningful line -- a key-value export. */
  line: number | null;
  raw: string;
  record_id: string | null;
}

export interface FrameworkRefs {
  nist_800_53: string[];
  iso_27001: string[];
  stig_ids: string[];
  cis_ids: string[];
}

export interface Finding {
  control_id: string;
  title: string;
  state: ResultState;
  severity: Severity;
  field: string;
  observed: unknown;
  expected: unknown;
  reason: string;
  confidence: number;
  evidence: EvidenceRef[];
  frameworks: FrameworkRefs;
  risk: number | null;
  attack?: AttackTag[];
}

export interface ConsensusSummary {
  total: number;
  confirmed: number;
  disputed: number;
  uncorroborated: number;
  dispute_rate_pct: number;
  pack_coverage_gaps: number;
}

export interface Assessment {
  assessment_id: string;
  supported: boolean;
  identity: Identity;
  coverage: Coverage;
  records: RecordAccounting;
  counts: Record<ResultState, number>;
  findings: Finding[];
  risk_total: number;
  risk_worst: string;
  consensus: ConsensusSummary;
  objects: number;
  relationships: number;
  notes: string[];
  /** Frameworks the user selected; null means all of them. */
  frameworks: string[] | null;
  framework_coverage: FrameworkCoverage[];
}

export interface FrameworkCoverage {
  framework: string;
  name: string;
  controls: number;
  decided: number;
  passed: number;
  score_pct: number | null;
  /** "average": each requirement scored by the share of its checks passed. */
  score_method: string;
  /** This framework's own score, averaged over its requirements. */
  framework_score_pct: number | null;
  /** The framework's own requirements (NIST controls, ISO Annex A, STIG IDs). */
  requirements: number;
  /** Requirements with at least one decided check. */
  requirements_decided: number;
  /** Requirements where every citing check passed. */
  requirements_met: number;
  requirements_not_met: number;
  not_met_ids: string[];
}

export interface AssessmentSummary {
  assessment_id: string;
  device: string;
  vendor: string;
  score_pct: number;
  assessed_pct: number;
}

export interface PlatformInfo {
  vendor: string;
  platform: string;
  reader: string;
  mappings: number;
}

export interface FrameworksResponse {
  catalogs: Record<string, number>;
  note: string;
}

export interface HealthResponse {
  ok: boolean;
  assessments: number;
  platforms_parsed: string[];
  graph_analyses: {
    capabilities: string[];
    platforms: string[];
    note: string;
  };
}

// ------------------------------------------------------------- rule hygiene

export interface HygieneFinding {
  kind: string;
  rule: string;
  detail: string;
  severity: string;
  related: string;
  hit_count: number | null;
}

/**
 * `analysis_ran: false` is the important case.
 *
 * It means no rule-graph builder exists for this platform, so hygiene was
 * never attempted. `summary` is null rather than zeroed, precisely so a chart
 * cannot render "0 findings" and read as a clean policy.
 */
export interface HygieneResponse {
  analysis_ran: boolean;
  summary: {
    rules_examined: number;
    rules_fully_resolved: number;
    unevaluable: number;
    findings: number;
    by_kind: Record<string, number>;
  } | null;
  findings: HygieneFinding[];
  unevaluable?: string[];
  reason?: string;
  supported_platforms?: string[];
  not_a_finding?: boolean;
}

// ------------------------------------------------------------- reachability

export interface ReachQuery {
  source?: string;
  destination?: string;
  port?: number;
  protocol?: string;
  source_zone?: string;
  destination_zone?: string;
}

export interface ReachAnswer {
  query: string;
  /** Tri-state. null means undecidable, which is NOT the same as denied. */
  permitted: boolean | null;
  decided_by: string;
  action: string;
  reason: string;
  rules_evaluated: number;
  rules_unevaluable: number;
  /** The deciding rule was zone-scoped but the query named no zone. */
  zone_assumed: boolean;
}

export interface ReachResponse {
  answer: ReachAnswer;
  explain: string;
}

// ------------------------------------------------------- the other analyses

export interface RemediationResponse {
  platform: string;
  rollback_command: string;
  rollback_note: string;
  steps: { control_id?: string; commands?: string[]; note?: string }[];
  deferred: unknown[];
  unavailable: string[];
  script: string;
}

export interface TrainingCandidate {
  name: string;
  occurrences: number;
  sample_values: string[];
  evidence: EvidenceRef;
  vendor: string;
  platform: string;
  suggested_field: string | null;
  suggestion_score: number;
  suggested_from: string;
  status: string;
  /** "keys": a table whose keys are the values (SONiC NTP_SERVER). */
  kind: string;
}

export interface RecertResponse {
  due: {
    device: string;
    rule_id: string;
    kind: string;
    severity: string;
    detail: string;
    owner: string;
    days_remaining: number | null;
    hit_count: number | null;
  }[];
  deletion_candidates: {
    rule: string;
    rule_id: string;
    signals: string[];
    confidence: number;
    hit_count: number | null;
    note: string;
  }[];
}

export interface ConsensusResponse {
  consensus: {
    items: {
      verdict: string;
      detector: string;
      field: string;
      line: number | null;
      evidence: string;
      universal_says: string;
      pack_says: string;
      pack_state: string;
      confidence: number;
      note: string;
    }[];
    pack_only: number;
    coverage_gaps: string[];
  };
  parser_agreement: unknown;
}

export interface InterfacesResponse {
  interfaces: {
    name: string;
    address: string | null;
    netmask: string | null;
    network: string | null;
    zone: string | null;
    enabled: boolean;
    description: string;
    evidence: string;
  }[];
  note?: string;
}

export interface TopologyResponse {
  devices: { assessment_id: string; device: string }[];
  skipped: { assessment_id: string; reason: string }[];
  summary: {
    devices: number;
    interfaces: number;
    links: number;
    platforms: string[];
  };
  adjacency: unknown[];
  path?: ReachAnswer;
  explain?: string;
}

export interface DiffResponse {
  device_key?: string;
  same_device?: boolean;
  device_changed?: boolean;
  analysis_changed?: boolean;
  before_at?: string;
  after_at?: string;
  score_before?: number | null;
  score_after?: number | null;
  control_changes?: {
    control_id: string;
    before: string;
    after: string;
    direction: string;
    attributable_to: string;
  }[];
  rules_added?: string[];
  rules_removed?: string[];
  rules_modified?: string[];
  summary?: {
    device_changed: boolean;
    analysis_changed: boolean;
    score: [number | null, number | null];
    improved: number;
    regressed: number;
    coverage_changes: number;
    rules: { added: number; removed: number; modified: number };
  };
  explain?: string;
  note?: string;
}


// ------------------------------------------------------- policy object graph

export interface ResolvedRef {
  name: string;
  /** RESOLVED / UNRESOLVED / CYCLIC / UNSUPPORTED / AMBIGUOUS */
  state: string;
  values: string[];
  path: string[];
  detail: string;
}

export interface GraphRule {
  id: string;
  name: string;
  order: number;
  enabled: boolean;
  action: string;
  source_zones: string[];
  destination_zones: string[];
  source: ResolvedRef[];
  destination: ResolvedRef[];
  services: ResolvedRef[];
  logging: boolean | null;
  hit_count: number | null;
  /** Why a port question cannot be decided by this rule alone. */
  undecidable_for_ports: string | null;
  evidence: EvidenceRef[];
}

export interface GraphObject {
  name: string;
  kind: string;
  values: string[];
  members: string[];
  attrs: Record<string, unknown>;
  evidence: EvidenceRef[];
}

export interface GraphResponse {
  summary: {
    objects: number;
    rules: number;
    by_kind: Record<string, number>;
    zones: string[];
    untrusted_zones: string[];
    interfaces: Record<string, string>;
  };
  /** False means the platform does not evaluate top-to-bottom, so shadow
   *  analysis is suppressed -- and the absence of shadow findings must not be
   *  read as a tidy policy. */
  ordered: boolean;
  default_action: string;
  default_action_observed: boolean;
  objects_shown: GraphObject[];
  rules_shown: GraphRule[];
}


// ------------------------------------------------- AI governance (our AI)

/** Governs the model INSIDE NCSA, not the audited device. See /ai-governance. */
export interface AiGovernanceResponse {
  scope: string;
  atlas: {
    techniques: number;
    mitigations: number;
    identifier_check: { claimed: number; resolve_in_atlas: number } | null;
  };
  ai_rmf_functions: Record<string, string[]>;
  guardrails: {
    guardrail: string;
    atlas: string[];
    owasp_llm: string;
    ai_rmf: string;
  }[];
  injection_signatures: number;
  corpus_isolation: string;
}

// ------------------------------------------ extended checks, blast, what-if

/** A MITRE ATT&CK technique a control stands in front of. Presentation only. */
export interface AttackTag {
  id: string;
  name: string;
  tactics: string[];
  why: string;
}

export interface ExtendedEvidence {
  file: string;
  line: number | null;
  record: string | null;
  raw: string;
}

export interface ExtendedFinding {
  check_id: string;
  title: string;
  domain: string;
  state: ResultState;
  severity: Severity | "info";
  scope: string;
  reason: string;
  observed: unknown;
  expected: unknown;
  rationale: string;
  nist_800_53: string[];
  attack: AttackTag[];
  evidence: ExtendedEvidence[];
}

/** One extended domain. `present: null` means we could not tell -- not "none". */
export interface ExtendedDomain {
  domain: string;
  present: boolean | null;
  summary: string;
  counts: Partial<Record<ResultState, number>>;
  validated_on: string;
  inventory: Record<string, unknown>[];
  notes: string[];
  findings: ExtendedFinding[];
  error?: boolean;
}

export interface ExtendedResponse {
  scope: string;
  domains: Record<string, ExtendedDomain>;
}

export interface BlastStep {
  to_zone: string;
  port: number;
  protocol: string;
  service: string;
  permitted: boolean;
  decided_by: string;
  reason: string;
  uncertain: boolean;
  zone_assumed: boolean;
  administrative: boolean;
}

export interface BlastSummary {
  origin: string;
  zones_reachable: number;
  zones_considered: number;
  paths_open: number;
  administrative_paths: number;
  uncertain_paths: number;
  blocked: number;
  undecidable: number;
  undecidable_by_zone: Record<string, number>;
  zones_fully_undecidable: string[];
  origin_populated: boolean | null;
  origin_members: string[];
  latent: boolean;
}

export interface BlastResponse {
  summary: BlastSummary;
  origin: string;
  origin_address: string;
  reachable: BlastStep[];
  zones_considered: string[];
  notes: string[];
  explain: string;
}

export interface ZonesResponse {
  source_zones: string[];
  destination_zones: string[];
  untrusted: string[];
}

export interface WhatIfRequest {
  fix_controls?: string[];
  disable_rules?: string[];
  origin_zone?: string;
}

export interface WhatIfChange {
  control_id: string;
  title: string;
  severity: Severity;
  before: ResultState;
  after: ResultState;
  targeted: boolean;
}

export interface WhatIfResponse {
  simulated: true;
  label: string;
  applied: Record<string, unknown>[];
  rejected: { item: string; reason: string; suggest_disable_rules?: string[] }[];
  warnings: string[];
  before: Coverage;
  after: Coverage;
  delta: { score_pct: number | null; assessed_pct: number | null };
  changes: WhatIfChange[];
  caveats: string[];
  blast_radius?: { origin_zone: string; before: BlastSummary; after: BlastSummary };
}

// ------------------------------------------------------------ training loop

export interface TrainingContext {
  supported: boolean;
  has_pack: boolean;
  vendor: string;
  platform: string;
  platform_known: boolean;
  reader: string;
  suggested_signature: string[];
  source_file: string;
  coverage: Coverage | null;
}

export interface SchemaField {
  field: string;
  type: string;
  domain: string;
  controls: string[];
}

export interface ApprovalRequest {
  setting_name: string;
  field: string;
  platform: string;
  approved_by: string;
  kind?: string;
  assessment_id?: string;
  vendor?: string;
  reader?: string;
  signature?: string[];
}

export interface ApprovalResult {
  accepted: boolean;
  reason: string;
  registry_version: string;
  regression: {
    broken?: string[];
    detail?: string[];
    pass_rate_before?: number;
    pass_rate_after?: number;
    direction_alert?: boolean;
  };
}

export interface LearnedSummary {
  total: number;
  platforms: {
    platform: string;
    vendor: string;
    new_vendor: boolean;
    reader: string;
    signature: string[];
    count: number;
    mappings: { setting: string; field: string; approved_by: string }[];
  }[];
}

// --------------------------------------------------------------- the client

/**
 * An engine refusal is not a crash.
 *
 * The API answers "this platform has no object graph" with a 422 carrying a
 * reason and the platforms that CAN answer. That is information the user needs
 * to see, so it is carried on the error rather than flattened to "request
 * failed".
 */
export class ApiError extends Error {
  status: number;
  reason?: string;
  supportedPlatforms?: string[];
  notAFinding?: boolean;

  constructor(status: number, message: string, detail?: unknown) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    if (detail && typeof detail === "object") {
      const d = detail as Record<string, unknown>;
      this.reason = typeof d.reason === "string" ? d.reason : undefined;
      this.supportedPlatforms = Array.isArray(d.supported_platforms)
        ? (d.supported_platforms as string[])
        : undefined;
      this.notAFinding = d.not_a_finding === true;
    }
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let res: Response;
  try {
    res = await fetch(`${BASE}${path}`, init);
  } catch {
    throw new ApiError(
      0,
      "Cannot reach the NCSA engine. Start it with: uvicorn ncsa.api.app:app --port 8000",
    );
  }

  if (!res.ok) {
    let detail: unknown;
    let message = `${res.status} ${res.statusText}`;
    try {
      const body = await res.json();
      detail = body?.detail ?? body;
      if (typeof detail === "string") message = detail;
      else if (detail && typeof detail === "object") {
        const d = detail as Record<string, unknown>;
        if (typeof d.error === "string") message = d.error;
      }
    } catch {
      /* a non-JSON error body is still an error; keep the status line */
    }
    throw new ApiError(res.status, message, detail);
  }
  return (await res.json()) as T;
}

/** A platform live collection supports, and the exact commands it sends. */
export interface CollectProfile {
  platform: string;
  netmiko: string;
  napalm: string | null;
  commands: string[];
}

export interface CollectRequest {
  host: string;
  platform: string;
  username: string;
  password: string;
  secret?: string;
  port?: number;
  driver?: string;
  redact?: boolean;
  frameworks?: string[] | null;
}

export const api = {
  health: () => request<HealthResponse>("/health"),
  platforms: () => request<PlatformInfo[]>("/platforms"),
  frameworks: () => request<FrameworksResponse>("/frameworks"),
  aiGovernance: () => request<AiGovernanceResponse>("/ai-governance"),

  assessments: () => request<AssessmentSummary[]>("/assessments"),
  assessment: (id: string) => request<Assessment>(`/assessment/${id}`),

  /** Bulk ingestion is a deliverable, so this takes many files by design. */
  assess: (files: File[], redact: boolean, frameworks: string[] = []) => {
    const form = new FormData();
    for (const f of files) form.append("files", f);
    const fw = frameworks.map((k) => `&frameworks=${encodeURIComponent(k)}`).join("");
    return request<Assessment[]>(`/assess?redact=${redact}${fw}`, {
      method: "POST",
      body: form,
    });
  },

  /** Live SSH collection: read-only commands, credentials used once. */
  collectProfiles: () => request<CollectProfile[]>("/collect/profiles"),
  collect: (body: CollectRequest) =>
    request<Assessment[]>("/collect", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    }),

  hygiene: (id: string) => request<HygieneResponse>(`/assessment/${id}/hygiene`),
  graph: (id: string) => request<GraphResponse>(`/assessment/${id}/graph`),
  extended: (id: string) =>
    request<ExtendedResponse>(`/assessment/${id}/extended`),
  zones: (id: string) => request<ZonesResponse>(`/assessment/${id}/zones`),
  /** SVG text of the topology figure. Rendered server-side, shown via <img>. */
  topologySvg: async (id: string, redact: boolean): Promise<string> => {
    const res = await fetch(
      `${BASE}/assessment/${id}/topology-map.svg?redact=${redact}`,
    );
    if (!res.ok) throw new ApiError(res.status, `${res.status} ${res.statusText}`);
    return res.text();
  },
  blastRadius: (id: string, originZone: string) =>
    request<BlastResponse>(
      `/assessment/${id}/blast-radius?origin_zone=${encodeURIComponent(originZone)}`,
      { method: "POST" },
    ),
  whatIf: (id: string, body: WhatIfRequest) =>
    request<WhatIfResponse>(`/assessment/${id}/what-if`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    }),
  remediation: (id: string) =>
    request<RemediationResponse>(`/assessment/${id}/remediation`),
  training: (id: string) =>
    request<TrainingCandidate[]>(`/assessment/${id}/training`),
  trainingContext: (id: string) =>
    request<TrainingContext>(`/assessment/${id}/training/context`),
  schemaFields: () => request<SchemaField[]>("/schema/fields"),
  learnedSummary: () => request<LearnedSummary>("/training/learned"),
  approveMapping: (body: ApprovalRequest) =>
    request<ApprovalResult>("/training/approve", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    }),
  rejectMapping: (body: {
    setting_name: string;
    platform: string;
    rejected_by: string;
    reason?: string;
  }) =>
    request<unknown>("/training/reject", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    }),
  reassess: (id: string) =>
    request<Assessment>(`/assessment/${id}/reassess`, { method: "POST" }),
  recertification: (id: string) =>
    request<RecertResponse>(`/assessment/${id}/recertification`),
  consensus: (id: string) =>
    request<ConsensusResponse>(`/assessment/${id}/consensus`),
  interfaces: (id: string) =>
    request<InterfacesResponse>(`/assessment/${id}/interfaces`),

  reach: (id: string, q: ReachQuery) =>
    request<ReachResponse>(`/assessment/${id}/reach`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(q),
    }),

  snapshot: (id: string) =>
    request<{ device_key: string; saved_to: string; taken_at: string }>(
      `/assessment/${id}/snapshot`,
      { method: "POST" },
    ),
  diff: (id: string) => request<DiffResponse>(`/assessment/${id}/diff`),

  topology: (assessment_ids: string[]) =>
    request<TopologyResponse>("/topology", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ assessment_ids }),
    }),
};

// ----------------------------------------------------------------- helpers

/** Counts by severity, over FAILING controls only. */
export function failuresBySeverity(findings: Finding[]): Record<Severity, number> {
  const out: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of findings) {
    if (f.state === "FAIL" || f.state === "PARTIAL") out[f.severity] += 1;
  }
  return out;
}

/**
 * The caption that must accompany every score.
 *
 * Written once, here, so no page can render the score alone by forgetting.
 */
export function coverageCaption(c: Coverage): string {
  return `${c.score_pct}% of ${c.controls_decided} decided controls · ${c.assessed_pct}% of the device assessed`;
}

export function vendorLabel(v: string): string {
  const map: Record<string, string> = {
    sonicwall: "SonicWall",
    fortinet: "Fortinet",
    paloalto: "Palo Alto",
    cisco: "Cisco",
    juniper: "Juniper",
    arista: "Arista",
    hpe_aruba: "HPE Aruba",
    aws: "AWS",
  };
  return map[v] ?? v.charAt(0).toUpperCase() + v.slice(1);
}
