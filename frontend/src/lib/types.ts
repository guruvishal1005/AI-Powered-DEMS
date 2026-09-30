/** Shared API shapes used until `pnpm gen:types` regenerates from OpenAPI. */

export type Severity = "informational" | "low" | "medium" | "high" | "critical";
export type IntegrityStatus =
  | "pending"
  | "verified"
  | "hash_mismatch"
  | "decryption_failed"
  | "object_missing";
export type Provenance = "derived" | "statistical" | "llm_assisted";

export type ActorRef = {
  id: string;
  full_name: string;
  email: string;
  job_title?: string | null;
  badge_number?: string | null;
};

export type CaseRef = { id: string; reference: string; title: string };
export type EvidenceRef = {
  id: string;
  reference: string;
  title: string;
  original_filename: string;
};

export type PageMeta = {
  page: number;
  size: number;
  total: number;
  pages: number;
  has_next: boolean;
  has_previous: boolean;
};

export type Page<T> = { items: T[]; meta: PageMeta };

export type RoleSummary = {
  id: string;
  slug: string;
  name: string;
  description: string;
  rank: number;
};

export type AuthenticatedUser = {
  id: string;
  email: string;
  full_name: string;
  job_title: string | null;
  department: string | null;
  badge_number: string | null;
  phone: string | null;
  status: string;
  timezone: string;
  initials: string;
  mfa_enabled: boolean;
  must_change_password: boolean;
  last_login_at: string | null;
  roles: RoleSummary[];
  permissions: string[];
};

export type LoginResponse = {
  access_token: string;
  token_type: string;
  expires_in: number;
  expires_at: string;
  csrf_token: string;
  user: AuthenticatedUser;
};

export type RefreshResponse = {
  access_token: string;
  expires_at: string;
  csrf_token: string;
};

export type CaseSummary = {
  id: string;
  reference: string;
  title: string;
  incident_type: string;
  severity: Severity;
  status: string;
  opened_at: string | null;
  incident_occurred_at: string | null;
  last_activity_at: string | null;
  lead_investigator: ActorRef | null;
  classification: string;
  jurisdiction: string | null;
  organization: string | null;
  external_reference: string | null;
  risk_score: number | null;
  legal_hold: boolean;
  tags: string[];
  created_at: string;
  updated_at: string;
};

export type CaseDetail = CaseSummary & {
  summary: string;
  reported_at: string | null;
  closed_at: string | null;
  closed_by: ActorRef | null;
  closure_summary: string | null;
  created_by: ActorRef | null;
  risk_breakdown: Record<string, unknown>;
  risk_computed_at: string | null;
  retention_expires_at: string | null;
  assignments: Array<{
    id: string;
    user: ActorRef;
    role_on_case: string;
    assigned_at: string;
    unassigned_at: string | null;
  }>;
};

export type EvidenceSummary = {
  id: string;
  reference: string;
  case_id: string;
  title: string;
  original_filename: string;
  evidence_type: string;
  source_category: string;
  acquisition_method: string;
  sha256: string;
  size_bytes: number;
  mime_type: string;
  declared_mime_type: string | null;
  mime_mismatch: boolean;
  entropy: number | null;
  status: string;
  integrity_status: IntegrityStatus;
  last_verified_at: string | null;
  version_count: number;
  custody_event_count: number;
  acquired_at: string | null;
  uploaded_at: string;
  uploaded_by: ActorRef | null;
  legal_hold: boolean;
  analysis_completed_at: string | null;
  tags: string[];
};

export type EvidenceDetail = EvidenceSummary & {
  case: CaseRef | null;
  description: string;
  source_description: string | null;
  source_identifier: string | null;
  source_location: string | null;
  acquired_by_name: string | null;
  acquired_by: ActorRef | null;
  received_at: string | null;
  integrity_note: string | null;
  custody_head_hash: string | null;
  extracted_metadata: Record<string, unknown>;
  retention_expires_at: string | null;
  current_version: {
    id: string;
    version_number: number;
    sha256: string;
    sha1: string | null;
    md5: string | null;
    size_bytes: number;
    mime_type: string;
    reason: string;
    is_current: boolean;
    created_by: ActorRef | null;
    created_at: string;
  } | null;
  created_at: string;
  updated_at: string;
};

export type CustodyEvent = {
  id: string;
  sequence: number;
  action: string;
  actor_id: string | null;
  actor_label: string;
  actor_role: string | null;
  occurred_at: string;
  recorded_at: string;
  previous_state: Record<string, unknown>;
  new_state: Record<string, unknown>;
  reason: string | null;
  notes: string | null;
  sha256_at_event: string | null;
  integrity_status_at_event: IntegrityStatus | null;
  ip_address: string | null;
  request_id: string | null;
  details: Record<string, unknown>;
  previous_hash: string | null;
  entry_hash: string;
  signing_key_id: string | null;
};

export type ChainStatus = {
  evidence_id: string;
  evidence_reference: string;
  event_count: number;
  intact: boolean;
  trustworthy: boolean;
  head_hash: string | null;
  head_matches_record: boolean;
  signatures_checked: number;
  signatures_valid: number;
  breaks: Array<{ kind: string; sequence: number; record_id: string; detail: string }>;
  summary: string;
  verified_at: string;
};

export type IntegrityCheck = {
  id: string;
  status: IntegrityStatus;
  expected_sha256: string;
  computed_sha256: string | null;
  ciphertext_verified: boolean;
  trigger: string;
  checked_by: ActorRef | null;
  duration_ms: number | null;
  detail: string | null;
  created_at: string;
};

export type AlertSummary = {
  id: string;
  reference: string;
  type: string;
  source: string;
  severity: Severity;
  status: string;
  title: string;
  occurrence_count: number;
  first_seen_at: string;
  last_seen_at: string;
  case_id: string | null;
  evidence_id: string | null;
  assigned_to: ActorRef | null;
  created_at: string;
};

export type Notification = {
  id: string;
  kind: string;
  title: string;
  body: string | null;
  severity: Severity;
  link: string | null;
  alert_id: string | null;
  read_at: string | null;
  is_dismissed: boolean;
  created_at: string;
};

export type Dashboard = {
  generated_at: string;
  cases_by_status: Record<string, number>;
  cases_open: number;
  cases_total: number;
  evidence_total: number;
  evidence_by_type: Array<{ label: string; count: number }>;
  integrity: {
    by_status: Record<string, number>;
    verified: number;
    failed: number;
    pending: number;
    last_failure_at: string | null;
  };
  open_alerts: Record<string, number>;
  queue_depth: number;
  jobs_failed_24h: number;
  storage_bytes: number;
  recent_cases: CaseSummary[];
  attention_cases: CaseSummary[];
  recent_evidence: EvidenceSummary[];
  recent_alerts: AlertSummary[];
  activity: Array<{ bucket_start: string; count: number }>;
  worst_alert_severity: Severity | null;
};

export type Insight = {
  id: string;
  case_id: string | null;
  kind: string;
  provenance: Provenance;
  severity: Severity;
  confidence: number;
  title: string;
  observed: string;
  interpretation: string | null;
  llm_narrative: string | null;
  llm_model: string | null;
  evidence_refs: Array<Record<string, unknown>>;
  entity_refs: Array<Record<string, unknown>>;
  case_refs: Array<Record<string, unknown>>;
  basis: Record<string, unknown>;
  rank_score: number;
  generator: string;
  generator_version: string;
  is_pinned: boolean;
  dismissed_at: string | null;
  dismissed_reason: string | null;
  created_at: string;
  updated_at: string;
};

export type TimelineEvent = {
  id: string;
  source: string;
  occurred_at: string;
  recorded_at: string | null;
  time_confidence: string | null;
  timezone_assumed: boolean;
  kind: string;
  title: string;
  summary: string | null;
  severity: Severity | null;
  case_id: string | null;
  evidence_id: string | null;
  evidence_reference: string | null;
  actor_label: string | null;
  locator: Record<string, unknown>;
  excerpt: string | null;
  attributes: Record<string, unknown>;
};

export type Timeline = {
  case_id: string | null;
  window_start: string | null;
  window_end: string | null;
  resolution: "raw" | "minute" | "hour" | "day";
  total: number;
  events: TimelineEvent[];
  buckets: Array<{
    bucket_start: string;
    bucket_end: string;
    count: number;
    by_source: Record<string, number>;
    by_kind: Record<string, number>;
    peak_severity: Severity | null;
  }>;
  sources: Record<string, number>;
};

export type GraphNode = {
  id: string;
  kind: "entity" | "evidence" | "case";
  label: string;
  sublabel: string | null;
  entity_type: string | null;
  evidence_id: string | null;
  case_id: string | null;
  occurrence_count: number;
  document_frequency: number;
  intel_severity: string | null;
  degree_centrality: number;
  betweenness_centrality: number;
  pagerank: number;
  is_pivot: boolean;
  attributes: Record<string, unknown>;
};

export type GraphEdge = {
  id: string;
  source: string;
  target: string;
  kind: string;
  label: string;
  weight: number;
  score: number | null;
  is_cross_case: boolean;
  basis: Record<string, unknown>;
};

export type GraphProjection = {
  case_id: string | null;
  depth: number;
  node_count: number;
  edge_count: number;
  pivot_node_ids: string[];
  nodes: GraphNode[];
  edges: GraphEdge[];
  layout_hint: "cose" | "concentric" | "breadthfirst";
};

export type ReportSummary = {
  id: string;
  reference: string;
  case_id: string;
  title: string;
  version: number;
  status: string;
  classification: string;
  evidence_count: number;
  finding_count: number;
  integrity_verified_count: number;
  integrity_failed_count: number;
  custody_chain_intact: boolean | null;
  snapshot_sha256: string | null;
  is_signed: boolean;
  prepared_by: ActorRef | null;
  prepared_at: string | null;
  signed_at: string | null;
  created_at: string;
};

export type Finding = {
  id: string;
  case_id: string;
  sequence: number;
  kind: string;
  title: string;
  description: string;
  confidence: string;
  severity: Severity;
  is_included_in_report: boolean;
  author: ActorRef | null;
  evidence_items: EvidenceRef[];
  created_at: string;
};

export type SearchResults = {
  query: string;
  cases: Array<{ kind: string; id: string; reference: string | null; title: string; subtitle?: string | null; href: string }>;
  evidence: Array<{ kind: string; id: string; reference: string | null; title: string; subtitle?: string | null; href: string }>;
  entities: Array<{ kind: string; id: string; reference: string | null; title: string; subtitle?: string | null; href: string }>;
  hashes: Array<{ kind: string; id: string; reference: string | null; title: string; subtitle?: string | null; href: string }>;
};

export type AuditEntry = {
  id: string;
  sequence: number;
  action: string;
  resource_type: string;
  resource_id: string | null;
  resource_label: string | null;
  actor_id: string | null;
  actor_label: string;
  result: string;
  case_id: string | null;
  ip_address: string | null;
  request_id: string | null;
  reason: string | null;
  detail: string | null;
  recorded_at: string;
  previous_hash: string | null;
  entry_hash: string;
};

export class ApiError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
    public details: Record<string, unknown> = {},
  ) {
    super(message);
    this.name = "ApiError";
  }
}
