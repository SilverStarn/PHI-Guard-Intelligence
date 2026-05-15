export type Severity = "critical" | "high" | "moderate" | "low";

export type FindingSummary = {
  id: string;
  title: string;
  severity: Severity;
  status: string;
  risk_score: number;
  confidence: number;
  asset_id: string;
  description: string;
  control_mapping: string[];
  remediation_summary: string;
};

export type FindingDetail = FindingSummary & {
  observation: string;
  why_it_matters: string;
  recommended_steps: string[];
  human_review: string;
  blast_radius: Record<string, unknown>;
  evidence: Array<{
    evidence_type: string;
    safe_snippet: string;
    raw_value_stored: boolean;
    metadata: Record<string, unknown>;
  }>;
  risk_factors: {
    impact: number;
    likelihood: number;
    exposure: number;
    control_gap: number;
    confidence: number;
  };
};

export type Summary = {
  workspace: string;
  scan_id: string;
  generated_at: string;
  risk_score: number;
  critical_findings: number;
  high_findings: number;
  open_findings: number;
  phi_assets: number;
  free_text_fields: number;
  external_destinations: number;
  deidentification_readiness_score: number;
  top_findings: FindingSummary[];
  trend: Array<{ period: string; critical: number; high: number; resolved: number }>;
};

export type SourceInfo = {
  mode: "demo" | "upload";
  workspace: string;
  scan_id: string;
  generated_at: string;
  parsed_files: string[];
  unsupported_files: string[];
  warnings: string[];
};

export type GraphNodeDto = {
  id: string;
  label: string;
  type: string;
  riskScore: number;
  rowCount?: number;
  description: string;
  classifications: string[];
};

export type GraphEdgeDto = {
  id: string;
  source: string;
  target: string;
  type: string;
  label: string;
  confidence: number;
};

export type GraphPayload = {
  nodes: GraphNodeDto[];
  edges: GraphEdgeDto[];
};

export type DeidentificationRow = {
  table: string;
  row_count_estimate: number;
  blockers: Record<string, string[]>;
  status: "Not ready" | "Review" | "Likely ready";
  readiness_score: number;
};

export type AccessMatrix = {
  principals: string[];
  assets: Array<{ id: string; name: string; risk_score: number }>;
  cells: Array<{ principal: string; asset_id: string; permission: string; risk: "high" | "moderate" }>;
  risky_combinations: Array<{ principal: string; reason: string }>;
};

export type RemediationTask = {
  id: string;
  finding_id: string;
  title: string;
  status: "open" | "in_progress" | "resolved";
  owner: string;
  severity: Severity;
  risk_score: number;
  asset_id: string;
  effort: "XS" | "S" | "M" | "L";
  due_window: string;
  control_mapping: string[];
  recommended_steps: string[];
  human_review: string;
  risk_reduction: number;
};

export type RemediationPayload = {
  summary: {
    total: number;
    critical: number;
    high: number;
    estimated_risk_reduction: number;
    by_owner: Record<string, number>;
    by_status: Record<string, number>;
  };
  items: RemediationTask[];
};

export type ReportPayload = {
  title: string;
  generated_at: string;
  executive_summary: {
    risk_score: number;
    critical_findings: number;
    high_findings: number;
    phi_assets: number;
    message: string;
  };
  technical_findings: FindingDetail[];
  limitations: string[];
};

export type ScanRun = {
  scan_id?: string;
  workspace?: string;
  source?: string;
  status?: string;
  completed_at?: string;
  created_at?: string;
  summary?: {
    asset_count?: number;
    finding_count?: number;
    critical_count?: number;
    raw_value_stored?: boolean;
  };
  summary_json?: {
    asset_count?: number;
    finding_count?: number;
    critical_count?: number;
    raw_value_stored?: boolean;
  };
};

export type AuditEvent = {
  created_at: string;
  workspace?: string;
  actor?: string;
  actor_id?: string;
  event_type: string;
  metadata?: Record<string, unknown>;
  metadata_json?: Record<string, unknown>;
};
