-- PHI Guard Intelligence persistent metadata store.
-- Stores tenant-scoped sanitized metadata, scan history, agent identity, RBAC, audit events, and retention policy.
-- Raw PHI values and raw uploaded files do not belong in these tables.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS organizations (
  id text PRIMARY KEY,
  name text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS workspaces (
  id text PRIMARY KEY,
  organization_id text NOT NULL REFERENCES organizations(id),
  name text NOT NULL,
  kms_key_ref text,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS users (
  id text PRIMARY KEY,
  organization_id text NOT NULL REFERENCES organizations(id),
  email text NOT NULL,
  display_name text,
  oidc_subject text,
  mfa_required boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS roles (
  id text PRIMARY KEY,
  workspace_id text NOT NULL REFERENCES workspaces(id),
  name text NOT NULL,
  permissions text[] NOT NULL DEFAULT '{}',
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS user_roles (
  user_id text NOT NULL REFERENCES users(id),
  role_id text NOT NULL REFERENCES roles(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, role_id)
);

CREATE TABLE IF NOT EXISTS data_sources (
  id text PRIMARY KEY,
  workspace_id text NOT NULL REFERENCES workspaces(id),
  type text NOT NULL,
  name text NOT NULL,
  connection_mode text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  last_scan_at timestamptz
);

CREATE TABLE IF NOT EXISTS scanner_agents (
  id text PRIMARY KEY,
  workspace_id text NOT NULL REFERENCES workspaces(id),
  name text NOT NULL,
  version text,
  identity_mode text NOT NULL,
  status text NOT NULL DEFAULT 'active',
  last_seen_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS agent_tokens (
  id text PRIMARY KEY,
  scanner_agent_id text NOT NULL REFERENCES scanner_agents(id),
  token_hash text NOT NULL,
  expires_at timestamptz,
  revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS retention_policies (
  id text PRIMARY KEY,
  workspace_id text NOT NULL REFERENCES workspaces(id),
  raw_upload_ttl_minutes integer NOT NULL DEFAULT 10,
  metadata_ttl_days integer,
  delete_raw_after_scan boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS secrets (
  id text PRIMARY KEY,
  workspace_id text NOT NULL REFERENCES workspaces(id),
  secret_type text NOT NULL,
  secret_ref text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  rotated_at timestamptz
);

CREATE TABLE IF NOT EXISTS scan_runs (
  id text PRIMARY KEY,
  workspace_id text NOT NULL,
  data_source_id text,
  scanner_agent_id text,
  source text NOT NULL,
  mode text,
  status text NOT NULL,
  started_at timestamptz NOT NULL DEFAULT now(),
  completed_at timestamptz,
  summary_json jsonb NOT NULL DEFAULT '{}'::jsonb,
  sanitized_package_sha256 text
);

CREATE TABLE IF NOT EXISTS assets (
  id text PRIMARY KEY,
  workspace_id text NOT NULL,
  scan_run_id text NOT NULL REFERENCES scan_runs(id),
  data_source_id text,
  asset_type text NOT NULL,
  name text NOT NULL,
  schema_name text,
  table_name text,
  column_name text,
  data_type text,
  row_count_estimate bigint,
  risk_score integer NOT NULL DEFAULT 0,
  metadata_json jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS classifications (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  asset_id text NOT NULL REFERENCES assets(id),
  label text NOT NULL,
  confidence numeric NOT NULL,
  source text NOT NULL,
  details_json jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS lineage_edges (
  id text PRIMARY KEY,
  workspace_id text NOT NULL,
  scan_run_id text NOT NULL REFERENCES scan_runs(id),
  source_asset_id text NOT NULL,
  target_asset_id text NOT NULL,
  edge_type text NOT NULL,
  confidence numeric NOT NULL,
  evidence_json jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS access_grants (
  id text PRIMARY KEY,
  workspace_id text NOT NULL,
  scan_run_id text NOT NULL REFERENCES scan_runs(id),
  asset_id text NOT NULL,
  principal_type text NOT NULL,
  principal_name text NOT NULL,
  permission text NOT NULL,
  source text NOT NULL,
  last_seen_at timestamptz
);

CREATE TABLE IF NOT EXISTS findings (
  id text PRIMARY KEY,
  workspace_id text NOT NULL,
  scan_run_id text NOT NULL REFERENCES scan_runs(id),
  severity text NOT NULL,
  title text NOT NULL,
  status text NOT NULL,
  risk_score integer NOT NULL,
  confidence numeric NOT NULL,
  asset_id text NOT NULL,
  description text NOT NULL,
  why_it_matters text NOT NULL,
  control_mapping_json jsonb NOT NULL DEFAULT '[]'::jsonb,
  remediation_summary text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  resolved_at timestamptz
);

CREATE TABLE IF NOT EXISTS finding_evidence (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  finding_id text NOT NULL REFERENCES findings(id),
  evidence_type text NOT NULL,
  safe_snippet text NOT NULL,
  raw_value_stored boolean NOT NULL DEFAULT false,
  metadata_json jsonb NOT NULL DEFAULT '{}'::jsonb,
  CHECK (raw_value_stored = false)
);

CREATE TABLE IF NOT EXISTS remediation_tasks (
  id text PRIMARY KEY,
  finding_id text NOT NULL REFERENCES findings(id),
  title text NOT NULL,
  description text,
  owner text,
  status text NOT NULL DEFAULT 'open',
  sql_patch text,
  iac_patch text,
  policy_patch text,
  created_at timestamptz NOT NULL DEFAULT now(),
  completed_at timestamptz
);

CREATE TABLE IF NOT EXISTS audit_events (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id text NOT NULL,
  actor_id text NOT NULL,
  event_type text NOT NULL,
  metadata_json jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_scan_runs_workspace_completed ON scan_runs (workspace_id, completed_at DESC);
CREATE INDEX IF NOT EXISTS idx_assets_workspace_scan ON assets (workspace_id, scan_run_id);
CREATE INDEX IF NOT EXISTS idx_findings_workspace_score ON findings (workspace_id, risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_audit_events_workspace_created ON audit_events (workspace_id, created_at DESC);
