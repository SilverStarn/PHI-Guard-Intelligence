CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS patients (
  id uuid PRIMARY KEY,
  first_name text NOT NULL,
  last_name text NOT NULL,
  email text NOT NULL,
  phone_number text NOT NULL,
  ssn text NOT NULL,
  mrn text NOT NULL,
  date_of_birth date NOT NULL,
  street_address text NOT NULL,
  city text NOT NULL,
  state text NOT NULL,
  zip text NOT NULL,
  gender text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS encounters (
  id uuid PRIMARY KEY,
  patient_id uuid NOT NULL REFERENCES patients(id),
  provider_id uuid NOT NULL,
  encounter_date date NOT NULL,
  diagnosis_code text NOT NULL,
  procedure_code text NOT NULL,
  condition text NOT NULL,
  notes_summary text
);

CREATE TABLE IF NOT EXISTS appointment_notes (
  id uuid PRIMARY KEY,
  appointment_id uuid NOT NULL,
  patient_id uuid NOT NULL REFERENCES patients(id),
  notes text NOT NULL,
  created_by text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS claims (
  id uuid PRIMARY KEY,
  patient_id uuid NOT NULL REFERENCES patients(id),
  claim_id text NOT NULL,
  payer text NOT NULL,
  diagnosis_code text NOT NULL,
  claim_amount numeric(12, 2) NOT NULL,
  service_date date NOT NULL,
  account_number text NOT NULL
);

CREATE TABLE IF NOT EXISTS payments (
  id uuid PRIMARY KEY,
  patient_id uuid NOT NULL REFERENCES patients(id),
  claim_id uuid NOT NULL REFERENCES claims(id),
  payment_amount numeric(12, 2) NOT NULL,
  account_balance numeric(12, 2) NOT NULL,
  payment_date date NOT NULL
);

CREATE TABLE IF NOT EXISTS medications (
  id uuid PRIMARY KEY,
  patient_id uuid NOT NULL REFERENCES patients(id),
  medication_name text NOT NULL,
  start_date date NOT NULL,
  condition_code text NOT NULL
);

CREATE TABLE IF NOT EXISTS lab_results (
  id uuid PRIMARY KEY,
  patient_id uuid NOT NULL REFERENCES patients(id),
  encounter_id uuid NOT NULL REFERENCES encounters(id),
  lab_result text NOT NULL,
  result_value text NOT NULL,
  result_date date NOT NULL
);

CREATE TABLE IF NOT EXISTS support_tickets (
  id uuid PRIMARY KEY,
  patient_id uuid NOT NULL REFERENCES patients(id),
  email text NOT NULL,
  message text NOT NULL,
  status text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS analytics_patient_segments (
  patient_id uuid NOT NULL REFERENCES patients(id),
  date_of_birth date NOT NULL,
  zip text NOT NULL,
  diagnosis_category text NOT NULL,
  risk_band text NOT NULL,
  last_encounter_date date NOT NULL
);

CREATE TABLE IF NOT EXISTS marketing_campaign_exports (
  patient_id uuid NOT NULL REFERENCES patients(id),
  email text NOT NULL,
  phone_number text NOT NULL,
  diagnosis_category text NOT NULL,
  campaign_id text NOT NULL,
  exported_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS ai_prompt_logs (
  id uuid PRIMARY KEY,
  patient_id uuid NOT NULL REFERENCES patients(id),
  prompt_text text NOT NULL,
  model_name text NOT NULL,
  response_summary text,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS audit_logs (
  id uuid PRIMARY KEY,
  actor_id text NOT NULL,
  role_name text NOT NULL,
  table_name text NOT NULL,
  action text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

INSERT INTO patients (
  id, first_name, last_name, email, phone_number, ssn, mrn, date_of_birth,
  street_address, city, state, zip, gender
) VALUES
  ('00000000-0000-4000-8000-000000000001', 'Alex', 'Rivera', 'alex.rivera@example.test', '555-214-0198', '123-45-6789', 'MRN-44812048', '1982-04-16', '10 Demo Street', 'Cambridge', 'MA', '02139', 'female'),
  ('00000000-0000-4000-8000-000000000002', 'Jordan', 'Lee', 'jordan.lee@example.test', '555-772-4421', '987-65-4321', 'MRN-44812049', '1974-06-11', '22 Synthetic Ave', 'New York', 'NY', '10027', 'male'),
  ('00000000-0000-4000-8000-000000000003', 'Casey', 'Nguyen', 'casey.nguyen@example.test', '555-303-4401', '111-22-3333', 'MRN-44812050', '1990-09-09', '7 Sample Road', 'Austin', 'TX', '78701', 'nonbinary')
ON CONFLICT (id) DO NOTHING;

INSERT INTO encounters (
  id, patient_id, provider_id, encounter_date, diagnosis_code, procedure_code, condition, notes_summary
) VALUES
  ('10000000-0000-4000-8000-000000000001', '00000000-0000-4000-8000-000000000001', gen_random_uuid(), '2025-11-03', 'E11.9', '99213', 'diabetes follow-up', 'routine follow-up'),
  ('10000000-0000-4000-8000-000000000002', '00000000-0000-4000-8000-000000000002', gen_random_uuid(), '2025-12-14', 'I10', '99214', 'hypertension', 'blood pressure review'),
  ('10000000-0000-4000-8000-000000000003', '00000000-0000-4000-8000-000000000003', gen_random_uuid(), '2026-01-20', 'J45.909', '99213', 'asthma', 'medication refill')
ON CONFLICT (id) DO NOTHING;

INSERT INTO appointment_notes (
  id, appointment_id, patient_id, notes, created_by
) VALUES
  ('20000000-0000-4000-8000-000000000001', gen_random_uuid(), '00000000-0000-4000-8000-000000000001', 'Synthetic note contains phone-like token 555-214-0198 and date 04/16/1982.', 'scheduler_demo'),
  ('20000000-0000-4000-8000-000000000002', gen_random_uuid(), '00000000-0000-4000-8000-000000000002', 'Synthetic note mentions address-like token 22 Synthetic Ave for callback.', 'support_demo')
ON CONFLICT (id) DO NOTHING;

INSERT INTO claims (
  id, patient_id, claim_id, payer, diagnosis_code, claim_amount, service_date, account_number
) VALUES
  ('30000000-0000-4000-8000-000000000001', '00000000-0000-4000-8000-000000000001', 'CLM-1001', 'Demo Health Plan', 'E11.9', 240.00, '2025-11-03', 'acct_84729120'),
  ('30000000-0000-4000-8000-000000000002', '00000000-0000-4000-8000-000000000002', 'CLM-1002', 'Northstar Payer', 'I10', 310.00, '2025-12-14', 'acct_84729121')
ON CONFLICT (id) DO NOTHING;

INSERT INTO payments (
  id, patient_id, claim_id, payment_amount, account_balance, payment_date
) VALUES
  ('40000000-0000-4000-8000-000000000001', '00000000-0000-4000-8000-000000000001', '30000000-0000-4000-8000-000000000001', 120.00, 120.00, '2025-12-29'),
  ('40000000-0000-4000-8000-000000000002', '00000000-0000-4000-8000-000000000002', '30000000-0000-4000-8000-000000000002', 200.00, 110.00, '2026-01-05')
ON CONFLICT (id) DO NOTHING;

INSERT INTO medications (
  id, patient_id, medication_name, start_date, condition_code
) VALUES
  ('50000000-0000-4000-8000-000000000001', '00000000-0000-4000-8000-000000000003', 'synthetic albuterol', '2025-08-04', 'J45.909')
ON CONFLICT (id) DO NOTHING;

INSERT INTO lab_results (
  id, patient_id, encounter_id, lab_result, result_value, result_date
) VALUES
  ('60000000-0000-4000-8000-000000000001', '00000000-0000-4000-8000-000000000001', '10000000-0000-4000-8000-000000000001', 'synthetic A1C', '7.4', '2026-02-08')
ON CONFLICT (id) DO NOTHING;

INSERT INTO support_tickets (
  id, patient_id, email, message, status
) VALUES
  ('70000000-0000-4000-8000-000000000001', '00000000-0000-4000-8000-000000000002', 'jordan.lee@example.test', 'Synthetic complaint includes callback token 555-772-4421 and visit date 12/14/2025.', 'open')
ON CONFLICT (id) DO NOTHING;

INSERT INTO analytics_patient_segments (
  patient_id, date_of_birth, zip, diagnosis_category, risk_band, last_encounter_date
) VALUES
  ('00000000-0000-4000-8000-000000000001', '1982-04-16', '02139', 'diabetes', 'high', '2025-11-03'),
  ('00000000-0000-4000-8000-000000000002', '1974-06-11', '10027', 'hypertension', 'moderate', '2025-12-14');

INSERT INTO marketing_campaign_exports (
  patient_id, email, phone_number, diagnosis_category, campaign_id
) VALUES
  ('00000000-0000-4000-8000-000000000001', 'alex.rivera@example.test', '555-214-0198', 'diabetes', 'CMP-2026-01'),
  ('00000000-0000-4000-8000-000000000003', 'casey.nguyen@example.test', '555-303-4401', 'asthma', 'CMP-2026-01');

INSERT INTO ai_prompt_logs (
  id, patient_id, prompt_text, model_name, response_summary
) VALUES
  ('80000000-0000-4000-8000-000000000001', '00000000-0000-4000-8000-000000000001', 'Synthetic prompt includes patient-linked detail for visit summary.', 'demo-model', 'synthetic response summary')
ON CONFLICT (id) DO NOTHING;

DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'clinical_reader') THEN CREATE ROLE clinical_reader; END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'billing_reader') THEN CREATE ROLE billing_reader; END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'analyst_role') THEN CREATE ROLE analyst_role; END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'reporting_role') THEN CREATE ROLE reporting_role; END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'support_role') THEN CREATE ROLE support_role; END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'marketing_ops') THEN CREATE ROLE marketing_ops; END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'old_service_account') THEN CREATE ROLE old_service_account; END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'ai_experiment_service') THEN CREATE ROLE ai_experiment_service; END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'security_auditor') THEN CREATE ROLE security_auditor; END IF;
END $$;

GRANT USAGE ON SCHEMA public TO clinical_reader, billing_reader, analyst_role, reporting_role, support_role, marketing_ops, old_service_account, ai_experiment_service, security_auditor;
GRANT SELECT ON patients TO clinical_reader, analyst_role, reporting_role, old_service_account;
GRANT SELECT ON encounters TO clinical_reader, reporting_role;
GRANT SELECT ON claims TO billing_reader, analyst_role;
GRANT SELECT ON payments TO billing_reader;
GRANT SELECT ON lab_results TO clinical_reader, reporting_role;
GRANT SELECT ON appointment_notes TO support_role, analyst_role;
GRANT SELECT ON support_tickets TO support_role;
GRANT SELECT ON analytics_patient_segments TO analyst_role;
GRANT SELECT ON marketing_campaign_exports TO marketing_ops, analyst_role;
GRANT SELECT ON ai_prompt_logs TO old_service_account;
GRANT INSERT ON ai_prompt_logs TO ai_experiment_service;
GRANT SELECT ON audit_logs TO security_auditor;

