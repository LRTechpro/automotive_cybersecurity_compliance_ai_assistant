PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS components (
  id INTEGER PRIMARY KEY,
  code TEXT UNIQUE NOT NULL,
  name TEXT NOT NULL,
  description TEXT NOT NULL,
  role TEXT NOT NULL,
  external_interfaces TEXT NOT NULL,
  security_focus TEXT NOT NULL,
  scope_status TEXT NOT NULL DEFAULT 'in_scope'
);

CREATE TABLE IF NOT EXISTS interfaces (
  id INTEGER PRIMARY KEY,
  source_code TEXT NOT NULL,
  target_code TEXT NOT NULL,
  protocol TEXT NOT NULL,
  trust_boundary TEXT NOT NULL,
  description TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS assets (
  id INTEGER PRIMARY KEY,
  asset_code TEXT UNIQUE NOT NULL,
  component_code TEXT NOT NULL,
  name TEXT NOT NULL,
  security_properties TEXT NOT NULL,
  description TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS threats (
  id INTEGER PRIMARY KEY,
  threat_code TEXT UNIQUE NOT NULL,
  component_code TEXT NOT NULL,
  title TEXT NOT NULL,
  stride_categories TEXT NOT NULL,
  mitre_techniques TEXT NOT NULL,
  scenario TEXT NOT NULL,
  vulnerability TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tara_records (
  id INTEGER PRIMARY KEY,
  tara_code TEXT UNIQUE NOT NULL,
  component_code TEXT NOT NULL,
  asset_code TEXT NOT NULL,
  threat_code TEXT NOT NULL,
  damage_scenario TEXT NOT NULL,
  attack_path TEXT NOT NULL,
  impact TEXT NOT NULL,
  feasibility TEXT NOT NULL,
  initial_risk TEXT NOT NULL,
  treatment TEXT NOT NULL,
  cybersecurity_goal TEXT NOT NULL,
  residual_risk TEXT NOT NULL,
  analyst_notes TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS controls (
  id INTEGER PRIMARY KEY,
  control_code TEXT UNIQUE NOT NULL,
  component_code TEXT NOT NULL,
  title TEXT NOT NULL,
  objective TEXT NOT NULL,
  implementation TEXT NOT NULL,
  verification TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS frameworks (
  id INTEGER PRIMARY KEY,
  framework_code TEXT UNIQUE NOT NULL,
  name TEXT NOT NULL,
  source_type TEXT NOT NULL,
  version TEXT NOT NULL,
  notes TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS requirements (
  id INTEGER PRIMARY KEY,
  requirement_code TEXT UNIQUE NOT NULL,
  framework_code TEXT NOT NULL,
  reference TEXT NOT NULL,
  title TEXT NOT NULL,
  summary TEXT NOT NULL,
  applicability TEXT NOT NULL,
  verification_note TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS control_mappings (
  id INTEGER PRIMARY KEY,
  control_code TEXT NOT NULL,
  requirement_code TEXT NOT NULL,
  relationship TEXT NOT NULL,
  confidence TEXT NOT NULL,
  rationale TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS evidence (
  id INTEGER PRIMARY KEY,
  evidence_code TEXT UNIQUE NOT NULL,
  component_code TEXT NOT NULL,
  title TEXT NOT NULL,
  evidence_type TEXT NOT NULL,
  file_name TEXT NOT NULL,
  summary TEXT NOT NULL,
  status TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  collected_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS assessments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  requirement_code TEXT NOT NULL,
  control_code TEXT NOT NULL,
  component_code TEXT NOT NULL,
  evidence_codes TEXT NOT NULL,
  status TEXT NOT NULL,
  rationale TEXT NOT NULL,
  recommendation TEXT NOT NULL,
  assessor TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  assessment_id INTEGER,
  campaign_id INTEGER,
  title TEXT NOT NULL,
  severity TEXT NOT NULL,
  status TEXT NOT NULL,
  recommendation TEXT NOT NULL,
  owner TEXT NOT NULL,
  due_date TEXT NOT NULL,
  residual_risk TEXT NOT NULL,
  created_at TEXT NOT NULL,
  FOREIGN KEY(assessment_id) REFERENCES assessments(id),
  FOREIGN KEY(campaign_id) REFERENCES campaigns(id)
);

CREATE TABLE IF NOT EXISTS campaigns (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  campaign_code TEXT UNIQUE NOT NULL,
  title TEXT NOT NULL,
  objective TEXT NOT NULL,
  vehicle_program TEXT NOT NULL,
  model_year TEXT NOT NULL,
  scope TEXT NOT NULL,
  software_baseline TEXT NOT NULL,
  period_start TEXT NOT NULL,
  period_end TEXT NOT NULL,
  assessor TEXT NOT NULL,
  approver TEXT NOT NULL,
  due_date TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS campaign_components (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  campaign_id INTEGER NOT NULL,
  component_code TEXT NOT NULL,
  software_version TEXT NOT NULL,
  environment TEXT NOT NULL,
  in_scope TEXT NOT NULL,
  notes TEXT NOT NULL,
  FOREIGN KEY(campaign_id) REFERENCES campaigns(id)
);

CREATE TABLE IF NOT EXISTS applicability (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  campaign_id INTEGER NOT NULL,
  requirement_code TEXT NOT NULL,
  component_code TEXT NOT NULL,
  decision TEXT NOT NULL,
  rationale TEXT NOT NULL,
  requirement_owner TEXT NOT NULL,
  review_status TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY(campaign_id) REFERENCES campaigns(id)
);

CREATE TABLE IF NOT EXISTS evidence_requests (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  campaign_id INTEGER NOT NULL,
  request_code TEXT UNIQUE NOT NULL,
  requirement_code TEXT NOT NULL,
  component_code TEXT NOT NULL,
  requested_evidence TEXT NOT NULL,
  evidence_owner TEXT NOT NULL,
  due_date TEXT NOT NULL,
  status TEXT NOT NULL,
  received_evidence_codes TEXT NOT NULL,
  sufficiency_notes TEXT NOT NULL,
  FOREIGN KEY(campaign_id) REFERENCES campaigns(id)
);

CREATE TABLE IF NOT EXISTS control_evaluations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  campaign_id INTEGER NOT NULL,
  requirement_code TEXT NOT NULL,
  control_code TEXT NOT NULL,
  component_code TEXT NOT NULL,
  evidence_codes TEXT NOT NULL,
  design_status TEXT NOT NULL,
  implementation_status TEXT NOT NULL,
  effectiveness_status TEXT NOT NULL,
  overall_status TEXT NOT NULL,
  evidence_relevance INTEGER NOT NULL,
  evidence_authenticity INTEGER NOT NULL,
  evidence_completeness INTEGER NOT NULL,
  evidence_currency INTEGER NOT NULL,
  evidence_scope INTEGER NOT NULL,
  rationale TEXT NOT NULL,
  recommendation TEXT NOT NULL,
  assessor TEXT NOT NULL,
  reviewer TEXT NOT NULL,
  created_at TEXT NOT NULL,
  FOREIGN KEY(campaign_id) REFERENCES campaigns(id)
);

CREATE TABLE IF NOT EXISTS corrective_actions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  finding_id INTEGER NOT NULL,
  action_code TEXT UNIQUE NOT NULL,
  root_cause TEXT NOT NULL,
  action_plan TEXT NOT NULL,
  interim_mitigation TEXT NOT NULL,
  owner TEXT NOT NULL,
  target_date TEXT NOT NULL,
  status TEXT NOT NULL,
  completion_evidence_codes TEXT NOT NULL,
  retest_status TEXT NOT NULL,
  retest_notes TEXT NOT NULL,
  approver TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY(finding_id) REFERENCES findings(id)
);

CREATE TABLE IF NOT EXISTS supplier_assessments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  campaign_id INTEGER NOT NULL,
  supplier_name TEXT NOT NULL,
  component_code TEXT NOT NULL,
  artifact TEXT NOT NULL,
  status TEXT NOT NULL,
  evidence_code TEXT NOT NULL,
  gap TEXT NOT NULL,
  recommendation TEXT NOT NULL,
  owner TEXT NOT NULL,
  FOREIGN KEY(campaign_id) REFERENCES campaigns(id)
);

CREATE TABLE IF NOT EXISTS profile_outcomes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  campaign_id INTEGER NOT NULL,
  outcome_code TEXT NOT NULL,
  framework_code TEXT NOT NULL,
  component_code TEXT NOT NULL,
  title TEXT NOT NULL,
  current_state TEXT NOT NULL,
  target_state TEXT NOT NULL,
  gap_level TEXT NOT NULL,
  action TEXT NOT NULL,
  FOREIGN KEY(campaign_id) REFERENCES campaigns(id)
);

CREATE TABLE IF NOT EXISTS audit_questions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  campaign_id INTEGER NOT NULL,
  category TEXT NOT NULL,
  question TEXT NOT NULL,
  expected_points TEXT NOT NULL,
  difficulty TEXT NOT NULL,
  FOREIGN KEY(campaign_id) REFERENCES campaigns(id)
);

CREATE TABLE IF NOT EXISTS audit_responses (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  question_id INTEGER NOT NULL,
  respondent TEXT NOT NULL,
  response TEXT NOT NULL,
  self_score INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  FOREIGN KEY(question_id) REFERENCES audit_questions(id)
);
