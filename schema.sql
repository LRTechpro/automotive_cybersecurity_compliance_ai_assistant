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

-- Version 3: continuous cybersecurity assurance
CREATE TABLE IF NOT EXISTS software_releases (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  release_code TEXT UNIQUE NOT NULL,
  component_code TEXT NOT NULL,
  version TEXT NOT NULL,
  baseline_code TEXT NOT NULL,
  release_date TEXT NOT NULL,
  supplier TEXT NOT NULL,
  status TEXT NOT NULL,
  notes TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS release_changes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  release_code TEXT NOT NULL,
  change_code TEXT UNIQUE NOT NULL,
  change_type TEXT NOT NULL,
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  affected_interfaces TEXT NOT NULL,
  affected_controls TEXT NOT NULL,
  affected_tara TEXT NOT NULL,
  affected_requirements TEXT NOT NULL,
  cybersecurity_impact TEXT NOT NULL,
  requires_retest TEXT NOT NULL,
  FOREIGN KEY(release_code) REFERENCES software_releases(release_code)
);

CREATE TABLE IF NOT EXISTS evidence_lifecycle (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  evidence_code TEXT NOT NULL,
  release_code TEXT NOT NULL,
  component_code TEXT NOT NULL,
  valid_for_version TEXT NOT NULL,
  review_due TEXT NOT NULL,
  status TEXT NOT NULL,
  stale_reason TEXT NOT NULL,
  superseded_by TEXT NOT NULL,
  required_for_gate TEXT NOT NULL,
  FOREIGN KEY(release_code) REFERENCES software_releases(release_code)
);

CREATE TABLE IF NOT EXISTS vulnerabilities (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  vuln_code TEXT UNIQUE NOT NULL,
  release_code TEXT NOT NULL,
  component_code TEXT NOT NULL,
  affected_component TEXT NOT NULL,
  affected_versions TEXT NOT NULL,
  severity TEXT NOT NULL,
  cvss REAL NOT NULL,
  reachability TEXT NOT NULL,
  exploitability TEXT NOT NULL,
  status TEXT NOT NULL,
  linked_tara TEXT NOT NULL,
  linked_control TEXT NOT NULL,
  remediation TEXT NOT NULL,
  due_date TEXT NOT NULL,
  FOREIGN KEY(release_code) REFERENCES software_releases(release_code)
);

CREATE TABLE IF NOT EXISTS sbom_components (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  release_code TEXT NOT NULL,
  component_name TEXT NOT NULL,
  version TEXT NOT NULL,
  supplier TEXT NOT NULL,
  purl TEXT NOT NULL,
  license TEXT NOT NULL,
  known_vulnerability TEXT NOT NULL,
  status TEXT NOT NULL,
  FOREIGN KEY(release_code) REFERENCES software_releases(release_code)
);

CREATE TABLE IF NOT EXISTS change_impacts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  release_code TEXT NOT NULL,
  source_change_code TEXT NOT NULL,
  impact_type TEXT NOT NULL,
  target_code TEXT NOT NULL,
  target_title TEXT NOT NULL,
  impact_reason TEXT NOT NULL,
  action TEXT NOT NULL,
  status TEXT NOT NULL,
  UNIQUE(release_code, source_change_code, impact_type, target_code),
  FOREIGN KEY(release_code) REFERENCES software_releases(release_code)
);

CREATE TABLE IF NOT EXISTS detection_rules (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  rule_code TEXT UNIQUE NOT NULL,
  title TEXT NOT NULL,
  component_code TEXT NOT NULL,
  behavior TEXT NOT NULL,
  telemetry_sources TEXT NOT NULL,
  logic_summary TEXT NOT NULL,
  severity TEXT NOT NULL,
  validation_status TEXT NOT NULL,
  last_tested TEXT NOT NULL,
  linked_tara TEXT NOT NULL,
  response_playbook TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cybersecurity_claims (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  claim_code TEXT UNIQUE NOT NULL,
  parent_claim_code TEXT NOT NULL,
  title TEXT NOT NULL,
  claim_type TEXT NOT NULL,
  statement TEXT NOT NULL,
  status TEXT NOT NULL,
  owner TEXT NOT NULL,
  rationale TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS claim_evidence (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  claim_code TEXT NOT NULL,
  evidence_code TEXT NOT NULL,
  support_type TEXT NOT NULL,
  notes TEXT NOT NULL,
  UNIQUE(claim_code, evidence_code),
  FOREIGN KEY(claim_code) REFERENCES cybersecurity_claims(claim_code)
);

CREATE TABLE IF NOT EXISTS release_gates (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  release_code TEXT NOT NULL,
  decision TEXT NOT NULL,
  decision_status TEXT NOT NULL,
  blockers TEXT NOT NULL,
  conditions TEXT NOT NULL,
  residual_risk TEXT NOT NULL,
  approver TEXT NOT NULL,
  approved_at TEXT NOT NULL,
  notes TEXT NOT NULL,
  created_at TEXT NOT NULL,
  FOREIGN KEY(release_code) REFERENCES software_releases(release_code)
);

CREATE TABLE IF NOT EXISTS ingested_artifacts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  artifact_code TEXT UNIQUE NOT NULL,
  artifact_type TEXT NOT NULL,
  component_code TEXT NOT NULL,
  release_code TEXT NOT NULL,
  file_name TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  parsed_summary TEXT NOT NULL,
  analyst_status TEXT NOT NULL,
  created_at TEXT NOT NULL,
  FOREIGN KEY(release_code) REFERENCES software_releases(release_code)
);
