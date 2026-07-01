# Data Model

The v2 schema separates technical traceability from assessment governance.

## Technical traceability

`components → assets → threats → tara_records → controls → control_mappings → requirements → evidence`

## Assessment governance

`campaigns → campaign_components → applicability → evidence_requests → control_evaluations → findings → corrective_actions`

## Program-level views

- `profile_outcomes` stores Current and Target Profile gaps.
- `supplier_assessments` stores supplier artifact reviews.
- `audit_questions` and `audit_responses` support audit-defense practice.

Evidence files are hashed at application startup. The SQLite database stores the current assessment state locally.
