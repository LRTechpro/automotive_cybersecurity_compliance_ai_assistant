# Query Portfolio Reference

This file summarizes the SQL query types implemented in `db.py`.

## Basic Retrieval

Function: `get_all_incidents()`

Purpose: Retrieves cybersecurity incidents with basic vehicle context.

## Parameterized Query

Function: `get_incidents_by_severity(severity)`

Purpose: Safely filters incidents based on a user-selected severity value.

Why it matters: the query uses a `?` placeholder and `params=(severity,)` instead of unsafe string formatting.

## JOIN Query

Function: `get_incidents_with_assets()`

Purpose: Joins incidents to vehicles so the analyst can see VIN, make, model, model year, ECU zone, and connectivity type.

## GROUP BY / Aggregation Query

Function: `get_incident_counts_by_severity()`

Purpose: Counts incidents by severity and calculates the average generated risk score.

## AI-Support Query

Function: `get_incident_evidence_for_ai(incident_id)`

Purpose: Retrieves incident details, vehicle context, controls, compliance gaps, evidence, risk data, and mitigations for a future AI summary feature.

## Dashboard Query

Function: `get_ai_context_for_incident(incident_id)`

Purpose: Retrieves the selected incident plus separate related tables for mapped controls, evidence items, and mitigation actions. This allows the Streamlit interface to display a full database-backed incident case file.
