# Database Access Notes

## Question 1: Which database access functions did you create, and what does each function do?

I created a reusable database access layer in `db.py`.

Core database access functions:

- `get_connection()` opens a connection to the local SQLite database and enables foreign key enforcement.
- `get_all_incidents()` retrieves all incident records with basic vehicle context.
- `get_incidents_by_severity(severity)` filters incidents by severity using a safe parameterized query.
- `get_incidents_with_assets()` joins cybersecurity incidents to the affected vehicle asset records.
- `get_incident_counts_by_severity()` summarizes incident counts and average generated risk scores by severity.
- `get_open_mitigations()` returns mitigation actions that are not completed.
- `get_incident_evidence_for_ai(incident_id)` retrieves a database-backed evidence package for a selected incident.

I also added Streamlit dashboard support functions:

- `get_incident_overview()` returns incident rows for the front-end incident table.
- `get_control_summary()` summarizes compliance/security-control mappings.
- `get_kpi_summary()` returns dashboard metrics such as total incidents, critical incidents, open mitigations, and mapped controls.
- `get_ai_context_for_incident(incident_id)` returns incident, control, evidence, and mitigation DataFrames for the selected incident in the dashboard.

## Question 2: Which function uses a parameterized query? Why is that important?

`get_incidents_by_severity(severity)` uses a parameterized query with a `?` placeholder and `params=(severity,)`.

`get_incident_evidence_for_ai(incident_id)` and `get_ai_context_for_incident(incident_id)` also use parameterized queries.

This matters because user-provided values should be treated as data, not executable SQL. Parameterized queries reduce SQL injection risk and make the future Streamlit interface safer.

## Question 3: Which function uses a JOIN? What relationship does it rely on?

`get_incidents_with_assets()` uses a JOIN between `incidents` and `vehicles`. It relies on the foreign key relationship where `incidents.vehicle_id` references `vehicles.vehicle_id`.

This relationship allows the application to show which vehicle platform, VIN, ECU zone, and connectivity type are connected to each cybersecurity incident.

## Question 4: Which function supports your future AI feature? What database evidence does it retrieve?

`get_incident_evidence_for_ai(incident_id)` supports the future AI feature. It retrieves the selected incident, vehicle context, ECU zone, connectivity type, risk likelihood, impact, generated risk score, TARA notes, linked controls, compliance gaps, evidence references, and mitigation summaries.

The Streamlit dashboard also uses `get_ai_context_for_incident(incident_id)` to retrieve the same kind of grounded case file, split into separate tables for display.

## Question 5: What problems did you encounter while connecting Python to the database, if any?

The main issue was making sure the database path worked from the project folder and did not depend on an absolute path from one computer. I addressed that by using `Path(__file__).resolve().parent` and building the database path relative to the project folder.

Another issue was avoiding unnecessary dependency problems. The project only needs `pandas` for the backend test and `streamlit` for the dashboard preview, so the requirements file was simplified to avoid package build errors from unrelated libraries.
