"""Database access layer for the AI Automotive Cybersecurity Incident & Compliance Assistant.

This file keeps SQL/database logic separate from the Streamlit UI. The functions
return pandas DataFrames because Streamlit can display DataFrames directly with
st.dataframe() or custom table rendering.
"""

import sqlite3
from pathlib import Path

import pandas as pd

BASE_DIR = Path(__file__).resolve().parent
DATABASE_PATH = BASE_DIR / "data" / "project.db"


def get_connection() -> sqlite3.Connection:
    """Return a connection to the local SQLite database.

    Expected failure point: this will fail if data/project.db has not been
    created yet. Run `python seed.py` before running this file.
    """
    conn = sqlite3.connect(DATABASE_PATH)
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


# ---------------------------------------------------------------------------
# Assignment 4.1 required database access functions
# ---------------------------------------------------------------------------

def get_all_incidents() -> pd.DataFrame:
    """Return all cybersecurity incident records with basic vehicle context."""
    query = """
        SELECT
            i.incident_id,
            i.title,
            i.attack_vector,
            i.affected_component,
            i.severity,
            i.status,
            i.detected_at,
            v.make,
            v.model,
            v.model_year
        FROM incidents AS i
        JOIN vehicles AS v
            ON i.vehicle_id = v.vehicle_id
        ORDER BY i.detected_at DESC;
    """

    with get_connection() as conn:
        return pd.read_sql_query(query, conn)


def get_incidents_by_severity(severity: str) -> pd.DataFrame:
    """Return incidents that match a selected severity using a parameterized query.

    The ? placeholder prevents user input from being interpreted as executable
    SQL. Do not replace this with an f-string.
    """
    query = """
        SELECT
            incident_id,
            title,
            attack_vector,
            affected_component,
            severity,
            status,
            detected_at
        FROM incidents
        WHERE severity = ?
        ORDER BY detected_at DESC;
    """

    with get_connection() as conn:
        return pd.read_sql_query(query, conn, params=(severity,))


def get_incidents_with_assets() -> pd.DataFrame:
    """Return incident records joined to affected vehicle/platform records."""
    query = """
        SELECT
            i.incident_id,
            i.title,
            i.severity,
            i.status,
            i.affected_component,
            v.vin,
            v.make,
            v.model,
            v.model_year,
            v.ecu_zone,
            v.connectivity_type
        FROM incidents AS i
        JOIN vehicles AS v
            ON i.vehicle_id = v.vehicle_id
        ORDER BY i.incident_id;
    """

    with get_connection() as conn:
        return pd.read_sql_query(query, conn)


def get_incident_counts_by_severity() -> pd.DataFrame:
    """Return an aggregation of incidents grouped by severity."""
    query = """
        SELECT
            i.severity,
            COUNT(*) AS incident_count,
            ROUND(AVG(COALESCE(ra.risk_score, 0)), 2) AS average_risk_score
        FROM incidents AS i
        LEFT JOIN risk_assessments AS ra
            ON i.incident_id = ra.incident_id
        GROUP BY i.severity
        ORDER BY
            CASE i.severity
                WHEN 'Critical' THEN 1
                WHEN 'High' THEN 2
                WHEN 'Medium' THEN 3
                WHEN 'Low' THEN 4
                ELSE 5
            END;
    """

    with get_connection() as conn:
        return pd.read_sql_query(query, conn)


def get_open_mitigations() -> pd.DataFrame:
    """Return open mitigation actions with related incident severity and status."""
    query = """
        SELECT
            m.mitigation_id,
            i.incident_id,
            i.title,
            i.severity,
            i.status AS incident_status,
            m.action_description,
            m.owner,
            m.due_date,
            m.completion_status
        FROM mitigations AS m
        JOIN incidents AS i
            ON m.incident_id = i.incident_id
        WHERE m.completion_status <> 'Completed'
        ORDER BY m.due_date;
    """

    with get_connection() as conn:
        return pd.read_sql_query(query, conn)


def get_incident_evidence_for_ai(incident_id: int) -> pd.DataFrame:
    """Return database evidence that can support the future AI summary feature.

    This function retrieves the selected incident, affected vehicle, linked
    controls, risk assessment, evidence references, and mitigation actions. The
    future AI feature can use this as the grounded case file for summarization.
    """
    query = """
        SELECT
            i.incident_id,
            i.title,
            i.description,
            i.attack_vector,
            i.affected_component,
            i.severity,
            i.status,
            i.detected_at,
            i.resolved_at,
            v.make || ' ' || v.model || ' ' || v.model_year AS vehicle_platform,
            v.ecu_zone,
            v.connectivity_type,
            ra.likelihood,
            ra.impact,
            ra.risk_score,
            ra.tara_notes,
            GROUP_CONCAT(DISTINCT c.framework_name || ' ' || c.clause_reference || ': ' || c.control_name) AS linked_controls,
            GROUP_CONCAT(DISTINCT CASE WHEN ic.compliance_gap_identified = 1 THEN c.control_name || ' - ' || COALESCE(ic.gap_notes, '') END) AS compliance_gaps,
            GROUP_CONCAT(DISTINCT e.evidence_type || ': ' || e.description || ' (' || e.evidence_reference || ')') AS evidence_summary,
            GROUP_CONCAT(DISTINCT m.completion_status || ': ' || m.action_description || ' [Owner: ' || m.owner || ']') AS mitigation_summary
        FROM incidents AS i
        JOIN vehicles AS v
            ON i.vehicle_id = v.vehicle_id
        LEFT JOIN risk_assessments AS ra
            ON i.incident_id = ra.incident_id
        LEFT JOIN incident_controls AS ic
            ON i.incident_id = ic.incident_id
        LEFT JOIN controls AS c
            ON ic.control_id = c.control_id
        LEFT JOIN evidence AS e
            ON i.incident_id = e.incident_id
        LEFT JOIN mitigations AS m
            ON i.incident_id = m.incident_id
        WHERE i.incident_id = ?
        GROUP BY
            i.incident_id,
            i.title,
            i.description,
            i.attack_vector,
            i.affected_component,
            i.severity,
            i.status,
            i.detected_at,
            i.resolved_at,
            v.make,
            v.model,
            v.model_year,
            v.ecu_zone,
            v.connectivity_type,
            ra.likelihood,
            ra.impact,
            ra.risk_score,
            ra.tara_notes;
    """

    with get_connection() as conn:
        return pd.read_sql_query(query, conn, params=(incident_id,))


# ---------------------------------------------------------------------------
# Streamlit dashboard support functions
# ---------------------------------------------------------------------------

def get_incident_overview() -> pd.DataFrame:
    """Return dashboard incident rows with affected vehicle and generated risk score."""
    query = """
        SELECT
            i.incident_id,
            i.title,
            i.severity,
            i.status,
            i.attack_vector,
            i.affected_component,
            v.make || ' ' || v.model || ' (' || v.model_year || ')' AS vehicle,
            ra.risk_score,
            i.detected_at
        FROM incidents AS i
        JOIN vehicles AS v
            ON i.vehicle_id = v.vehicle_id
        LEFT JOIN risk_assessments AS ra
            ON i.incident_id = ra.incident_id
        ORDER BY i.detected_at DESC;
    """

    with get_connection() as conn:
        return pd.read_sql_query(query, conn)


def get_control_summary() -> pd.DataFrame:
    """Return how often each compliance/security control is mapped to incidents."""
    query = """
        SELECT
            c.framework_name,
            c.clause_reference,
            c.control_name,
            COUNT(ic.incident_id) AS mapped_incident_count
        FROM controls AS c
        LEFT JOIN incident_controls AS ic
            ON c.control_id = ic.control_id
        GROUP BY
            c.control_id,
            c.framework_name,
            c.clause_reference,
            c.control_name
        ORDER BY mapped_incident_count DESC, c.framework_name, c.clause_reference;
    """

    with get_connection() as conn:
        return pd.read_sql_query(query, conn)


def get_kpi_summary() -> dict:
    """Return high-level dashboard metrics for the Streamlit interface."""
    query_map = {
        "total_incidents": "SELECT COUNT(*) FROM incidents;",
        "critical_incidents": "SELECT COUNT(*) FROM incidents WHERE severity = 'Critical';",
        "open_mitigations": "SELECT COUNT(*) FROM mitigations WHERE completion_status <> 'Completed';",
        "mapped_controls": "SELECT COUNT(*) FROM incident_controls;",
    }

    with get_connection() as conn:
        return {
            name: conn.execute(query).fetchone()[0]
            for name, query in query_map.items()
        }


def get_ai_context_for_incident(incident_id: int) -> dict:
    """Return database-backed context that a future AI feature can summarize.

    The selected incident is retrieved using a parameterized query. Related
    records are split into separate DataFrames so the interface can display
    incident, control, evidence, and mitigation information cleanly.
    """
    with get_connection() as conn:
        incident = pd.read_sql_query(
            """
            SELECT
                i.*,
                v.make,
                v.model,
                v.model_year,
                v.ecu_zone,
                v.connectivity_type,
                ra.likelihood,
                ra.impact,
                ra.risk_score,
                ra.tara_notes,
                ra.assessed_at
            FROM incidents AS i
            JOIN vehicles AS v
                ON i.vehicle_id = v.vehicle_id
            LEFT JOIN risk_assessments AS ra
                ON i.incident_id = ra.incident_id
            WHERE i.incident_id = ?;
            """,
            conn,
            params=(incident_id,),
        )

        controls = pd.read_sql_query(
            """
            SELECT
                c.framework_name,
                c.clause_reference,
                c.control_name,
                c.control_type,
                ic.compliance_gap_identified,
                ic.gap_notes
            FROM incident_controls AS ic
            JOIN controls AS c
                ON ic.control_id = c.control_id
            WHERE ic.incident_id = ?
            ORDER BY c.framework_name, c.clause_reference;
            """,
            conn,
            params=(incident_id,),
        )

        evidence = pd.read_sql_query(
            """
            SELECT
                evidence_type,
                evidence_reference,
                description,
                collected_at
            FROM evidence
            WHERE incident_id = ?
            ORDER BY collected_at;
            """,
            conn,
            params=(incident_id,),
        )

        mitigation_actions = pd.read_sql_query(
            """
            SELECT
                action_description,
                owner,
                due_date,
                completion_status
            FROM mitigations
            WHERE incident_id = ?
            ORDER BY due_date;
            """,
            conn,
            params=(incident_id,),
        )

    return {
        "incident": incident,
        "controls": controls,
        "evidence": evidence,
        "mitigation_actions": mitigation_actions,
    }


def _print_section(title: str, dataframe: pd.DataFrame) -> None:
    """Print a readable test section for command-line verification."""
    print(f"\n=== {title} ===")
    if dataframe.empty:
        print("No rows returned.")
    else:
        print(dataframe.to_string(index=False))


if __name__ == "__main__":
    print("Testing MS587 database access functions...")
    print(f"Database path: {DATABASE_PATH}")

    try:
        _print_section("All incidents", get_all_incidents())
        _print_section("High severity incidents - parameterized query", get_incidents_by_severity("High"))
        _print_section("Incidents with vehicle assets - JOIN query", get_incidents_with_assets())
        _print_section("Incident counts by severity - GROUP BY query", get_incident_counts_by_severity())
        _print_section("Open mitigations", get_open_mitigations())
        _print_section("Incident 3 evidence for future AI feature", get_incident_evidence_for_ai(3))
    except sqlite3.Error as error:
        print("Database error occurred. Confirm that you ran `python seed.py` first.")
        print(error)
