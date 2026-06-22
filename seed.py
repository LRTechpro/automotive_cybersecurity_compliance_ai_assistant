"""Build and seed the MS587 automotive cybersecurity incident database."""

import sqlite3
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DATABASE_PATH = BASE_DIR / "data" / "project.db"
SCHEMA_PATH = BASE_DIR / "schema.sql"


def initialize_database() -> None:
    """Create the SQLite database from schema.sql and insert realistic seed data."""
    DATABASE_PATH.parent.mkdir(exist_ok=True)

    with sqlite3.connect(DATABASE_PATH) as conn:
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))

        conn.executemany(
            """
            INSERT INTO vehicles
                (vehicle_id, vin, make, model, model_year, ecu_zone, connectivity_type)
            VALUES (?, ?, ?, ?, ?, ?, ?);
            """,
            [
                (1, "1FTFW3L86RFB85841", "Ford", "F-150", 2024, "Gateway", "Cellular OTA / CAN"),
                (2, "1FMHK7FH3RGA20002", "Ford", "Explorer", 2024, "ADAS", "Cellular OTA / CAN"),
                (3, "3FMTK4RE4RPA30003", "Ford", "Mustang Mach-E", 2024, "Telematics", "Cellular OTA / Wi-Fi"),
                (4, "1FMCU4G68RUA40004", "Ford", "Escape", 2024, "Infotainment", "Bluetooth / Wi-Fi / CAN"),
            ],
        )

        conn.executemany(
            """
            INSERT INTO incidents
                (incident_id, vehicle_id, title, description, attack_vector,
                 affected_component, severity, status, detected_at, resolved_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """,
            [
                (
                    1,
                    1,
                    "Gateway rejected OTA package after signature validation warning",
                    "FDRS/GIVIS review showed a failed programming attempt where the gateway rejected an OTA software package after a signature validation warning and repeated authorization retries.",
                    "Remote",
                    "Gateway Module",
                    "High",
                    "Mitigating",
                    "2026-05-18",
                    None,
                ),
                (
                    2,
                    2,
                    "Ford Explorer ADAS calibration log showed inconsistent radar module identity response",
                    "During post-repair calibration on a Ford Explorer, the front radar module returned inconsistent DID values across multiple Ford ADAS diagnostic scan sessions, creating concern for module mismatch or corrupted configuration data.",
                    "Physical",
                    "Front Radar Module",
                    "Medium",
                    "Under Review",
                    "2026-05-22",
                    None,
                ),
                (
                    3,
                    3,
                    "Ford Mustang Mach-E telematics unit generated abnormal authentication failures",
                    "The Ford Mustang Mach-E telematics control unit produced repeated authentication failures from a Ford Connected Vehicle Services endpoint during a scheduled connectivity test window.",
                    "Remote",
                    "Telematics Control Unit",
                    "Critical",
                    "Open",
                    "2026-05-25",
                    None,
                ),
                (
                    4,
                    4,
                    "Ford Escape SYNC infotainment Bluetooth service exposed outdated pairing configuration",
                    "A review of Ford Escape SYNC infotainment configuration data found outdated Bluetooth pairing settings that could increase risk of unauthorized local access.",
                    "Physical",
                    "Infotainment System",
                    "Low",
                    "Resolved",
                    "2026-05-12",
                    "2026-05-19",
                ),
            ],
        )

        conn.executemany(
            """
            INSERT INTO controls
                (control_id, framework_name, clause_reference, control_name, control_type, control_description)
            VALUES (?, ?, ?, ?, ?, ?);
            """,
            [
                (1, "ISO/SAE 21434", "9.4", "Cybersecurity verification", "Detective", "Verify that cybersecurity requirements and controls are implemented and functioning."),
                (2, "UNECE R155", "7.2.2.2", "Vehicle cyber risk management", "Preventive", "Manage vehicle cyber risks across the lifecycle through a cybersecurity management system."),
                (3, "UNECE R156", "7.1.1", "Software update authenticity", "Preventive", "Ensure software updates are authenticated and protected before installation."),
                (4, "NIST CSF", "DE.CM", "Security continuous monitoring", "Detective", "Monitor systems and assets to identify cybersecurity events."),
                (5, "ISO/SAE 21434", "15.4", "Post-development monitoring", "Corrective", "Monitor cybersecurity events and vulnerabilities after release and respond appropriately."),
            ],
        )

        conn.executemany(
            """
            INSERT INTO incident_controls
                (incident_id, control_id, compliance_gap_identified, gap_notes)
            VALUES (?, ?, ?, ?);
            """,
            [
                (1, 3, 1, "OTA authenticity control triggered, but retry behavior needs review."),
                (1, 4, 0, "Monitoring captured the warning and authorization retries."),
                (2, 1, 1, "Verification process needs clearer handling for DID mismatch cases."),
                (3, 2, 1, "Remote endpoint authentication risk requires CSMS escalation."),
                (3, 4, 0, "Monitoring detected abnormal authentication activity."),
                (3, 5, 1, "Post-release response workflow is open and not yet completed."),
                (4, 1, 0, "Configuration review confirmed the pairing setting issue."),
            ],
        )

        conn.executemany(
            """
            INSERT INTO risk_assessments
                (incident_id, likelihood, impact, tara_notes, assessed_at)
            VALUES (?, ?, ?, ?, ?);
            """,
            [
                (1, 4, 4, "Remote OTA path plus repeated retries creates elevated likelihood and high operational impact if exploited.", "2026-05-19"),
                (2, 3, 3, "Physical access and service-process context limit exposure, but ADAS safety impact remains meaningful.", "2026-05-23"),
                (3, 5, 5, "Remote telematics authentication failures affect externally reachable connectivity and require urgent containment.", "2026-05-26"),
                (4, 2, 2, "Local proximity is required and remediation is straightforward; impact is limited to infotainment access exposure.", "2026-05-13"),
            ],
        )

        conn.executemany(
            """
            INSERT INTO evidence
                (incident_id, evidence_type, evidence_reference, description, collected_at)
            VALUES (?, ?, ?, ?, ?);
            """,
            [
                (1, "Log File", "evidence/gateway_ota_auth_retry.log", "Gateway OTA session log showing signature warning and retry sequence.", "2026-05-18"),
                (1, "Analysis Report", "reports/incident_001_gateway_ota_summary.md", "Analyst notes summarizing OTA failure pattern and control mapping.", "2026-05-19"),
                (2, "Scan Report", "scans/front_radar_did_compare.pdf", "Comparison of DID responses across calibration scan sessions.", "2026-05-22"),
                (3, "Packet Capture", "pcaps/tcu_auth_failures.pcapng", "Packet capture showing repeated remote authentication failures.", "2026-05-25"),
                (3, "Log File", "evidence/tcu_service_auth_errors.log", "TCU application log containing abnormal authentication errors.", "2026-05-25"),
                (4, "Screenshot", "screenshots/bluetooth_pairing_config.png", "Screenshot of outdated Bluetooth pairing configuration.", "2026-05-12"),
            ],
        )

        conn.executemany(
            """
            INSERT INTO mitigations
                (incident_id, action_description, owner, due_date, completion_status)
            VALUES (?, ?, ?, ?, ?);
            """,
            [
                (1, "Review OTA authorization retry logic and confirm package signing validation path.", "Gateway Security Team", "2026-06-10", "In Progress"),
                (2, "Validate radar module part number and configuration lineage before releasing calibration.", "ADAS Diagnostics Team", "2026-06-08", "Not Started"),
                (3, "Disable affected remote endpoint pending authentication review and rotate service credentials.", "Connected Vehicle SOC", "2026-06-03", "Blocked"),
                (3, "Open CSMS escalation record for telematics authentication event.", "Compliance Reviewer", "2026-06-07", "In Progress"),
                (4, "Clear outdated Bluetooth pairings and update infotainment configuration checklist.", "Infotainment Service Team", "2026-05-18", "Completed"),
            ],
        )


        conn.executemany(
            """
            INSERT INTO vehicles
                (vehicle_id, vin, make, model, model_year, ecu_zone, connectivity_type)
            VALUES (?, ?, ?, ?, ?, ?, ?);
            """,
            [
                (5, "1FMDE5BH0RLA10005", "Ford", "Bronco Sport", 2024, "Powertrain", "CAN-only"),
                (6, "1FTER4FH0RLE10006", "Ford", "Ranger", 2024, "Gateway", "OTA-capable / CAN"),
            ],
        )

        conn.executemany(
            """
            INSERT INTO incidents
                (incident_id, vehicle_id, title, description, attack_vector,
                 affected_component, severity, status, detected_at, resolved_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """,
            [
                (
                    5,
                    5,
                    "Ford CAN bus diagnostic flooding",
                    "Ford powertrain network logs show repeated diagnostic requests that increased bus utilization and delayed normal responses.",
                    "Physical",
                    "Powertrain CAN",
                    "High",
                    "Mitigating",
                    "2026-05-11 13:25:00",
                    None,
                ),
                (
                    6,
                    6,
                    "Gateway configuration drift after service update",
                    "Gateway configuration comparison showed unexpected drift after a service software update, requiring validation against approved release baselines.",
                    "Supply Chain",
                    "Gateway Module",
                    "Low",
                    "Closed",
                    "2026-05-13 10:10:00",
                    "2026-05-17 09:00:00",
                ),
            ],
        )

        conn.executemany(
            """
            INSERT INTO risk_assessments
                (incident_id, likelihood, impact, tara_notes, assessed_at)
            VALUES (?, ?, ?, ?, ?);
            """,
            [
                (5, 4, 4, "Diagnostic flooding can disrupt normal powertrain communication and requires access-control review.", "2026-05-12"),
                (6, 2, 2, "Configuration drift appears contained and closed after baseline comparison, but repeat monitoring is recommended.", "2026-05-14"),
            ],
        )

        conn.executemany(
            """
            INSERT INTO incident_controls
                (incident_id, control_id, compliance_gap_identified, gap_notes)
            VALUES (?, ?, ?, ?);
            """,
            [
                (5, 3, 1, "CAN flooding requires monitoring for unauthorized diagnostic behavior."),
                (5, 5, 1, "Containment actions are required to reduce operational impact."),
                (6, 2, 0, "Configuration drift maps to threat and risk management review."),
            ],
        )

        conn.executemany(
            """
            INSERT INTO evidence
                (incident_id, evidence_type, evidence_reference, description, collected_at)
            VALUES (?, ?, ?, ?, ?);
            """,
            [
                (5, "Log File", "evidence/can_bus_flooding.log", "CAN trace shows repeated diagnostic requests increasing bus utilization.", "2026-05-11 13:40:00"),
                (6, "Analysis Report", "reports/gateway_config_drift_review.md", "Configuration baseline comparison after service update.", "2026-05-14 09:30:00"),
            ],
        )

        conn.executemany(
            """
            INSERT INTO mitigations
                (incident_id, action_description, owner, due_date, completion_status)
            VALUES (?, ?, ?, ?, ?);
            """,
            [
                (5, "Validate diagnostic tool authorization and reduce unnecessary request frequency.", "Vehicle Diagnostics Team", "2026-05-20", "In Progress"),
                (6, "Document approved gateway configuration baseline and close review ticket.", "Gateway Release Team", "2026-05-17", "Completed"),
            ],
        )

        conn.commit()


if __name__ == "__main__":
    initialize_database()
    print(f"Database created at: {DATABASE_PATH}")
