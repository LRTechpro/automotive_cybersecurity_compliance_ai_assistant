PRAGMA foreign_keys = ON;

DROP TABLE IF EXISTS mitigations;
DROP TABLE IF EXISTS evidence;
DROP TABLE IF EXISTS risk_assessments;
DROP TABLE IF EXISTS incident_controls;
DROP TABLE IF EXISTS controls;
DROP TABLE IF EXISTS incidents;
DROP TABLE IF EXISTS vehicles;

CREATE TABLE vehicles (
    vehicle_id INTEGER PRIMARY KEY AUTOINCREMENT,
    vin TEXT UNIQUE,
    make TEXT NOT NULL,
    model TEXT NOT NULL,
    model_year INTEGER NOT NULL CHECK (model_year BETWEEN 1996 AND 2100),
    ecu_zone TEXT CHECK (ecu_zone IN ('ADAS', 'Telematics', 'Gateway', 'Powertrain', 'Body', 'Infotainment')),
    connectivity_type TEXT NOT NULL
);

CREATE TABLE incidents (
    incident_id INTEGER PRIMARY KEY AUTOINCREMENT,
    vehicle_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    attack_vector TEXT NOT NULL CHECK (attack_vector IN ('Remote', 'Physical', 'Supply Chain', 'Insider', 'Unknown')),
    affected_component TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('Low', 'Medium', 'High', 'Critical')),
    status TEXT NOT NULL CHECK (status IN ('New', 'Under Review', 'Open', 'Mitigating', 'Resolved', 'Closed')),
    detected_at TEXT NOT NULL,
    resolved_at TEXT,
    FOREIGN KEY (vehicle_id) REFERENCES vehicles(vehicle_id) ON DELETE CASCADE
);

CREATE TABLE controls (
    control_id INTEGER PRIMARY KEY AUTOINCREMENT,
    framework_name TEXT NOT NULL,
    clause_reference TEXT NOT NULL,
    control_name TEXT NOT NULL,
    control_type TEXT NOT NULL CHECK (control_type IN ('Preventive', 'Detective', 'Corrective')),
    control_description TEXT NOT NULL,
    UNIQUE (framework_name, clause_reference)
);

CREATE TABLE incident_controls (
    incident_control_id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER NOT NULL,
    control_id INTEGER NOT NULL,
    compliance_gap_identified INTEGER NOT NULL DEFAULT 0 CHECK (compliance_gap_identified IN (0, 1)),
    gap_notes TEXT,
    FOREIGN KEY (incident_id) REFERENCES incidents(incident_id) ON DELETE CASCADE,
    FOREIGN KEY (control_id) REFERENCES controls(control_id) ON DELETE CASCADE,
    UNIQUE (incident_id, control_id)
);

CREATE TABLE risk_assessments (
    risk_assessment_id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER NOT NULL,
    likelihood INTEGER NOT NULL CHECK (likelihood BETWEEN 1 AND 5),
    impact INTEGER NOT NULL CHECK (impact BETWEEN 1 AND 5),
    risk_score INTEGER GENERATED ALWAYS AS (likelihood * impact) STORED,
    tara_notes TEXT NOT NULL,
    assessed_at TEXT NOT NULL,
    FOREIGN KEY (incident_id) REFERENCES incidents(incident_id) ON DELETE CASCADE
);

CREATE TABLE evidence (
    evidence_id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER NOT NULL,
    evidence_type TEXT NOT NULL CHECK (evidence_type IN ('Log File', 'Packet Capture', 'Scan Report', 'Analysis Report', 'Screenshot', 'Other')),
    evidence_reference TEXT NOT NULL,
    description TEXT NOT NULL,
    collected_at TEXT NOT NULL,
    FOREIGN KEY (incident_id) REFERENCES incidents(incident_id) ON DELETE CASCADE
);

CREATE TABLE mitigations (
    mitigation_id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER NOT NULL,
    action_description TEXT NOT NULL,
    owner TEXT NOT NULL,
    due_date TEXT,
    completion_status TEXT NOT NULL CHECK (completion_status IN ('Not Started', 'In Progress', 'Completed', 'Blocked')),
    FOREIGN KEY (incident_id) REFERENCES incidents(incident_id) ON DELETE CASCADE
);
