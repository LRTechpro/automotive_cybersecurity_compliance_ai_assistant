from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
DB_PATH = ROOT / "data" / "autocyber.db"
SCHEMA_PATH = ROOT / "schema.sql"
SEED_PATH = ROOT / "seed_data.json"
EVIDENCE_DIR = ROOT / "data" / "evidence"

BASE_TABLES = [
    "components", "interfaces", "assets", "threats", "tara_records", "controls",
    "frameworks", "requirements", "control_mappings", "evidence",
]
SEED_TABLES = BASE_TABLES + [
    "campaigns", "campaign_components", "applicability", "evidence_requests",
    "control_evaluations", "supplier_assessments", "profile_outcomes", "audit_questions",
]


def connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _insert_many(conn: sqlite3.Connection, table: str, records: list[dict[str, Any]]) -> None:
    if not records:
        return
    columns = list(records[0].keys())
    placeholders = ",".join("?" for _ in columns)
    sql = f"INSERT OR REPLACE INTO {table} ({','.join(columns)}) VALUES ({placeholders})"
    conn.executemany(sql, [tuple(record.get(col) for col in columns) for record in records])


def initialize_database(reset: bool = False) -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    if reset and DB_PATH.exists():
        DB_PATH.unlink()

    new_db = not DB_PATH.exists()
    with connection() as conn:
        conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
        if new_db or conn.execute("SELECT COUNT(*) FROM components").fetchone()[0] == 0:
            seed = json.loads(SEED_PATH.read_text(encoding="utf-8"))
            for table in SEED_TABLES:
                _insert_many(conn, table, seed.get(table, []))
            _insert_many(conn, "assessments", seed.get("assessments", []))
            _insert_many(conn, "findings", seed.get("findings", []))
            _insert_many(conn, "corrective_actions", seed.get("corrective_actions", []))

        for item in conn.execute("SELECT evidence_code, file_name FROM evidence").fetchall():
            path = EVIDENCE_DIR / item["file_name"]
            if path.exists():
                conn.execute(
                    "UPDATE evidence SET sha256=? WHERE evidence_code=?",
                    (_hash_file(path), item["evidence_code"]),
                )
        conn.commit()


def rows(query: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
    with connection() as conn:
        return [dict(item) for item in conn.execute(query, params).fetchall()]


def row(query: str, params: tuple[Any, ...] = ()) -> dict[str, Any] | None:
    with connection() as conn:
        item = conn.execute(query, params).fetchone()
        return dict(item) if item else None


def execute(query: str, params: tuple[Any, ...]) -> int:
    with connection() as conn:
        cur = conn.execute(query, params)
        conn.commit()
        return int(cur.lastrowid)


def update(query: str, params: tuple[Any, ...]) -> int:
    with connection() as conn:
        cur = conn.execute(query, params)
        conn.commit()
        return int(cur.rowcount)


def metrics(campaign_id: int = 1) -> dict[str, Any]:
    with connection() as conn:
        applicable = conn.execute(
            "SELECT COUNT(*) FROM applicability WHERE campaign_id=? AND decision LIKE 'Applicable%'",
            (campaign_id,),
        ).fetchone()[0]
        evaluations = conn.execute(
            "SELECT COUNT(*) FROM control_evaluations WHERE campaign_id=?", (campaign_id,)
        ).fetchone()[0]
        return {
            "in_scope_components": conn.execute(
                "SELECT COUNT(*) FROM components WHERE scope_status='in_scope'"
            ).fetchone()[0],
            "tara_records": conn.execute("SELECT COUNT(*) FROM tara_records").fetchone()[0],
            "framework_sources": conn.execute("SELECT COUNT(*) FROM frameworks").fetchone()[0],
            "control_mappings": conn.execute("SELECT COUNT(*) FROM control_mappings").fetchone()[0],
            "evidence_objects": conn.execute("SELECT COUNT(*) FROM evidence").fetchone()[0],
            "open_findings": conn.execute(
                "SELECT COUNT(*) FROM findings WHERE status NOT IN ('Closed','Accepted')"
            ).fetchone()[0],
            "applicable_requirements": applicable,
            "control_evaluations": evaluations,
            "campaigns": conn.execute("SELECT COUNT(*) FROM campaigns").fetchone()[0],
            "open_actions": conn.execute(
                "SELECT COUNT(*) FROM corrective_actions WHERE status NOT IN ('Closed','Verified')"
            ).fetchone()[0],
        }


def bootstrap(campaign_id: int = 1) -> dict[str, Any]:
    return {
        "components": rows("SELECT * FROM components ORDER BY id"),
        "interfaces": rows("SELECT * FROM interfaces ORDER BY id"),
        "assets": rows("SELECT * FROM assets ORDER BY id"),
        "threats": rows("SELECT * FROM threats ORDER BY id"),
        "tara": rows("SELECT * FROM tara_records ORDER BY id"),
        "controls": rows("SELECT * FROM controls ORDER BY id"),
        "frameworks": rows("SELECT * FROM frameworks ORDER BY id"),
        "requirements": rows("SELECT * FROM requirements ORDER BY id"),
        "mappings": crosswalk(),
        "evidence": rows("SELECT * FROM evidence ORDER BY id"),
        "assessments": rows("SELECT * FROM assessments ORDER BY id DESC"),
        "findings": rows("SELECT * FROM findings ORDER BY id DESC"),
        "campaigns": rows("SELECT * FROM campaigns ORDER BY id DESC"),
        "campaign_components": rows(
            "SELECT * FROM campaign_components WHERE campaign_id=? ORDER BY id", (campaign_id,)
        ),
        "applicability": applicability(campaign_id),
        "evidence_requests": rows(
            "SELECT * FROM evidence_requests WHERE campaign_id=? ORDER BY id", (campaign_id,)
        ),
        "control_evaluations": rows(
            "SELECT * FROM control_evaluations WHERE campaign_id=? ORDER BY id DESC", (campaign_id,)
        ),
        "corrective_actions": corrective_actions(),
        "supplier_assessments": rows(
            "SELECT * FROM supplier_assessments WHERE campaign_id=? ORDER BY id", (campaign_id,)
        ),
        "profile_outcomes": rows(
            "SELECT * FROM profile_outcomes WHERE campaign_id=? ORDER BY id", (campaign_id,)
        ),
        "audit_questions": rows(
            "SELECT * FROM audit_questions WHERE campaign_id=? ORDER BY id", (campaign_id,)
        ),
        "metrics": metrics(campaign_id),
    }


def traceability(component_code: str | None = None) -> list[dict[str, Any]]:
    query = """
    SELECT tr.tara_code, tr.component_code, a.name AS asset, t.title AS threat,
           t.stride_categories, t.mitre_techniques, tr.damage_scenario, tr.attack_path,
           tr.impact, tr.feasibility, tr.initial_risk, tr.cybersecurity_goal,
           tr.treatment, tr.residual_risk, c.control_code, c.title AS control_title,
           c.verification
    FROM tara_records tr
    JOIN assets a ON a.asset_code=tr.asset_code
    JOIN threats t ON t.threat_code=tr.threat_code
    LEFT JOIN controls c ON c.component_code=tr.component_code
    """
    params: tuple[Any, ...] = ()
    if component_code:
        query += " WHERE tr.component_code=?"
        params = (component_code,)
    query += " ORDER BY tr.id, c.id"
    raw = rows(query, params)
    grouped: dict[str, dict[str, Any]] = {}
    for item in raw:
        key = item["tara_code"]
        if key not in grouped:
            grouped[key] = {k: item[k] for k in [
                "tara_code", "component_code", "asset", "threat", "stride_categories",
                "mitre_techniques", "damage_scenario", "attack_path", "impact",
                "feasibility", "initial_risk", "cybersecurity_goal", "treatment", "residual_risk",
            ]}
            grouped[key]["controls"] = []
        if item.get("control_code"):
            grouped[key]["controls"].append({
                "control_code": item["control_code"],
                "title": item["control_title"],
                "verification": item["verification"],
            })
    return list(grouped.values())


def crosswalk() -> list[dict[str, Any]]:
    return rows("""
    SELECT cm.control_code, c.title AS control_title, c.component_code,
           r.requirement_code, r.reference, r.title AS requirement_title,
           f.framework_code, f.name AS framework_name, f.source_type,
           cm.relationship, cm.confidence, cm.rationale
    FROM control_mappings cm
    JOIN controls c ON c.control_code=cm.control_code
    JOIN requirements r ON r.requirement_code=cm.requirement_code
    JOIN frameworks f ON f.framework_code=r.framework_code
    ORDER BY c.id, f.id, r.id
    """)


def applicability(campaign_id: int) -> list[dict[str, Any]]:
    return rows("""
    SELECT a.*, r.title AS requirement_title, r.reference, r.framework_code,
           f.name AS framework_name
    FROM applicability a
    JOIN requirements r ON r.requirement_code=a.requirement_code
    JOIN frameworks f ON f.framework_code=r.framework_code
    WHERE a.campaign_id=? ORDER BY a.id
    """, (campaign_id,))


def corrective_actions() -> list[dict[str, Any]]:
    return rows("""
    SELECT ca.*, f.title AS finding_title, f.severity AS finding_severity,
           f.status AS finding_status
    FROM corrective_actions ca
    JOIN findings f ON f.id=ca.finding_id
    ORDER BY ca.id DESC
    """)


def evidence_content(evidence_code: str) -> dict[str, Any] | None:
    item = row("SELECT * FROM evidence WHERE evidence_code=?", (evidence_code,))
    if not item:
        return None
    path = EVIDENCE_DIR / item["file_name"]
    item["content"] = path.read_text(encoding="utf-8") if path.exists() else "Evidence file missing."
    return item


def _required(payload: dict[str, Any], fields: list[str]) -> None:
    missing = [name for name in fields if str(payload.get(name, "")).strip() == ""]
    if missing:
        raise ValueError(f"Missing fields: {', '.join(missing)}")


def add_campaign(payload: dict[str, Any]) -> int:
    fields = ["campaign_code", "title", "objective", "vehicle_program", "model_year", "scope",
              "software_baseline", "period_start", "period_end", "assessor", "approver",
              "due_date", "status", "created_at"]
    _required(payload, fields)
    return execute(
        f"INSERT INTO campaigns ({','.join(fields)}) VALUES ({','.join('?' for _ in fields)})",
        tuple(payload[name] for name in fields),
    )


def save_applicability(payload: dict[str, Any]) -> int:
    fields = ["campaign_id", "requirement_code", "component_code", "decision", "rationale",
              "requirement_owner", "review_status", "updated_at"]
    _required(payload, fields)
    existing = row(
        "SELECT id FROM applicability WHERE campaign_id=? AND requirement_code=? AND component_code=?",
        (payload["campaign_id"], payload["requirement_code"], payload["component_code"]),
    )
    if existing:
        update("""
            UPDATE applicability SET decision=?, rationale=?, requirement_owner=?, review_status=?, updated_at=?
            WHERE id=?
        """, (payload["decision"], payload["rationale"], payload["requirement_owner"],
              payload["review_status"], payload["updated_at"], existing["id"]))
        return int(existing["id"])
    return execute(
        f"INSERT INTO applicability ({','.join(fields)}) VALUES ({','.join('?' for _ in fields)})",
        tuple(payload[name] for name in fields),
    )


def add_evidence_request(payload: dict[str, Any]) -> int:
    fields = ["campaign_id", "request_code", "requirement_code", "component_code",
              "requested_evidence", "evidence_owner", "due_date", "status",
              "received_evidence_codes", "sufficiency_notes"]
    _required(payload, fields[:-2])
    payload.setdefault("received_evidence_codes", "")
    payload.setdefault("sufficiency_notes", "")
    return execute(
        f"INSERT INTO evidence_requests ({','.join(fields)}) VALUES ({','.join('?' for _ in fields)})",
        tuple(payload.get(name, "") for name in fields),
    )


def add_control_evaluation(payload: dict[str, Any]) -> int:
    fields = ["campaign_id", "requirement_code", "control_code", "component_code", "evidence_codes",
              "design_status", "implementation_status", "effectiveness_status", "overall_status",
              "evidence_relevance", "evidence_authenticity", "evidence_completeness",
              "evidence_currency", "evidence_scope", "rationale", "recommendation", "assessor",
              "reviewer", "created_at"]
    _required(payload, fields)
    return execute(
        f"INSERT INTO control_evaluations ({','.join(fields)}) VALUES ({','.join('?' for _ in fields)})",
        tuple(payload[name] for name in fields),
    )


def add_assessment(payload: dict[str, Any]) -> int:
    fields = ["requirement_code", "control_code", "component_code", "evidence_codes", "status",
              "rationale", "recommendation", "assessor", "created_at"]
    _required(payload, fields)
    return execute(
        f"INSERT INTO assessments ({','.join(fields)}) VALUES ({','.join('?' for _ in fields)})",
        tuple(payload[name] for name in fields),
    )


def add_finding(payload: dict[str, Any]) -> int:
    fields = ["assessment_id", "campaign_id", "title", "severity", "status", "recommendation",
              "owner", "due_date", "residual_risk", "created_at"]
    _required(payload, ["title", "severity", "status", "recommendation", "owner", "due_date",
                        "residual_risk", "created_at"])
    return execute(
        f"INSERT INTO findings ({','.join(fields)}) VALUES ({','.join('?' for _ in fields)})",
        tuple(payload.get(name) for name in fields),
    )


def add_corrective_action(payload: dict[str, Any]) -> int:
    fields = ["finding_id", "action_code", "root_cause", "action_plan", "interim_mitigation", "owner",
              "target_date", "status", "completion_evidence_codes", "retest_status", "retest_notes",
              "approver", "updated_at"]
    _required(payload, ["finding_id", "action_code", "root_cause", "action_plan", "owner",
                        "target_date", "status", "retest_status", "approver", "updated_at"])
    return execute(
        f"INSERT INTO corrective_actions ({','.join(fields)}) VALUES ({','.join('?' for _ in fields)})",
        tuple(payload.get(name, "") for name in fields),
    )


def add_audit_response(payload: dict[str, Any]) -> int:
    fields = ["question_id", "respondent", "response", "self_score", "created_at"]
    _required(payload, fields)
    return execute(
        f"INSERT INTO audit_responses ({','.join(fields)}) VALUES ({','.join('?' for _ in fields)})",
        tuple(payload[name] for name in fields),
    )


def export_report(campaign_id: int = 1) -> str:
    data = bootstrap(campaign_id)
    campaign = row("SELECT * FROM campaigns WHERE id=?", (campaign_id,)) or {}
    lines = [
        "# Automotive Cybersecurity Assurance Campaign Report", "",
        f"**Campaign:** {campaign.get('campaign_code', 'N/A')} — {campaign.get('title', 'N/A')}",
        f"**Vehicle program:** {campaign.get('vehicle_program', 'N/A')}",
        f"**Software baseline:** {campaign.get('software_baseline', 'N/A')}",
        f"**Scope:** {campaign.get('scope', 'N/A')}",
        f"**Assessment period:** {campaign.get('period_start', '')} to {campaign.get('period_end', '')}",
        f"**Assessor / approver:** {campaign.get('assessor', '')} / {campaign.get('approver', '')}", "",
        "## Executive Snapshot", "",
        f"- Applicable requirements: {data['metrics']['applicable_requirements']}",
        f"- Control evaluations: {data['metrics']['control_evaluations']}",
        f"- Evidence objects: {data['metrics']['evidence_objects']}",
        f"- Open findings: {data['metrics']['open_findings']}",
        f"- Open corrective actions: {data['metrics']['open_actions']}", "",
        "## Applicability Decisions", "",
    ]
    for item in data["applicability"]:
        lines += [f"### {item['requirement_code']} — {item['component_code']}",
                  f"- Decision: {item['decision']}", f"- Rationale: {item['rationale']}",
                  f"- Owner: {item['requirement_owner']}", ""]
    lines += ["## Evidence Request Plan", ""]
    for item in data["evidence_requests"]:
        lines += [f"### {item['request_code']} — {item['status']}",
                  f"- Requirement/component: {item['requirement_code']} / {item['component_code']}",
                  f"- Requested: {item['requested_evidence']}",
                  f"- Received: {item['received_evidence_codes'] or 'None'}",
                  f"- Sufficiency: {item['sufficiency_notes'] or 'Not assessed'}", ""]
    lines += ["## Control Evaluations", ""]
    for item in data["control_evaluations"]:
        quality = sum(int(item[k]) for k in ["evidence_relevance", "evidence_authenticity",
                                              "evidence_completeness", "evidence_currency", "evidence_scope"])
        lines += [f"### Evaluation {item['id']} — {item['overall_status']}",
                  f"- Requirement / control: {item['requirement_code']} / {item['control_code']}",
                  f"- Design: {item['design_status']}",
                  f"- Implementation: {item['implementation_status']}",
                  f"- Operating effectiveness: {item['effectiveness_status']}",
                  f"- Evidence quality: {quality}/25",
                  f"- Rationale: {item['rationale']}",
                  f"- Recommendation: {item['recommendation']}", ""]
    lines += ["## Current and Target Profile", ""]
    for item in data["profile_outcomes"]:
        lines += [f"### {item['outcome_code']} — {item['gap_level']} gap",
                  f"- Current: {item['current_state']}", f"- Target: {item['target_state']}",
                  f"- Action: {item['action']}", ""]
    lines += ["## Findings and Corrective Actions", ""]
    for finding in data["findings"]:
        lines += [f"### Finding {finding['id']} — {finding['severity']} / {finding['status']}",
                  f"- {finding['title']}", f"- Recommendation: {finding['recommendation']}",
                  f"- Residual risk: {finding['residual_risk']}", ""]
    for action in data["corrective_actions"]:
        lines += [f"### {action['action_code']} — {action['status']}",
                  f"- Finding: {action['finding_title']}", f"- Root cause: {action['root_cause']}",
                  f"- Action: {action['action_plan']}", f"- Retest: {action['retest_status']} — {action['retest_notes']}", ""]
    lines += ["## Limitations", "",
              "This portfolio prototype supports learning, traceability and evidence-based assessment. It does not certify compliance, reproduce proprietary OEM processes, or replace authorized engineering and regulatory decisions."]
    return "\n".join(lines)
