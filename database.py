from __future__ import annotations

import hashlib
import json
import sqlite3
import re
import shutil
from contextlib import contextmanager
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Iterator

ROOT = Path(__file__).resolve().parent
DB_PATH = ROOT / "data" / "autocyber.db"
SCHEMA_PATH = ROOT / "schema.sql"
SEED_PATH = ROOT / "seed_data.json"
EVIDENCE_DIR = ROOT / "data" / "evidence"
INGEST_DIR = ROOT / "data" / "ingested"

BASE_TABLES = [
    "components", "interfaces", "assets", "threats", "tara_records", "controls",
    "frameworks", "requirements", "control_mappings", "evidence",
]
SEED_TABLES = BASE_TABLES + [
    "campaigns", "campaign_components", "applicability", "evidence_requests",
    "control_evaluations", "supplier_assessments", "profile_outcomes", "audit_questions",
    "software_releases", "release_changes", "evidence_lifecycle", "vulnerabilities",
    "sbom_components", "change_impacts", "detection_rules", "cybersecurity_claims",
    "claim_evidence", "release_gates", "ingested_artifacts",
]


@contextmanager
def connection() -> Iterator[sqlite3.Connection]:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
    finally:
        conn.close()


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


def _clear_ingested_artifacts() -> None:
    INGEST_DIR.mkdir(parents=True, exist_ok=True)
    for item in INGEST_DIR.iterdir():
        try:
            if item.is_dir():
                shutil.rmtree(item)
            else:
                item.unlink()
        except OSError as exc:
            raise RuntimeError(f"Unable to remove local ingested artifact '{item}': {exc}") from exc


def _reset_schema(conn: sqlite3.Connection) -> None:
    conn.execute("PRAGMA foreign_keys = OFF")
    objects = conn.execute("""
        SELECT type, name FROM sqlite_master
        WHERE type IN ('view','trigger','table')
          AND name NOT LIKE 'sqlite_%'
        ORDER BY CASE type WHEN 'view' THEN 1 WHEN 'trigger' THEN 2 ELSE 3 END
    """).fetchall()
    for item in objects:
        name = str(item["name"]).replace('"', '""')
        conn.execute(f'DROP {item["type"].upper()} IF EXISTS "{name}"')
    conn.execute("PRAGMA foreign_keys = ON")


def initialize_database(reset: bool = False) -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    INGEST_DIR.mkdir(parents=True, exist_ok=True)
    if reset:
        _clear_ingested_artifacts()

    with connection() as conn:
        if reset:
            _reset_schema(conn)
        conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
        seed = json.loads(SEED_PATH.read_text(encoding="utf-8"))
        for table in SEED_TABLES:
            if conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == 0:
                _insert_many(conn, table, seed.get(table, []))
        for table in ("assessments", "findings", "corrective_actions"):
            if conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == 0:
                _insert_many(conn, table, seed.get(table, []))

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

# ---------------------------------------------------------------------------
# Version 3 continuous-assurance functions. Later definitions intentionally
# extend the v2 API while preserving the existing assessment workflow.
# ---------------------------------------------------------------------------

def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _count(conn: sqlite3.Connection, sql: str, params: tuple[Any, ...] = ()) -> int:
    return int(conn.execute(sql, params).fetchone()[0])


def metrics(campaign_id: int = 1) -> dict[str, Any]:
    with connection() as conn:
        return {
            "in_scope_components": _count(conn, "SELECT COUNT(*) FROM components WHERE scope_status='in_scope'"),
            "tara_records": _count(conn, "SELECT COUNT(*) FROM tara_records"),
            "framework_sources": _count(conn, "SELECT COUNT(*) FROM frameworks"),
            "control_mappings": _count(conn, "SELECT COUNT(*) FROM control_mappings"),
            "evidence_objects": _count(conn, "SELECT COUNT(*) FROM evidence"),
            "open_findings": _count(conn, "SELECT COUNT(*) FROM findings WHERE status NOT IN ('Closed','Accepted')"),
            "applicable_requirements": _count(conn, "SELECT COUNT(*) FROM applicability WHERE campaign_id=? AND decision LIKE 'Applicable%'", (campaign_id,)),
            "control_evaluations": _count(conn, "SELECT COUNT(*) FROM control_evaluations WHERE campaign_id=?", (campaign_id,)),
            "campaigns": _count(conn, "SELECT COUNT(*) FROM campaigns"),
            "open_actions": _count(conn, "SELECT COUNT(*) FROM corrective_actions WHERE status NOT IN ('Closed','Verified')"),
            "candidate_releases": _count(conn, "SELECT COUNT(*) FROM software_releases WHERE status NOT LIKE 'Approved%'"),
            "stale_evidence": _count(conn, "SELECT COUNT(*) FROM evidence_lifecycle WHERE status IN ('Stale','Retest required','Gap open','Pending') AND required_for_gate='Yes'"),
            "open_high_vulnerabilities": _count(conn, "SELECT COUNT(*) FROM vulnerabilities WHERE severity IN ('Critical','High') AND status NOT IN ('Closed','Remediated','Accepted')"),
            "open_change_impacts": _count(conn, "SELECT COUNT(*) FROM change_impacts WHERE status NOT IN ('Closed','Complete','Accepted')"),
            "unsupported_claims": _count(conn, "SELECT COUNT(*) FROM cybersecurity_claims WHERE status NOT IN ('Supported','Accepted')"),
        }


def release_comparison(base_release: str, candidate_release: str) -> dict[str, Any]:
    base = row("SELECT * FROM software_releases WHERE release_code=?", (base_release,))
    candidate = row("SELECT * FROM software_releases WHERE release_code=?", (candidate_release,))
    if not base or not candidate:
        raise ValueError("Both base and candidate releases are required")
    base_sbom = {x["component_name"]: x for x in rows("SELECT * FROM sbom_components WHERE release_code=?", (base_release,))}
    cand_sbom = {x["component_name"]: x for x in rows("SELECT * FROM sbom_components WHERE release_code=?", (candidate_release,))}
    diffs = []
    for name in sorted(set(base_sbom) | set(cand_sbom)):
        before, after = base_sbom.get(name), cand_sbom.get(name)
        if not before:
            change = "Added"
        elif not after:
            change = "Removed"
        elif before["version"] != after["version"]:
            change = "Updated"
        else:
            change = "Unchanged"
        diffs.append({
            "component_name": name,
            "before": before["version"] if before else "—",
            "after": after["version"] if after else "—",
            "change": change,
            "known_vulnerability": (after or before).get("known_vulnerability", ""),
            "status": (after or before).get("status", ""),
        })
    return {
        "base": base,
        "candidate": candidate,
        "changes": rows("SELECT * FROM release_changes WHERE release_code=? ORDER BY id", (candidate_release,)),
        "sbom_diff": diffs,
    }


def analyze_release(release_code: str) -> dict[str, Any]:
    release = row("SELECT * FROM software_releases WHERE release_code=?", (release_code,))
    if not release:
        raise ValueError("Release not found")
    changes = rows("SELECT * FROM release_changes WHERE release_code=? ORDER BY id", (release_code,))
    with connection() as conn:
        for change in changes:
            mappings = [
                ("Control", change["affected_controls"]),
                ("TARA", change["affected_tara"]),
                ("Requirement", change["affected_requirements"]),
            ]
            for impact_type, codes in mappings:
                for code in [c.strip() for c in codes.split(";") if c.strip()]:
                    title = code
                    if impact_type == "Control":
                        found = conn.execute("SELECT title FROM controls WHERE control_code=?", (code,)).fetchone()
                    elif impact_type == "TARA":
                        found = conn.execute("SELECT damage_scenario FROM tara_records WHERE tara_code=?", (code,)).fetchone()
                    else:
                        found = conn.execute("SELECT title FROM requirements WHERE requirement_code=?", (code,)).fetchone()
                    if found:
                        title = found[0]
                    conn.execute("""
                        INSERT OR IGNORE INTO change_impacts
                        (release_code, source_change_code, impact_type, target_code, target_title, impact_reason, action, status)
                        VALUES (?,?,?,?,?,?,?,?)
                    """, (
                        release_code, change["change_code"], impact_type, code, title,
                        change["cybersecurity_impact"],
                        "Reassess and obtain current evidence" if change["requires_retest"] == "Yes" else "Review impact",
                        "Retest required" if change["requires_retest"] == "Yes" else "Review",
                    ))
        conn.commit()
    return {
        "release": release,
        "changes": changes,
        "impacts": rows("SELECT * FROM change_impacts WHERE release_code=? ORDER BY id", (release_code,)),
        "evidence_lifecycle": rows("SELECT * FROM evidence_lifecycle WHERE release_code=? ORDER BY id", (release_code,)),
        "gate": gate_posture(release_code),
    }


def gate_posture(release_code: str) -> dict[str, Any]:
    release = row("SELECT * FROM software_releases WHERE release_code=?", (release_code,))
    if not release:
        raise ValueError("Release not found")
    stale = rows("""
        SELECT * FROM evidence_lifecycle
        WHERE release_code=? AND required_for_gate='Yes'
          AND status NOT IN ('Current','Accepted','Approved','Supports')
        ORDER BY id
    """, (release_code,))
    vulns = rows("""
        SELECT * FROM vulnerabilities
        WHERE release_code=? AND severity IN ('Critical','High')
          AND status NOT IN ('Closed','Remediated','Accepted')
        ORDER BY cvss DESC
    """, (release_code,))
    detections = rows("""
        SELECT * FROM detection_rules
        WHERE validation_status NOT IN ('Validated','Accepted')
          AND (component_code=? OR component_code LIKE ? OR linked_tara IN
              (SELECT affected_tara FROM release_changes WHERE release_code=?))
        ORDER BY id
    """, (release["component_code"], f"%{release['component_code']}%", release_code))
    claims = rows("SELECT * FROM cybersecurity_claims WHERE status NOT IN ('Supported','Accepted') ORDER BY id")
    findings = rows("SELECT * FROM findings WHERE severity IN ('Critical','High') AND status NOT IN ('Closed','Accepted') ORDER BY id")
    blockers = []
    blockers += [f"{v['vuln_code']} ({v['severity']}) remains {v['status']}" for v in vulns]
    blockers += [f"{e['evidence_code']}: {e['status']}" for e in stale]
    blockers += [f"{d['rule_code']}: detection {d['validation_status']}" for d in detections]
    blockers += [f"{c['claim_code']}: {c['status']}" for c in claims if c["claim_code"] != "CLAIM-TOP-001"]
    blockers += [f"Finding {f['id']}: {f['title']}" for f in findings]
    if vulns or stale or findings:
        status, recommendation = "Blocked", "Additional evidence or remediation required"
    elif detections or claims:
        status, recommendation = "Conditional", "Approve only with documented conditions and authorized residual-risk acceptance"
    else:
        status, recommendation = "Ready for human approval", "Security evidence supports release-gate review"
    return {
        "release": release,
        "status": status,
        "recommendation": recommendation,
        "blockers": blockers,
        "counts": {
            "stale_evidence": len(stale),
            "high_vulnerabilities": len(vulns),
            "unvalidated_detections": len(detections),
            "unsupported_claims": len(claims),
            "high_findings": len(findings),
        },
        "latest_decision": row("SELECT * FROM release_gates WHERE release_code=? ORDER BY id DESC LIMIT 1", (release_code,)),
    }


def _parse_artifact(artifact_type: str, content: str) -> dict[str, Any]:
    low = content.lower()
    result: dict[str, Any] = {"artifact_type": artifact_type, "observations": []}
    if artifact_type.lower() in {"uds log", "gateway log", "diagnostic log"}:
        services = sorted(set(re.findall(r"0x(?:27|34|10|11|22|2e|31)", low)))
        nrcs = sorted(set(re.findall(r"nrc\s*0x[0-9a-f]{2}|0x33\s*securityaccessdenied", low)))
        result.update({
            "services": services,
            "negative_responses": nrcs,
            "forwarded_to_protected_route": "no" if re.search(r"forwarded[^\n:]*:\s*no", low) else "unknown",
            "fleet_alert": "no" if re.search(r"fleet alert[^\n:]*:\s*no", low) else ("yes" if re.search(r"fleet alert[^\n:]*:\s*yes", low) else "unknown"),
        })
        if "0x34" in services and "0x33" in low:
            result["observations"].append("Unauthorized RequestDownload appears to have been denied with NRC 0x33.")
        if result["fleet_alert"] == "no":
            result["observations"].append("Prevention may be demonstrated, but centralized reporting is not.")
    elif artifact_type.lower() == "sbom":
        lines = [line.strip() for line in content.splitlines() if line.strip()]
        result["component_lines"] = len(lines)
        result["vulnerability_mentions"] = sorted(set(re.findall(r"CVE-[A-Z0-9-]+|CVE-\d{4}-\d+", content, re.I)))
        if result["vulnerability_mentions"]:
            result["observations"].append("SBOM contains one or more vulnerability references requiring disposition.")
    elif artifact_type.lower() in {"vulnerability advisory", "scan result"}:
        cvss = re.search(r"cvss\s*[:=]\s*([0-9.]+)", low)
        severity = re.search(r"severity\s*[:=]\s*(critical|high|medium|low)", low)
        result["cvss"] = float(cvss.group(1)) if cvss else None
        result["severity"] = severity.group(1).title() if severity else "Unknown"
        result["observations"].append("Reachability and vehicle-context exploitability still require analyst validation.")
    else:
        result["line_count"] = len(content.splitlines())
        result["observations"].append("Artifact stored and hashed; analyst interpretation is required.")
    return result


def ingest_artifact(payload: dict[str, Any]) -> dict[str, Any]:
    required = ["artifact_type", "component_code", "release_code", "file_name", "content"]
    _required(payload, required)
    content = str(payload["content"])
    digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
    with connection() as conn:
        artifact_id = _count(conn, "SELECT COUNT(*) FROM ingested_artifacts") + 1
    artifact_code = f"ART-{artifact_id:04d}"
    safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "_", str(payload["file_name"]))[:120] or f"{artifact_code}.txt"
    stored_name = f"{artifact_code}_{safe_name}"
    INGEST_DIR.mkdir(parents=True, exist_ok=True)
    (INGEST_DIR / stored_name).write_text(content, encoding="utf-8")
    parsed = _parse_artifact(str(payload["artifact_type"]), content)
    record_id = execute("""
        INSERT INTO ingested_artifacts
        (artifact_code, artifact_type, component_code, release_code, file_name, sha256, parsed_summary, analyst_status, created_at)
        VALUES (?,?,?,?,?,?,?,?,?)
    """, (artifact_code, payload["artifact_type"], payload["component_code"], payload["release_code"], stored_name,
          digest, json.dumps(parsed, ensure_ascii=False), "Pending analyst confirmation", utc_now()))
    return {"id": record_id, "artifact_code": artifact_code, "sha256": digest, "parsed": parsed}


def add_vulnerability(payload: dict[str, Any]) -> int:
    fields = ["vuln_code", "release_code", "component_code", "affected_component", "affected_versions",
              "severity", "cvss", "reachability", "exploitability", "status", "linked_tara", "linked_control",
              "remediation", "due_date"]
    _required(payload, fields)
    return execute(
        f"INSERT INTO vulnerabilities ({','.join(fields)}) VALUES ({','.join('?' for _ in fields)})",
        tuple(payload[name] for name in fields),
    )


def save_release_gate(payload: dict[str, Any]) -> int:
    fields = ["release_code", "decision", "decision_status", "blockers", "conditions", "residual_risk",
              "approver", "approved_at", "notes", "created_at"]
    _required(payload, ["release_code", "decision", "decision_status", "blockers", "conditions",
                        "residual_risk", "approver", "notes", "created_at"])
    payload.setdefault("approved_at", "")
    return execute(
        f"INSERT INTO release_gates ({','.join(fields)}) VALUES ({','.join('?' for _ in fields)})",
        tuple(payload.get(name, "") for name in fields),
    )


def bootstrap(campaign_id: int = 1) -> dict[str, Any]:
    data = {
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
        "campaign_components": rows("SELECT * FROM campaign_components WHERE campaign_id=? ORDER BY id", (campaign_id,)),
        "applicability": applicability(campaign_id),
        "evidence_requests": rows("SELECT * FROM evidence_requests WHERE campaign_id=? ORDER BY id", (campaign_id,)),
        "control_evaluations": rows("SELECT * FROM control_evaluations WHERE campaign_id=? ORDER BY id DESC", (campaign_id,)),
        "corrective_actions": corrective_actions(),
        "supplier_assessments": rows("SELECT * FROM supplier_assessments WHERE campaign_id=? ORDER BY id", (campaign_id,)),
        "profile_outcomes": rows("SELECT * FROM profile_outcomes WHERE campaign_id=? ORDER BY id", (campaign_id,)),
        "audit_questions": rows("SELECT * FROM audit_questions WHERE campaign_id=? ORDER BY id", (campaign_id,)),
        "software_releases": rows("SELECT * FROM software_releases ORDER BY component_code, version"),
        "release_changes": rows("SELECT * FROM release_changes ORDER BY id"),
        "evidence_lifecycle": rows("SELECT * FROM evidence_lifecycle ORDER BY id"),
        "vulnerabilities": rows("SELECT * FROM vulnerabilities ORDER BY cvss DESC, id"),
        "sbom_components": rows("SELECT * FROM sbom_components ORDER BY release_code, component_name"),
        "change_impacts": rows("SELECT * FROM change_impacts ORDER BY id"),
        "detection_rules": rows("SELECT * FROM detection_rules ORDER BY id"),
        "cybersecurity_claims": rows("SELECT * FROM cybersecurity_claims ORDER BY id"),
        "claim_evidence": rows("SELECT * FROM claim_evidence ORDER BY id"),
        "release_gates": rows("SELECT * FROM release_gates ORDER BY id DESC"),
        "ingested_artifacts": rows("SELECT * FROM ingested_artifacts ORDER BY id DESC"),
        "metrics": metrics(campaign_id),
    }
    return data


def export_report(campaign_id: int = 1, release_code: str = "REL-TCU-53") -> str:
    data = bootstrap(campaign_id)
    campaign = row("SELECT * FROM campaigns WHERE id=?", (campaign_id,)) or {}
    gate = gate_posture(release_code)
    comparison = release_comparison("REL-TCU-52", release_code) if release_code == "REL-TCU-53" else None
    lines = [
        "# Continuous Automotive Cybersecurity Assurance Report", "",
        f"**Campaign:** {campaign.get('campaign_code', 'N/A')} — {campaign.get('title', 'N/A')}",
        f"**Candidate release:** {release_code}",
        f"**Generated:** {utc_now()}", "",
        "## Release Gate Posture", "",
        f"- Calculated posture: **{gate['status']}**",
        f"- Recommendation: {gate['recommendation']}",
        f"- Stale/pending mandatory evidence: {gate['counts']['stale_evidence']}",
        f"- Open high vulnerabilities: {gate['counts']['high_vulnerabilities']}",
        f"- Unvalidated detections: {gate['counts']['unvalidated_detections']}",
        f"- Unsupported claims: {gate['counts']['unsupported_claims']}", "",
        "### Blockers", "",
    ]
    lines += [f"- {item}" for item in gate["blockers"]] or ["- None"]
    lines += ["", "## Release Changes", ""]
    for change in rows("SELECT * FROM release_changes WHERE release_code=? ORDER BY id", (release_code,)):
        lines += [f"### {change['change_code']} — {change['title']}",
                  f"- Type: {change['change_type']}", f"- Description: {change['description']}",
                  f"- Affected controls: {change['affected_controls']}", f"- Affected TARA: {change['affected_tara']}",
                  f"- Impact: {change['cybersecurity_impact']}", f"- Retest: {change['requires_retest']}", ""]
    if comparison:
        lines += ["## SBOM Difference", "", "| Component | Before | After | Change | Vulnerability |", "|---|---:|---:|---|---|"]
        for item in comparison["sbom_diff"]:
            lines.append(f"| {item['component_name']} | {item['before']} | {item['after']} | {item['change']} | {item['known_vulnerability']} |")
        lines.append("")
    lines += ["## Change Impact", ""]
    for impact in rows("SELECT * FROM change_impacts WHERE release_code=? ORDER BY id", (release_code,)):
        lines += [f"- **{impact['impact_type']} {impact['target_code']}** — {impact['status']}: {impact['impact_reason']} Action: {impact['action']}"]
    lines += ["", "## Evidence Lifecycle", ""]
    for ev in rows("SELECT * FROM evidence_lifecycle WHERE release_code=? ORDER BY id", (release_code,)):
        lines += [f"- **{ev['evidence_code']}** — {ev['status']} — valid for {ev['valid_for_version']}. {ev['stale_reason']}"]
    lines += ["", "## Vulnerabilities", ""]
    for v in rows("SELECT * FROM vulnerabilities WHERE release_code=? ORDER BY cvss DESC", (release_code,)):
        lines += [f"- **{v['vuln_code']}** — {v['severity']} / CVSS {v['cvss']} / {v['status']}. Reachability: {v['reachability']}. Remediation: {v['remediation']}"]
    lines += ["", "## Detection Engineering", ""]
    for d in data["detection_rules"]:
        lines += [f"- **{d['rule_code']}** — {d['validation_status']}: {d['logic_summary']}"]
    lines += ["", "## Cybersecurity Case", ""]
    for c in data["cybersecurity_claims"]:
        lines += [f"- **{c['claim_code']} — {c['title']}**: {c['status']}. {c['rationale']}"]
    lines += ["", "## Human Decision Boundary", "",
              "The system calculates evidence posture and proposes actions. An authorized engineer or release authority must approve the release and any residual-risk acceptance."]
    return "\n".join(lines)
