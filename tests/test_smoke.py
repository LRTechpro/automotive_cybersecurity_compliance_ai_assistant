from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import database  # noqa: E402


def main() -> None:
    database.initialize_database(reset=True)
    data = database.bootstrap(1)
    assert data["metrics"]["in_scope_components"] == 3
    assert data["metrics"]["campaigns"] >= 1
    assert data["metrics"]["candidate_releases"] >= 1
    assert data["metrics"]["stale_evidence"] >= 3
    assert data["metrics"]["open_high_vulnerabilities"] >= 1
    assert len(data["software_releases"]) >= 4
    assert len(data["release_changes"]) >= 3
    assert len(data["cybersecurity_claims"]) >= 4
    assert database.evidence_content("EVD-GWM-001")["content"]
    assert database.evidence_content("EVD-TCU-004")["content"]
    assert database.traceability("TCU")[0]["tara_code"].startswith("TARA-TCU")
    comparison = database.release_comparison("REL-TCU-52", "REL-TCU-53")
    assert any(item["component_name"] == "CertCore" and item["change"] == "Updated" for item in comparison["sbom_diff"])
    impact = database.analyze_release("REL-TCU-53")
    assert impact["impacts"]
    gate = database.gate_posture("REL-TCU-53")
    assert gate["status"] == "Blocked"
    assert gate["counts"]["high_vulnerabilities"] >= 1
    artifact = database.ingest_artifact({
        "artifact_type": "UDS log",
        "component_code": "TCU/GWM",
        "release_code": "REL-TCU-53",
        "file_name": "test_uds.txt",
        "content": "UDS 0x34 RequestDownload\nNRC 0x33 securityAccessDenied\nForwarded to protected route: NO\nFleet alert generated: NO",
    })
    assert artifact["parsed"]["fleet_alert"] == "no"
    report = database.export_report(1, "REL-TCU-53")
    assert "Continuous Automotive Cybersecurity Assurance Report" in report
    assert "Release Gate Posture" in report
    print(json.dumps(data["metrics"], indent=2))
    print("Version 3 smoke tests passed.")


if __name__ == "__main__":
    main()
