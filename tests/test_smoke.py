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
    assert data["metrics"]["applicable_requirements"] >= 3
    assert data["metrics"]["control_evaluations"] >= 2
    assert data["metrics"]["evidence_objects"] >= 7
    assert database.evidence_content("EVD-GWM-001")["content"]
    assert database.traceability("TCU")[0]["tara_code"].startswith("TARA-TCU")
    assert any(item["requirement_code"] == "REQ-OEM-GWM" for item in database.crosswalk())
    assert any(item["decision"] == "Applicable" for item in database.applicability(1))
    assert database.corrective_actions()
    report = database.export_report(1)
    assert "Automotive Cybersecurity Assurance Campaign Report" in report
    assert "Design:" in report and "Operating effectiveness:" in report
    print(json.dumps(data["metrics"], indent=2))
    print("Smoke tests passed.")


if __name__ == "__main__":
    main()
