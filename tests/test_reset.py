from __future__ import annotations

import json
import shutil
import sys
import tempfile
import threading
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import database  # noqa: E402
import server  # noqa: E402


def request_json(base_url: str, path: str, payload: dict | None = None) -> tuple[int, dict]:
    body = None
    headers = {"Content-Type": "application/json"}
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(base_url + path, data=body, headers=headers, method="POST" if payload is not None else "GET")
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise AssertionError(f"{path} failed with HTTP {exc.code}: {detail}") from exc


def main() -> None:
    original_paths = (
        database.DB_PATH,
        database.EVIDENCE_DIR,
        database.INGEST_DIR,
        server.EXPORT_DIR,
    )
    with tempfile.TemporaryDirectory(prefix="autocyber-reset-test-") as tmp:
        temp_root = Path(tmp)
        temp_data = temp_root / "data"
        temp_evidence = temp_data / "evidence"
        temp_ingested = temp_data / "ingested"
        shutil.copytree(ROOT / "data" / "evidence", temp_evidence)

        database.DB_PATH = temp_data / "autocyber.db"
        database.EVIDENCE_DIR = temp_evidence
        database.INGEST_DIR = temp_ingested
        server.EXPORT_DIR = temp_root / "exports"

        database.initialize_database(reset=True)
        assert database.DB_PATH.exists()
        assert database.evidence_content("EVD-GWM-001")["content"]

        httpd = server.ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        base_url = f"http://127.0.0.1:{httpd.server_address[1]}"
        try:
            status, data = request_json(base_url, "/api/bootstrap")
            assert status == 200
            assert data["metrics"]["candidate_releases"] >= 1

            for path in (
                "/api/release-comparison?base=REL-TCU-52&candidate=REL-TCU-53",
                "/api/change-impact?release_code=REL-TCU-53",
                "/api/release-gate?release_code=REL-TCU-53",
            ):
                status, _ = request_json(base_url, path)
                assert status == 200

            status, artifact = request_json(base_url, "/api/ingest", {
                "artifact_type": "UDS log",
                "component_code": "TCU/GWM",
                "release_code": "REL-TCU-53",
                "file_name": "reset_regression.txt",
                "content": "UDS 0x34 RequestDownload\nNRC 0x33 securityAccessDenied\nForwarded to protected route: NO\nFleet alert generated: NO",
            })
            assert status == 201
            assert artifact["artifact_code"]
            assert list(temp_ingested.iterdir())

            reset_payload = {"confirm": "RESET DEMO DATA"}
            status, result = request_json(base_url, "/api/reset", reset_payload)
            assert status == 200
            assert result == {"ok": True}
            assert not list(temp_ingested.iterdir())

            status, data = request_json(base_url, "/api/bootstrap")
            assert status == 200
            assert data["metrics"]["candidate_releases"] >= 1
            assert data["ingested_artifacts"] == []
            assert database.evidence_content("EVD-GWM-001")["content"]

            status, result = request_json(base_url, "/api/reset", reset_payload)
            assert status == 200
            assert result == {"ok": True}
            assert not list(temp_ingested.iterdir())
            assert (temp_evidence / "EVD-GWM-001_UDS_Enforcement_Log.txt").exists()
        finally:
            httpd.shutdown()
            httpd.server_close()
            thread.join(timeout=5)
            database.DB_PATH, database.EVIDENCE_DIR, database.INGEST_DIR, server.EXPORT_DIR = original_paths

    print("Reset regression tests passed.")


if __name__ == "__main__":
    main()
