from __future__ import annotations

import argparse
import json
import mimetypes
import sys
import threading
import webbrowser
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import advisor
import database

ROOT = Path(__file__).resolve().parent
STATIC_DIR = ROOT / "static"
TEMPLATE_DIR = ROOT / "templates"
EXPORT_DIR = ROOT / "exports"


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


class Handler(SimpleHTTPRequestHandler):
    server_version = "AutoCyberWorkbench/3.0"

    def log_message(self, fmt: str, *args: object) -> None:
        sys.stdout.write(f"[{self.log_date_time_string()}] {fmt % args}\n")

    def _send_json(self, payload: object, status: int = 200) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.end_headers()
        self.wfile.write(body)

    def _send_file(self, path: Path, download_name: str | None = None) -> None:
        if not path.exists() or not path.is_file():
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        content = path.read_bytes()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", mimetypes.guess_type(path.name)[0] or "application/octet-stream")
        self.send_header("Content-Length", str(len(content)))
        self.send_header("X-Content-Type-Options", "nosniff")
        if download_name:
            self.send_header("Content-Disposition", f'attachment; filename="{download_name}"')
        self.end_headers()
        self.wfile.write(content)

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length > 4_000_000:
            raise ValueError("Request too large")
        raw = self.rfile.read(length) if length else b"{}"
        return json.loads(raw.decode("utf-8"))

    @staticmethod
    def _campaign_id(query: dict[str, list[str]]) -> int:
        try:
            return int(query.get("campaign_id", ["1"])[0])
        except ValueError:
            return 1

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)
        campaign_id = self._campaign_id(query)

        if path in ("/", "/index.html"):
            return self._send_file(TEMPLATE_DIR / "index.html")
        if path.startswith("/static/"):
            relative = Path(path.removeprefix("/static/"))
            safe = (STATIC_DIR / relative).resolve()
            if STATIC_DIR.resolve() not in safe.parents:
                return self.send_error(HTTPStatus.FORBIDDEN)
            return self._send_file(safe)
        if path == "/api/bootstrap":
            return self._send_json(database.bootstrap(campaign_id))
        if path == "/api/traceability":
            return self._send_json(database.traceability(query.get("component", [None])[0]))
        if path == "/api/crosswalk":
            return self._send_json(database.crosswalk())
        if path == "/api/evidence":
            return self._send_json(database.rows("SELECT * FROM evidence ORDER BY id"))
        if path.startswith("/api/evidence/"):
            item = database.evidence_content(path.rsplit("/", 1)[-1])
            return self._send_json(item or {"error": "Evidence not found"}, 200 if item else 404)
        if path == "/api/release-comparison":
            base = query.get("base", ["REL-TCU-52"])[0]
            candidate = query.get("candidate", ["REL-TCU-53"])[0]
            return self._send_json(database.release_comparison(base, candidate))
        if path == "/api/change-impact":
            release = query.get("release_code", ["REL-TCU-53"])[0]
            return self._send_json(database.analyze_release(release))
        if path == "/api/release-gate":
            release = query.get("release_code", ["REL-TCU-53"])[0]
            return self._send_json(database.gate_posture(release))
        if path == "/api/audit-responses":
            return self._send_json(database.rows("SELECT * FROM audit_responses ORDER BY id DESC"))
        if path == "/api/export":
            release = query.get("release_code", ["REL-TCU-53"])[0]
            EXPORT_DIR.mkdir(parents=True, exist_ok=True)
            report_path = EXPORT_DIR / f"AutoCyber_Continuous_Assurance_{release}.md"
            report_path.write_text(database.export_report(campaign_id, release), encoding="utf-8")
            return self._send_file(report_path, report_path.name)
        if path == "/api/health":
            return self._send_json({"status": "ok", "version": "3.0.0", "time": utc_now(), "local_only": True})
        self.send_error(HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        try:
            payload = self._read_json()
            payload.setdefault("created_at", utc_now())
            payload.setdefault("updated_at", utc_now())
            routes = {
                "/api/campaigns": database.add_campaign,
                "/api/applicability": database.save_applicability,
                "/api/evidence-requests": database.add_evidence_request,
                "/api/control-evaluations": database.add_control_evaluation,
                "/api/assessments": database.add_assessment,
                "/api/findings": database.add_finding,
                "/api/corrective-actions": database.add_corrective_action,
                "/api/audit-responses": database.add_audit_response,
                "/api/vulnerabilities": database.add_vulnerability,
                "/api/release-gates": database.save_release_gate,
            }
            if parsed.path in routes:
                record_id = routes[parsed.path](payload)
                return self._send_json({"ok": True, "id": record_id}, 201)
            if parsed.path == "/api/analyze-release":
                release_code = str(payload.get("release_code", "REL-TCU-53"))
                return self._send_json(database.analyze_release(release_code))
            if parsed.path == "/api/ingest":
                return self._send_json(database.ingest_artifact(payload), 201)
            if parsed.path == "/api/assistant":
                prompt = str(payload.get("prompt", "")).strip()
                if not prompt:
                    raise ValueError("Prompt is required")
                return self._send_json(advisor.advise(prompt, payload.get("context") or {}))
            if parsed.path == "/api/reset":
                if payload.get("confirm") != "RESET DEMO DATA":
                    raise ValueError("Confirmation phrase does not match")
                database.initialize_database(reset=True)
                return self._send_json({"ok": True})
        except (ValueError, json.JSONDecodeError) as exc:
            return self._send_json({"error": str(exc)}, 400)
        except Exception as exc:  # pragma: no cover - surfaced to local user
            return self._send_json({"error": f"Unexpected error: {exc}"}, 500)
        self.send_error(HTTPStatus.NOT_FOUND)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the local Automotive Cybersecurity Assurance Workbench")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--no-browser", action="store_true")
    parser.add_argument("--reset", action="store_true")
    args = parser.parse_args()

    database.initialize_database(reset=args.reset)
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    url = f"http://{args.host}:{args.port}"
    print(f"AutoCyber Traceability & Continuous Assurance Workbench v3.0 running at {url}")
    print("Press Ctrl+C to stop. Data remains local in data/autocyber.db.")
    if not args.no_browser:
        threading.Timer(0.7, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping server.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
