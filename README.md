# AutoCyber Traceability & Continuous Assurance Workbench

A local, portfolio-grade automotive cybersecurity engineering and compliance-assurance prototype focused on a **synthetic APIM, GWM, and TCU architecture**.

Version 3 demonstrates how an engineer maintains assurance when software, dependencies, interfaces, vulnerabilities, evidence, detections, and release baselines change.

## What the project demonstrates

The workbench connects:

- vehicle architecture and trust boundaries;
- STRIDE threat categorization and applicable MITRE ATT&CK enrichment;
- TARA assets, damage scenarios, attack paths, impact, feasibility, treatment, and residual risk;
- cybersecurity goals, technical requirements, controls, and verification;
- ISO/SAE 21434 concepts, UN R155, UN R156, NIST CSF 2.0, ISO/IEC 27001, synthetic OEM policy, and supplier requirements;
- evidence quality, version scope, expiration, staleness, and supersession;
- SBOM differences, vulnerability reachability, exploitability, mitigation, and release impact;
- detection telemetry, analytics, validation, and response playbooks;
- cybersecurity claims, supporting evidence, contradictions, and unresolved gaps;
- calculated release-gate posture and human approval authority.

The application does **not** certify compliance, reproduce Ford internal processes, or contain real OEM data.

## Version 3 learning scenario

The primary scenario compares:

```text
Approved baseline: REL-TCU-52 / TCU 5.2.0
Candidate release: REL-TCU-53 / TCU 5.3.0
```

The candidate release changes:

1. **Certificate validation library** — CertCore 2.8.4 → 3.1.0
2. **DoIP retry and route-selection behavior**
3. **Telemetry event schema** — adds `security_event_id`

The workbench identifies the consequences:

- earlier TCU certificate evidence becomes stale;
- earlier GWM enforcement evidence requires interaction regression testing;
- an SBOM match identifies a synthetic High vulnerability;
- TCU/GWM detection correlation remains unvalidated;
- cybersecurity claims are no longer fully supported;
- the candidate release is calculated as **Blocked** pending remediation and evidence.

## Version progression

| Version | Capability |
|---|---|
| v1 | Trace architecture, TARA, controls, evidence, mappings, and findings |
| v2 | Plan, execute, defend, and close a compliance assessment campaign |
| v3 | Maintain assurance across product releases and post-development changes |

## Version 3 features

- Release and software-baseline comparison
- Change-impact graph
- Evidence staleness and supersession
- SBOM version comparison
- Vehicle-context vulnerability disposition
- Local artifact ingestion and SHA-256 hashing
- UDS/gateway log parsing
- Detection engineering and validation
- Structured cybersecurity case
- Release security gate
- Human decision audit trail
- Continuous assurance report export
- Guided learning and analyst modes
- Optional local Ollama integration

## Quick start

### Windows

1. Install Python 3.11 or newer.
2. Extract the downloaded ZIP or clone the repository.
3. Double-click `run_windows.bat`.
4. Open `http://127.0.0.1:8765` if the browser does not open automatically.

### macOS or Linux

```bash
chmod +x run_mac_linux.sh
./run_mac_linux.sh
```

### Reset the synthetic demonstration

```bash
python server.py --reset
```

## Recommended learning order

1. Assurance dashboard
2. Releases & baselines
3. Change impact
4. Evidence lifecycle
5. Vulnerabilities & SBOM
6. Evidence ingestion
7. Detection engineering
8. Cybersecurity case
9. Release security gate
10. TARA and framework traceability
11. Interview walkthrough

Read `QUICK_START.md` for the guided exercise and `INTERVIEW_WALKTHROUGH.md` for the demonstration script.

## Local architecture

```text
Browser UI
   ↓
Python local HTTP server
   ↓
SQLite assurance database
   ├── TARA, controls, requirements, mappings
   ├── campaigns, evaluations, findings, actions
   ├── releases, changes, impacts, evidence lifecycle
   ├── SBOM and vulnerabilities
   ├── detections and cybersecurity claims
   └── release-gate decisions
```

No third-party Python packages are required for the core application.

## Optional local AI

The built-in deterministic guidance requires no model. To use a local Ollama model:

```powershell
$env:OLLAMA_MODEL="llama3.1:8b"
python server.py
```

Only selected local assessment context is sent to the locally hosted Ollama endpoint.

## Tests

```bash
python -m py_compile server.py database.py advisor.py
node --check static/app.js
python tests/test_smoke.py
```

## Interview positioning

> I built a local continuous automotive cybersecurity assurance prototype focused on a synthetic APIM, GWM, and TCU architecture. It compares approved and candidate software baselines, traces changes to TARA risks, controls, requirements, evidence, framework mappings, detection analytics, and cybersecurity claims, identifies stale evidence and SBOM vulnerabilities, and calculates release-gate posture. The system assists with traceability and evidence gaps, while authorized engineers retain release and residual-risk authority.

## Boundaries

- Synthetic architecture, evidence, policies, suppliers, versions, vulnerabilities, and findings
- Illustrative framework mappings requiring qualified review
- No real Ford data, proprietary process claims, or production release decisions
- No type approval, certification, or legal-compliance determination
- Licensed standards are not reproduced
