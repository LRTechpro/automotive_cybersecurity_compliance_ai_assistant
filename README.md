# AutoCyber Traceability & Assurance Workbench

A local, portfolio-grade proof of concept for automotive cybersecurity engineering and compliance-assurance work. The application is intentionally limited to a **synthetic APIM, GWM, and TCU architecture** and demonstrates how an engineer connects:

- vehicle architecture and trust boundaries;
- STRIDE threat categorization and applicable MITRE ATT&CK enrichment;
- TARA assets, damage scenarios, attack paths, impact, feasibility, and risk treatment;
- cybersecurity goals, technical requirements, and controls;
- ISO/SAE 21434 concepts, UN R155, UN R156, NIST CSF 2.0, ISO/IEC 27001, synthetic OEM policy, and supplier requirements;
- objective evidence, findings, corrective actions, retesting, and residual-risk approval.

The application does **not** certify compliance, reproduce Ford internal processes, or contain real OEM data.

## Why v2.0 matters

Version 1 demonstrated traceability. Version 2 models the full compliance-assessment lifecycle:

1. Define an assessment campaign and software baseline.
2. Determine requirement applicability.
3. Create an evidence request plan.
4. Assess control design effectiveness.
5. Verify implementation in the scoped baseline.
6. Evaluate operating effectiveness using objective evidence.
7. Score evidence relevance, authenticity, completeness, currency, and scope.
8. Issue findings and corrective actions.
9. Retest and route residual risk to an authorized approver.
10. Defend the assessment through an audit-question simulator.

## Primary demonstration scenario

**Remote TCU compromise → DoIP activity toward the GWM → unauthorized UDS SecurityAccess and RequestDownload attempts.**

The GWM denies the requests and creates a local event. Centralized fleet alerting and TCU-to-GWM event correlation remain incomplete. The resulting compliance-level conclusion is:

- Design effectiveness: **Effective**
- Implementation: **Implemented**
- Operating effectiveness: **Partially Effective**
- Overall status: **Partially Met**

## Features

- Local Python HTTP server and SQLite database
- No required third-party Python packages
- Guided learning and analyst modes
- APIM–GWM–TCU architecture review
- TARA traceability workspace
- Cross-framework control mappings
- Assessment campaigns and software baselines
- Requirement applicability matrix
- Evidence request planning
- Three-layer control evaluation
- Evidence-quality scoring
- Current-versus-target profiles
- Findings and corrective-action workflow
- Supplier assurance review
- Audit-defense simulator
- Optional local Ollama assistant
- Markdown campaign report export

## Quick start

### Windows

1. Install Python 3.11 or newer.
2. Clone or download the repository.
3. Double-click `run_windows.bat`.
4. On the first run, the launcher reconstructs the checksum-verified v2 source ZIP, extracts it, and starts the application.
5. Open `http://127.0.0.1:8765` if the browser does not open automatically.

### macOS or Linux

```bash
chmod +x run_mac_linux.sh
./run_mac_linux.sh
```

The launcher performs the same reconstruction and extraction on its first run.

### Manual reconstruction

```bash
python assemble_v2_release.py
python -m zipfile -e AutoCyber_Traceability_Workbench_v2.0_source.zip .
cd AutoCyber_Traceability_Workbench
python server.py
```

The assembly script verifies this SHA-256 value before accepting the reconstructed source package:

```text
73ac09951150f5751f9385190312815a8cc53366496900218e3d45d874d5abc3
```

### Reset the synthetic demonstration data

Use `run_windows_reset_demo.bat`, or from the extracted application directory run:

```bash
python server.py --reset
```

## Tests

First reconstruct and extract the application. Then run these commands inside `AutoCyber_Traceability_Workbench`:

```bash
python tests/test_smoke.py
python -m py_compile server.py database.py advisor.py
node --check static/app.js
```

## Optional local AI

The built-in guidance rules require no model. To use a local Ollama model:

```powershell
$env:OLLAMA_MODEL="llama3.1:8b"
python server.py
```

Only the selected assessment context is sent to the locally hosted Ollama endpoint.

## Repository structure

```text
├── README.md
├── assemble_v2_release.py
├── release_parts/               # Checksum-verified source archive parts
├── run_windows.bat              # Reconstructs, extracts, and launches
├── run_windows_reset_demo.bat
├── run_mac_linux.sh
├── server.py                    # Readable backend source for review
├── database.py
├── advisor.py
├── schema.sql
├── docs/
└── tests/
```

The reconstructed application includes the complete frontend, seed data, evidence pack, backend, documentation, and tests.

## Interview positioning

> I built a local automotive cybersecurity traceability and assurance prototype focused on a synthetic APIM, GWM, and TCU architecture. It connects STRIDE and applicable MITRE ATT&CK enrichment to TARA, risk-derived requirements, control implementation, objective evidence, ISO/SAE 21434 concepts, UN R155/R156, NIST CSF 2.0, ISO 27001, synthetic OEM policy, supplier requirements, findings, corrective actions, retesting, and residual-risk decisions. The tool assists the engineer, but final compliance and risk decisions remain under human authority.

## Sources and content boundaries

The prototype stores user-authored summaries, identifiers, and illustrative mappings. It does not reproduce licensed standards. Review `LICENSE_AND_CONTENT_NOTICE.md` before expanding the framework library.

Useful public references:

- NIST Cybersecurity Framework 2.0 and Profiles: https://www.nist.gov/cyberframework
- NIST CSF 2.0 Informative References: https://www.nist.gov/cyberframework/informative-references
- UN Regulation No. 155: https://unece.org/transport/documents/2021/03/standards/un-regulation-no-155-cyber-security-and-cyber-security
- UN Regulation No. 156: https://unece.org/transport/documents/2021/03/standards/un-regulation-no-156-software-update-and-software-update
- MITRE ATT&CK: https://attack.mitre.org/

## Limitations

- Synthetic architecture, evidence, policy, suppliers, and software versions
- Illustrative crosswalks requiring qualified review
- Not a type-approval, certification, or legal-compliance engine
- Not representative of Ford proprietary systems, standards, scoring, or governance
- Does not replace authorized cybersecurity, safety, legal, or regulatory decisions
