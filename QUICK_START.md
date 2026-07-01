# Version 3 Guided Exercise

## Objective

Determine whether synthetic TCU release 5.3 can pass the automotive cybersecurity release gate.

## 1. Launch

Run `run_windows.bat` or:

```bash
python server.py --reset
```

Reset rebuilds the seeded v3 database, removes locally ingested artifacts from `data/ingested`, and preserves the seeded evidence pack under `data/evidence`.

Open `http://127.0.0.1:8765` and leave **Guided learning** enabled.

## 2. Compare the release

Open **Releases & baselines**.

Compare:

- `REL-TCU-52` — approved TCU 5.2.0
- `REL-TCU-53` — candidate TCU 5.3.0

Identify the three material changes:

- certificate validation library;
- DoIP retry/route selection;
- telemetry event schema.

Explain why these are cybersecurity-relevant rather than merely software changes.

## 3. Run change-impact analysis

Open **Change impact** and click **Recalculate impact**.

Follow the changes to:

- `TARA-TCU-001` and `TARA-TCU-002`;
- `CTRL-TCU-002`, `CTRL-GWM-001`, `CTRL-GWM-003`, and `CTRL-LOG-001`;
- related ISO/SAE 21434, UN R155/R156, NIST, ISO 27001, OEM, and supplier requirements;
- stale evidence;
- detection rules;
- cybersecurity claims.

## 4. Review evidence staleness

Open **Evidence lifecycle**.

State why:

- `EVD-TCU-002` is stale for TCU 5.3;
- `EVD-GWM-001` requires retesting even though GWM 6.4 did not change;
- `EVD-LOG-001` remains a known gap;
- pending replacement evidence cannot support release approval.

## 5. Analyze the SBOM and vulnerability

Open **Vulnerabilities & SBOM**.

Review `CVE-SYNTH-2026-0421` and answer:

- Is CertCore 3.1.0 present?
- Is the affected functionality reachable?
- Is exploitation proven?
- Which TARA and control are affected?
- What remediation and retest are required?

Do not treat the CVE match as automatic proof of vehicle exploitation.

## 6. Parse evidence

Open **Evidence ingestion**.

Use the seeded UDS result and click **Parse and store locally**.

Confirm that the parser identifies:

- UDS `0x34 RequestDownload`;
- NRC `0x33 securityAccessDenied`;
- no forwarding to the protected route;
- no fleet alert.

Explain why this supports prevention but not complete detection/reporting.

## 7. Review detection engineering

Open **Detection engineering**.

For `DET-TCU-GWM-001`, identify:

- attacker behavior;
- telemetry sources;
- correlation window and logic;
- expected severity;
- response playbook;
- missing validation evidence.

## 8. Review the cybersecurity case

Open **Cybersecurity case**.

Explain why:

- the diagnostic claim needs revalidation;
- the identity claim is unsupported for the candidate;
- the monitoring claim is only partially supported;
- the top-level claim cannot yet be fully supported.

## 9. Make the release decision

Open **Release security gate**.

The calculated posture should be **Blocked** because of:

- an open High vulnerability;
- stale and pending mandatory evidence;
- unvalidated detections;
- unsupported claims;
- an open High monitoring finding.

Record **Additional evidence required** as the human decision. Do not approve the release.

## 10. Repeat in Analyst mode

Reset the database and repeat without guided explanations. Make your own release decision before opening the gate screen.
