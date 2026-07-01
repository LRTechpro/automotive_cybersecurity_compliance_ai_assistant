# Version 3 Interview Walkthrough

## Opening

> I built a local continuous automotive cybersecurity assurance prototype around a synthetic APIM, GWM, and TCU platform. Version 3 focuses on maintaining assurance when a software release changes, rather than treating compliance as a one-time assessment.

## 1. Baseline and candidate

Show `REL-TCU-52` and `REL-TCU-53`.

Explain that the candidate changes the certificate library, DoIP behavior, and security-event schema.

## 2. Change-impact traceability

Show how those changes affect:

- TARA threat paths and assumptions;
- TCU and GWM controls;
- technical and organizational requirements;
- evidence validity;
- detection rules;
- cybersecurity claims.

## 3. Evidence lifecycle

Explain that old evidence is preserved but marked stale or retest-required because it was produced against a different implementation or interaction baseline.

Highlight that unchanged GWM software still requires retesting because the TCU’s behavior changed.

## 4. SBOM and vulnerability

Show the CertCore version change and synthetic High vulnerability.

Explain the distinction among:

- component presence;
- reachability;
- exploitability;
- mitigation;
- release impact.

## 5. Evidence parsing

Import the seeded UDS log.

Show that the parser identifies successful prevention but missing fleet alerting. State that the parser proposes observations; the analyst owns the conclusion.

## 6. Detection engineering

Show the unexpected DoIP programming rule, required telemetry, shared event identifier, correlation logic, response playbook, and incomplete validation.

## 7. Cybersecurity case

Show the top-level claim and supporting diagnostic, identity, and monitoring claims. Explain why stale or contradictory evidence weakens the assurance argument.

## 8. Release gate

Show the **Blocked** posture and blockers. Explain that the application can calculate posture but cannot approve the release or accept residual risk.

## Closing

> This project taught me to compare product baselines, perform change-impact analysis, maintain evidence validity, evaluate supplier composition and vulnerabilities, connect detection to modeled attack paths, update a cybersecurity case, and prepare an evidence-based release recommendation for an authorized approver.
