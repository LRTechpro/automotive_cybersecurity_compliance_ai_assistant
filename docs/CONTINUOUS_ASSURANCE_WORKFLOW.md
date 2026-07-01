# Continuous Assurance Workflow

```text
Approved baseline
    ↓
Candidate release
    ↓
Software / configuration / interface difference
    ↓
Affected TARA assumptions and attack paths
    ↓
Affected goals, requirements, and controls
    ↓
Evidence validity and required retesting
    ↓
SBOM and vulnerability disposition
    ↓
Detection and monitoring validation
    ↓
Cybersecurity claim update
    ↓
Release-gate posture
    ↓
Authorized human decision
```

## Core principles

1. An assurance conclusion is scoped to a defined system and version.
2. Evidence remains historical even when it is no longer sufficient for the candidate.
3. Changes in one component can invalidate evidence for an interacting component.
4. SBOM presence does not equal release approval.
5. Vulnerability presence does not equal exploitability, but unresolved risk requires disposition.
6. Detection must be validated end to end, not inferred from local logging.
7. A cybersecurity case makes claims, assumptions, evidence, contradictions, and gaps visible.
8. The system supports the release authority; it does not replace that authority.
