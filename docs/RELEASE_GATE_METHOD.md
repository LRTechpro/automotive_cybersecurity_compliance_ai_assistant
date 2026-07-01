# Release Security Gate Method

The v3 gate calculates one of three postures:

## Blocked

Used when any of the following are present:

- open Critical or High vulnerability without accepted disposition;
- required evidence that is stale, pending, failed, or retest-required;
- open Critical or High finding;
- required control or cybersecurity claim unsupported for the candidate.

## Conditional

Used when major blockers are closed but remaining monitoring, documentation, or Medium-risk gaps require explicit conditions and authorized residual-risk acceptance.

## Ready for human approval

Used when required evidence is current, vulnerabilities and findings are dispositioned, detections are validated, and cybersecurity claims are supported.

This status is not an approval. The authorized release authority records the final decision.
