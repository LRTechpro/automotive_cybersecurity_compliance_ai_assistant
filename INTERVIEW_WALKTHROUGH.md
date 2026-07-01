# Five-Minute Interview Walkthrough

## 1. Define the product and boundary

“This is a locally hosted portfolio prototype using a synthetic APIM, GWM, and TCU architecture. It contains no Ford internal data or processes.”

## 2. Show the assessment campaign

Explain the software baseline, production-equivalent environment, assessment period, assessor, approver, and scope exclusions.

## 3. Connect architecture to applicability

Explain why an externally exposed TCU and APIM make GWM diagnostic isolation applicable. Connect the decision to the TCU diagnostic-pivot TARA.

## 4. Show the evidence request

Demonstrate that evidence requirements were defined before reviewing submitted artifacts: approved policy, software version, UDS capture, local event, fleet alert, procedure, and result.

## 5. Perform the three-layer evaluation

- Design is effective because source-aware diagnostic authorization would address the risk.
- Implementation is present in the scoped GWM baseline.
- Operating effectiveness is partial because denial and local logging work, but centralized alerting and automatic event correlation are not demonstrated.

## 6. Explain evidence quality

The evidence is relevant and current but incomplete for the full requirement. One denied request does not prove every route, restart state, update state, or reporting outcome.

## 7. Show the finding and corrective action

Explain the root cause, owner, interim mitigation, target date, required completion evidence, retest, and approval.

## 8. Show cross-framework traceability

One control can support related outcomes across automotive, organizational, OEM, and supplier sources. A mapping shows a relationship; it does not automatically prove conformity.

## 9. Close with human authority

“The assistant identifies mappings and evidence gaps. The engineer owns the rationale, and an authorized risk owner or approver accepts residual risk.”
