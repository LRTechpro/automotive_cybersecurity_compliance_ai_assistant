from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from typing import Any


def _ollama(prompt: str, context: dict[str, Any]) -> str | None:
    model = os.getenv("OLLAMA_MODEL", "").strip()
    if not model:
        return None
    url = os.getenv("OLLAMA_URL", "http://127.0.0.1:11434/api/generate")
    system = (
        "You are a local automotive cybersecurity assurance assistant for a synthetic APIM, GWM and TCU platform. "
        "Teach and support assessment campaigns, applicability, evidence requests, design effectiveness, implementation, "
        "operating effectiveness, findings, corrective action, retesting and residual-risk decisions. Connect STRIDE and "
        "applicable MITRE ATT&CK enrichment to TARA, ISO/SAE 21434 concepts, UN R155/R156, NIST CSF 2.0, ISO 27001, "
        "synthetic OEM policy and supplier requirements. Never claim certification, legal conformity or final authority. "
        "State assumptions, missing evidence and which human role must approve the decision."
    )
    payload = {
        "model": model,
        "prompt": f"{system}\n\nContext:\n{json.dumps(context, indent=2)}\n\nQuestion:\n{prompt}",
        "stream": False,
    }
    req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=45) as response:
            data = json.loads(response.read().decode("utf-8"))
            return str(data.get("response", "")).strip() or None
    except (urllib.error.URLError, TimeoutError, ValueError):
        return None


def advise(prompt: str, context: dict[str, Any]) -> dict[str, str]:
    local = _ollama(prompt, context)
    if local:
        return {"engine": "Local Ollama", "answer": local}

    text = f"{prompt} {json.dumps(context)}".lower()
    if "applicab" in text:
        answer = (
            "Start with architecture and scope. A requirement is applicable when its outcome is relevant to the assessed "
            "component, interface, lifecycle phase or organizational process. Document the specific attack surface or process "
            "that makes it relevant. Use 'Indirect / organizational' when the obligation applies to the program rather than "
            "to firmware behavior. A 'Not applicable' decision needs a defensible boundary and reviewer approval."
        )
    elif "evidence request" in text or "evidence plan" in text:
        answer = (
            "Define sufficient evidence before reviewing what engineering submitted. Request architecture and version scope, "
            "the approved requirement/control design, implementation or configuration evidence, a repeatable test procedure, "
            "raw result evidence, and approval records. For GWM diagnostic isolation, request both denied UDS traffic and proof "
            "of local logging, fleet reporting and end-to-end correlation."
        )
    elif "design" in text and "effect" in text:
        answer = (
            "Assess three separate layers: **Design effectiveness** asks whether the control would address the requirement if "
            "implemented as described. **Implementation** asks whether it exists in the scoped software/configuration baseline. "
            "**Operating effectiveness** asks whether representative evidence shows it performs consistently. Do not mark the "
            "overall requirement Met when any required layer is only partial or unsupported."
        )
    elif "quality" in text or "sufficient" in text:
        answer = (
            "Score evidence for relevance, authenticity, completeness, currency and scope. A log can be highly relevant but still "
            "be incomplete if it proves only one test case, lacks the software version, or omits centralized alerting. Low scores "
            "should drive 'Insufficient evidence' or 'Partially Met,' not an optimistic Met conclusion."
        )
    elif "supplier" in text or "sbom" in text:
        answer = (
            "Supplier assurance should verify the artifact, release/version, origin and completeness. An SBOM supports inventory, "
            "but it does not by itself prove source-to-binary provenance, secure development, vulnerability disposition or release "
            "approval. Record missing artifacts as gaps, assign an owner, define a release gate and require resubmission or risk acceptance."
        )
    elif "audit" in text or "defend" in text:
        answer = (
            "Answer in this order: scope and baseline; applicability rationale; TARA or risk connection; required evidence; what the "
            "evidence proves; what it does not prove; assessment conclusion; finding and corrective action; retest and residual-risk approver. "
            "A mapping supports traceability but does not prove conformance with every mapped source."
        )
    elif "gwm" in text and ("0x34" in text or "diagnostic" in text):
        answer = (
            "Suggested overall conclusion: **Partially Met**. The design is effective and the implementation is present because the "
            "GWM denied unauthorized SecurityAccess and RequestDownload and did not forward traffic. Operating effectiveness is only "
            "partial because centralized fleet alerting and cross-module correlation are not demonstrated. Retain the deny behavior, "
            "add a shared event ID and fleet alert, then repeat the end-to-end test."
        )
    elif "profile" in text or "current" in text and "target" in text:
        answer = (
            "Use the Current Profile to state the evidenced present condition and the Target Profile to state the required outcome. "
            "The gap is not merely a missing checkbox; it should name the engineering or process difference and the action needed to close it."
        )
    else:
        answer = (
            "Work the campaign in sequence: define scope and software baseline; decide applicability; plan sufficient evidence; assess "
            "control design, implementation and operating effectiveness; evaluate evidence quality; record the overall status; create a "
            "finding and corrective action; retest; and route residual risk to the authorized approver."
        )
    answer = re.sub(r"\bcertified\b", "assessed", answer, flags=re.I)
    return {"engine": "Built-in local assurance guidance", "answer": answer}
