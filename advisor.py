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
        "Support release comparison, change-impact analysis, TARA traceability, evidence staleness, vulnerability and SBOM "
        "disposition, detection engineering, cybersecurity-case reasoning, compliance campaigns, retesting, and release gates. "
        "Never claim certification, Ford internal knowledge, legal conformity, release authority, or final risk acceptance. "
        "State what evidence proves, what it does not prove, and which authorized human must decide."
    )
    payload = {
        "model": model,
        "prompt": f"{system}\n\nContext:\n{json.dumps(context, indent=2)}\n\nQuestion:\n{prompt}",
        "stream": False,
    }
    request = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=45) as response:
            data = json.loads(response.read().decode("utf-8"))
            return str(data.get("response", "")).strip() or None
    except (urllib.error.URLError, TimeoutError, ValueError):
        return None


def advise(prompt: str, context: dict[str, Any]) -> dict[str, str]:
    local = _ollama(prompt, context)
    if local:
        return {"engine": "Local Ollama", "answer": local}

    text = f"{prompt} {json.dumps(context)}".lower()
    if "change" in text and "impact" in text:
        answer = (
            "Start with the changed configuration item, then trace outward: interface and behavior changes → affected assets and "
            "TARA assumptions → cybersecurity goals and controls → requirements and mappings → evidence validity → detections and "
            "cybersecurity claims → release-gate decision. A change to the TCU can invalidate GWM evidence even when GWM software is unchanged."
        )
    elif "stale" in text or "evidence lifecycle" in text:
        answer = (
            "Evidence becomes stale when a material implementation, dependency, configuration, interface, test environment, requirement, "
            "or threat assumption changes. Preserve the old artifact as historical evidence, record why it no longer supports the candidate "
            "baseline, identify its replacement, and generate a version-specific retest."
        )
    elif "sbom" in text or "vulnerab" in text:
        answer = (
            "An SBOM match establishes that an affected component may be present. The engineer must still validate delivered-binary identity, "
            "reachability, exploitability in vehicle context, existing mitigations, affected TARA paths, required monitoring, and remediation. "
            "An unresolved High or Critical issue should block or condition the release unless authorized residual risk is documented."
        )
    elif "detection" in text or "telemetry" in text:
        answer = (
            "Translate the attack path into observable events. Define required telemetry, timestamps, identifiers, correlation window, logic, "
            "severity, expected alert, response playbook, and validation test. A local log is not equivalent to one actionable fleet incident."
        )
    elif "claim" in text or "cybersecurity case" in text:
        answer = (
            "A cybersecurity case is a structured argument: top-level acceptability claim → supporting technical or process claims → objective "
            "evidence → assumptions and unresolved gaps. Mark a claim unsupported or revalidation-required when its evidence is stale or a new "
            "release changes the underlying control."
        )
    elif "release gate" in text or "approve" in text:
        answer = (
            "Calculate posture from mandatory evidence, unresolved vulnerabilities, open findings, detection validation, and cybersecurity claims. "
            "The tool may recommend Blocked, Conditional, or Ready for human approval. Only the designated release authority can approve the "
            "release or accept residual risk."
        )
    elif "applicab" in text:
        answer = (
            "Tie applicability to architecture, lifecycle, release scope, and risk. Re-evaluate applicability when interfaces or features change. "
            "A new APIM or TCU DoIP capability can make gateway diagnostic-isolation requirements newly applicable."
        )
    elif "design" in text and "effect" in text:
        answer = (
            "Assess design effectiveness, implementation, and operating effectiveness separately. Version 3 adds a fourth question: is the "
            "evidence still valid for this candidate baseline? A previously effective control still requires retest when its interacting source changes."
        )
    else:
        answer = (
            "Use the continuous-assurance sequence: compare baseline and candidate; identify material changes; trace affected TARA, controls, "
            "requirements and claims; invalidate stale evidence; analyze SBOM and vulnerabilities; update detections; obtain current retest evidence; "
            "reassess residual risk; and route the calculated release posture to the authorized human approver."
        )
    answer = re.sub(r"\bcertified\b", "assessed", answer, flags=re.I)
    return {"engine": "Built-in local continuous-assurance guidance", "answer": answer}
