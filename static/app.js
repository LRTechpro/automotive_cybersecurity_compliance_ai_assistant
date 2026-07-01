'use strict';

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
const state = {
  data: null,
  releaseCode: localStorage.getItem('autocyber-release') || 'REL-TCU-53',
  mode: localStorage.getItem('autocyber-mode') || 'guided',
  comparison: null,
  impact: null,
  gate: null,
};

const esc = value => String(value ?? '').replace(/[&<>'"]/g, char => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[char]));
const slug = value => String(value ?? '').replace(/[^A-Za-z0-9_-]/g, '-');
const splitCodes = value => String(value || '').split(';').map(x => x.trim()).filter(Boolean);

async function api(url, options = {}) {
  const response = await fetch(url, {headers: {'Content-Type': 'application/json'}, ...options});
  const type = response.headers.get('content-type') || '';
  const payload = type.includes('application/json') ? await response.json() : await response.text();
  if (!response.ok) throw new Error(payload.error || payload || `Request failed: ${response.status}`);
  return payload;
}

function notify(message, error = false) {
  const el = $('#notice');
  el.textContent = message;
  el.className = `notice ${error ? 'error' : 'success'}`;
  clearTimeout(notify.timer);
  notify.timer = setTimeout(() => el.classList.add('hidden'), 4500);
}

function statusBadge(value) {
  const cls = String(value || '').toLowerCase().includes('block') || String(value || '').toLowerCase().includes('stale') || String(value || '').toLowerCase().includes('open') || String(value || '').toLowerCase().includes('unsupported') || String(value || '').toLowerCase().includes('fail')
    ? 'status-Not'
    : String(value || '').toLowerCase().includes('partial') || String(value || '').toLowerCase().includes('pending') || String(value || '').toLowerCase().includes('retest') || String(value || '').toLowerCase().includes('conditional')
      ? 'status-Partially'
      : 'status-Met';
  return `<span class="status-badge ${cls}">${esc(value)}</span>`;
}

function riskBadge(value) {
  return `<span class="risk-badge risk-${esc(value)}">${esc(value)}</span>`;
}

function table(headers, rows) {
  return `<table><thead><tr>${headers.map(h => `<th>${esc(h)}</th>`).join('')}</tr></thead><tbody>${rows.join('')}</tbody></table>`;
}

function details(items) {
  return `<div class="detail-grid">${items.map(([label, value]) => `<div class="detail-row"><span>${esc(label)}</span><div>${value}</div></div>`).join('')}</div>`;
}

function currentRelease() {
  return state.data.software_releases.find(item => item.release_code === state.releaseCode) || state.data.software_releases[0];
}

function setMode(mode) {
  state.mode = mode;
  localStorage.setItem('autocyber-mode', mode);
  document.body.classList.toggle('analyst-mode', mode === 'analyst');
  $('#modeSelect').value = mode;
}

function switchView(view) {
  $$('.view').forEach(item => item.classList.toggle('active', item.id === `view-${view}`));
  $$('.nav-item').forEach(item => item.classList.toggle('active', item.dataset.view === view));
  const active = $(`.nav-item[data-view="${view}"]`);
  $('#pageTitle').textContent = active ? active.textContent : 'AutoCyber';
  window.scrollTo({top: 0, behavior: 'smooth'});
}

async function loadData() {
  state.data = await api('/api/bootstrap?campaign_id=1');
  if (!state.data.software_releases.some(r => r.release_code === state.releaseCode)) state.releaseCode = 'REL-TCU-53';
  await loadReleaseViews();
  renderAll();
}

async function loadReleaseViews() {
  const candidate = state.releaseCode;
  const base = candidate === 'REL-TCU-53' ? 'REL-TCU-52' : candidate;
  state.comparison = await api(`/api/release-comparison?base=${encodeURIComponent(base)}&candidate=${encodeURIComponent(candidate)}`);
  state.impact = await api(`/api/change-impact?release_code=${encodeURIComponent(candidate)}`);
  state.gate = await api(`/api/release-gate?release_code=${encodeURIComponent(candidate)}`);
}

function populateSelects() {
  const releases = state.data.software_releases;
  const options = releases.map(r => `<option value="${esc(r.release_code)}">${esc(r.release_code)} · ${esc(r.component_code)} ${esc(r.version)} · ${esc(r.status)}</option>`).join('');
  $('#releaseSelect').innerHTML = options;
  $('#releaseSelect').value = state.releaseCode;
  $('#baseRelease').innerHTML = options;
  $('#candidateRelease').innerHTML = options;
  $('#baseRelease').value = state.releaseCode === 'REL-TCU-53' ? 'REL-TCU-52' : state.releaseCode;
  $('#candidateRelease').value = state.releaseCode;
  $('#exportLink').href = `/api/export?campaign_id=1&release_code=${encodeURIComponent(state.releaseCode)}`;
  $('#frameworkFilter').innerHTML = `<option value="">All sources</option>${state.data.frameworks.map(f => `<option value="${esc(f.framework_code)}">${esc(f.name)}</option>`).join('')}`;
}

function renderMetrics() {
  const m = state.data.metrics;
  const metrics = [
    ['Candidate releases', m.candidate_releases],
    ['Open change impacts', m.open_change_impacts],
    ['Stale gate evidence', m.stale_evidence],
    ['High vulnerabilities', m.open_high_vulnerabilities],
    ['Unsupported claims', m.unsupported_claims],
    ['Framework sources', m.framework_sources],
  ];
  $('#metrics').innerHTML = metrics.map(([label, value]) => `<div class="metric"><strong>${esc(value)}</strong><span>${esc(label)}</span></div>`).join('');
}

function renderDashboard() {
  const release = currentRelease();
  const gate = state.gate;
  $('#dashboardReleaseTitle').textContent = `${release.release_code} · ${release.component_code} ${release.version}`;
  const cards = [
    ['Release posture', gate.status, gate.recommendation],
    ['Mandatory evidence gaps', gate.counts.stale_evidence, 'Stale, pending, or retest-required artifacts'],
    ['Open high vulnerabilities', gate.counts.high_vulnerabilities, 'Vehicle-context disposition required'],
    ['Detection gaps', gate.counts.unvalidated_detections, 'Analytics not fully validated'],
    ['Cybersecurity claims', gate.counts.unsupported_claims, 'Claims not fully supported for candidate'],
  ];
  $('#dashboardPosture').innerHTML = cards.map(([label, value, note], index) => `<div class="posture-card ${index === 0 && gate.status === 'Blocked' ? 'gap-High' : index > 0 && Number(value) > 0 ? 'gap-High' : 'gap-Low'}"><span>${esc(label)}</span><strong>${index === 0 ? statusBadge(value) : esc(value)}</strong><small>${esc(note)}</small></div>`).join('');
}

function renderReleases() {
  const c = state.comparison;
  $('#releaseSummary').innerHTML = [c.base, c.candidate].map((r, i) => `<article class="panel"><span class="eyebrow">${i ? 'Candidate' : 'Approved baseline'}</span><h3>${esc(r.release_code)} · ${esc(r.component_code)} ${esc(r.version)}</h3>${details([['Status', statusBadge(r.status)], ['Baseline', esc(r.baseline_code)], ['Release date', esc(r.release_date)], ['Supplier/team', esc(r.supplier)], ['Notes', esc(r.notes)]])}</article>`).join('');
  $('#releaseChanges').innerHTML = table(['Change', 'Type', 'Description', 'Affected controls', 'Affected TARA', 'Retest'], c.changes.map(x => `<tr><td><b>${esc(x.change_code)}</b><br>${esc(x.title)}</td><td>${esc(x.change_type)}</td><td>${esc(x.description)}</td><td>${splitCodes(x.affected_controls).map(code => `<span class="pill">${esc(code)}</span>`).join(' ')}</td><td>${splitCodes(x.affected_tara).map(code => `<span class="pill">${esc(code)}</span>`).join(' ')}</td><td>${statusBadge(x.requires_retest === 'Yes' ? 'Retest required' : 'Review')}</td></tr>`));
  $('#sbomDiff').innerHTML = table(['Component', 'Approved', 'Candidate', 'Change', 'Vulnerability', 'Status'], c.sbom_diff.map(x => `<tr><td><b>${esc(x.component_name)}</b></td><td>${esc(x.before)}</td><td>${esc(x.after)}</td><td>${statusBadge(x.change)}</td><td>${esc(x.known_vulnerability)}</td><td>${statusBadge(x.status)}</td></tr>`));
}

function renderImpacts() {
  const changes = state.impact.changes;
  const impacts = state.impact.impacts;
  $('#impactCards').innerHTML = changes.map(change => {
    const linked = impacts.filter(i => i.source_change_code === change.change_code);
    return `<article class="trace-card"><div class="trace-card-header"><div><span class="eyebrow">${esc(change.change_type)}</span><h3>${esc(change.change_code)} · ${esc(change.title)}</h3></div>${statusBadge(change.requires_retest === 'Yes' ? 'Retest required' : 'Review')}</div><p>${esc(change.description)}</p><p class="callout">${esc(change.cybersecurity_impact)}</p><div class="impact-grid">${linked.map(i => `<div class="impact-node"><span>${esc(i.impact_type)}</span><b>${esc(i.target_code)}</b><p>${esc(i.target_title)}</p><small>${esc(i.action)}</small>${statusBadge(i.status)}</div>`).join('')}</div></article>`;
  }).join('');
}

function renderVulnerabilities() {
  const sbom = state.data.sbom_components.filter(x => x.release_code === state.releaseCode);
  $('#sbomTable').innerHTML = table(['Component', 'Version', 'Supplier', 'Known vulnerability', 'Status'], sbom.map(x => `<tr><td><b>${esc(x.component_name)}</b><br><small>${esc(x.purl)}</small></td><td>${esc(x.version)}</td><td>${esc(x.supplier)}</td><td>${esc(x.known_vulnerability)}</td><td>${statusBadge(x.status)}</td></tr>`));
  const vulns = state.data.vulnerabilities.filter(x => x.release_code === state.releaseCode || x.component_code === currentRelease().component_code);
  $('#vulnerabilityTable').innerHTML = table(['Vulnerability', 'Library/version', 'Severity', 'Vehicle context', 'Traceability', 'Disposition'], vulns.map(v => `<tr><td><b>${esc(v.vuln_code)}</b><br>${statusBadge(v.status)}</td><td>${esc(v.affected_component)} ${esc(v.affected_versions)}</td><td>${riskBadge(v.severity)}<br>CVSS ${esc(v.cvss)}</td><td><b>Reachability:</b> ${esc(v.reachability)}<br><b>Exploitability:</b> ${esc(v.exploitability)}</td><td>${esc(v.linked_tara)}<br>${esc(v.linked_control)}</td><td>${esc(v.remediation)}<br><small>Due ${esc(v.due_date)}</small></td></tr>`));
}

function renderLifecycle() {
  const records = state.data.evidence_lifecycle.filter(x => x.release_code === state.releaseCode);
  $('#lifecycleTable').innerHTML = table(['Evidence', 'Component', 'Valid for', 'Current status', 'Reason', 'Replacement', 'Gate'], records.map(x => `<tr><td><b>${esc(x.evidence_code)}</b></td><td>${esc(x.component_code)}</td><td>${esc(x.valid_for_version)}</td><td>${statusBadge(x.status)}<br><small>Review ${esc(x.review_due)}</small></td><td>${esc(x.stale_reason)}</td><td>${esc(x.superseded_by || '—')}</td><td>${x.required_for_gate === 'Yes' ? '<span class="pill">Required</span>' : 'Supporting'}</td></tr>`));
}

function renderIngest() {
  $('#ingestTable').innerHTML = table(['Artifact', 'Type', 'Component/release', 'Hash', 'Status'], state.data.ingested_artifacts.map(x => `<tr><td><b>${esc(x.artifact_code)}</b><br>${esc(x.file_name)}</td><td>${esc(x.artifact_type)}</td><td>${esc(x.component_code)}<br>${esc(x.release_code)}</td><td class="hash">${esc(x.sha256)}</td><td>${statusBadge(x.analyst_status)}</td></tr>`));
}

function renderDetections() {
  $('#detectionCards').innerHTML = state.data.detection_rules.map(rule => `<article class="evaluation-card"><div class="card-header"><div><span class="eyebrow">${esc(rule.component_code)} · ${esc(rule.severity)}</span><h3>${esc(rule.rule_code)} · ${esc(rule.title)}</h3></div>${statusBadge(rule.validation_status)}</div>${details([['Behavior', esc(rule.behavior)], ['Telemetry', esc(rule.telemetry_sources)], ['Logic', esc(rule.logic_summary)], ['Linked TARA', esc(rule.linked_tara)], ['Last tested', esc(rule.last_tested)], ['Response', esc(rule.response_playbook)]])}</article>`).join('');
}

function claimChildren(parent) {
  return state.data.cybersecurity_claims.filter(c => c.parent_claim_code === parent);
}

function renderClaim(claim) {
  const evidence = state.data.claim_evidence.filter(e => e.claim_code === claim.claim_code);
  const children = claimChildren(claim.claim_code);
  return `<article class="claim-card claim-${esc(claim.claim_type)}"><div class="card-header"><div><span class="eyebrow">${esc(claim.claim_type)}</span><h3>${esc(claim.claim_code)} · ${esc(claim.title)}</h3></div>${statusBadge(claim.status)}</div><p>${esc(claim.statement)}</p><p class="callout muted">${esc(claim.rationale)}</p>${evidence.length ? `<div class="claim-evidence"><b>Evidence relationship</b>${evidence.map(e => `<span>${esc(e.evidence_code)} · ${esc(e.support_type)} — ${esc(e.notes)}</span>`).join('')}</div>` : ''}${children.length ? `<div class="claim-children">${children.map(renderClaim).join('')}</div>` : ''}</article>`;
}

function renderCase() {
  $('#claimTree').innerHTML = claimChildren('').map(renderClaim).join('');
}

function renderGate() {
  const g = state.gate;
  $('#gateSummary').innerHTML = `<div class="gate-banner gate-${slug(g.status)}"><div><span class="eyebrow">Calculated posture</span><h2>${esc(g.release.release_code)} · ${statusBadge(g.status)}</h2><p>${esc(g.recommendation)}</p></div><div class="gate-counts"><span><b>${g.counts.stale_evidence}</b> evidence gaps</span><span><b>${g.counts.high_vulnerabilities}</b> high vulnerabilities</span><span><b>${g.counts.unvalidated_detections}</b> detection gaps</span><span><b>${g.counts.unsupported_claims}</b> unsupported claims</span></div></div><article class="panel"><span class="eyebrow">Calculated blockers</span><h3>What prevents approval now?</h3><ul class="clean-list">${g.blockers.length ? g.blockers.map(x => `<li>${esc(x)}</li>`).join('') : '<li>No calculated blockers.</li>'}</ul></article>`;
  $('#gateBlockers').value = g.blockers.join('\n');
  $('#gateConditions').value = 'Resolve or formally mitigate high vulnerabilities; approve current certificate and DoIP/UDS regression evidence; validate one correlated fleet incident; update cybersecurity claims; obtain authorized residual-risk decision.';
  $('#gateStatus').value = g.status === 'Blocked' ? 'Blocked' : g.status === 'Conditional' ? 'Conditional' : 'Pending authority';
}

function renderCampaign() {
  const c = state.data.campaigns[0];
  $('#campaignDetail').innerHTML = `<span class="eyebrow">${esc(c.campaign_code)}</span><h3>${esc(c.title)}</h3>${details([['Objective', esc(c.objective)], ['Vehicle program', esc(c.vehicle_program)], ['Model year', esc(c.model_year)], ['Scope', esc(c.scope)], ['Baseline', esc(c.software_baseline)], ['Period', `${esc(c.period_start)} to ${esc(c.period_end)}`], ['Assessor', esc(c.assessor)], ['Approver', esc(c.approver)], ['Status', statusBadge(c.status)]])}`;
  $('#campaignComponents').innerHTML = table(['Component', 'Version', 'Environment', 'In scope', 'Notes'], state.data.campaign_components.map(x => `<tr><td><b>${esc(x.component_code)}</b></td><td>${esc(x.software_version)}</td><td>${esc(x.environment)}</td><td>${statusBadge(x.in_scope)}</td><td>${esc(x.notes)}</td></tr>`));
}

function renderComponent(code) {
  const c = state.data.components.find(x => x.code === code);
  if (!c) {
    $('#componentDetail').innerHTML = `<span class="eyebrow">Context node</span><h3>${esc(code)}</h3><p>This node provides system context but is outside the three-module assessment boundary.</p>`;
    return;
  }
  const assets = state.data.assets.filter(a => a.component_code === code);
  const threats = state.data.threats.filter(t => t.component_code === code);
  const releases = state.data.software_releases.filter(r => r.component_code === code);
  $('#componentDetail').innerHTML = `<span class="eyebrow">${esc(c.role)}</span><h3>${esc(c.code)} · ${esc(c.name)}</h3>${details([['Description', esc(c.description)], ['Interfaces', esc(c.external_interfaces)], ['Security focus', esc(c.security_focus)], ['Releases', releases.map(r => `${esc(r.version)} (${esc(r.status)})`).join('<br>')], ['Assets', assets.map(a => `${esc(a.asset_code)} — ${esc(a.name)}`).join('<br>')], ['Threats', threats.map(t => `${esc(t.threat_code)} — ${esc(t.title)}`).join('<br>')]])}`;
}

function renderTara() {
  $('#taraCards').innerHTML = state.data.tara.map(t => `<article class="trace-card"><div class="trace-card-header"><div><span class="eyebrow">${esc(t.component_code)}</span><h3>${esc(t.tara_code)}</h3></div>${riskBadge(t.initial_risk)}</div><div class="trace-chain"><div class="trace-step"><span>Damage</span><p>${esc(t.damage_scenario)}</p></div><div class="trace-step"><span>Attack path</span><p>${esc(t.attack_path)}</p></div><div class="trace-step"><span>Assessment</span><p>${esc(t.impact)} impact · ${esc(t.feasibility)} feasibility</p></div><div class="trace-step"><span>Goal</span><p>${esc(t.cybersecurity_goal)}</p></div><div class="trace-step"><span>Residual</span><p>${esc(t.residual_risk)}</p></div></div>${state.data.change_impacts.some(i => i.target_code === t.tara_code && i.release_code === state.releaseCode) ? '<p class="callout">This TARA record is affected by the selected release and requires reassessment.</p>' : ''}</article>`).join('');
}

function renderCrosswalk() {
  const search = ($('#crosswalkSearch').value || '').toLowerCase();
  const framework = $('#frameworkFilter').value;
  const list = state.data.mappings.filter(x => (!framework || x.framework_code === framework) && (!search || JSON.stringify(x).toLowerCase().includes(search)));
  $('#crosswalkTable').innerHTML = table(['Control', 'Source', 'Requirement', 'Relationship', 'Confidence', 'Rationale'], list.map(x => `<tr><td><b>${esc(x.control_code)}</b><br>${esc(x.control_title)}</td><td>${esc(x.framework_name)}<br><small>${esc(x.source_type)}</small></td><td><b>${esc(x.requirement_code)}</b><br>${esc(x.reference)}<br>${esc(x.requirement_title)}</td><td>${esc(x.relationship)}</td><td>${statusBadge(x.confidence)}</td><td>${esc(x.rationale)}</td></tr>`));
}

function renderEvaluations() {
  $('#evaluationCards').innerHTML = state.data.control_evaluations.map(e => {
    const score = ['evidence_relevance','evidence_authenticity','evidence_completeness','evidence_currency','evidence_scope'].reduce((sum, k) => sum + Number(e[k] || 0), 0);
    return `<article class="evaluation-card"><div class="card-header"><div><span class="eyebrow">${esc(e.component_code)} · Evaluation ${e.id}</span><h3>${esc(e.requirement_code)} → ${esc(e.control_code)}</h3></div>${statusBadge(e.overall_status)}</div>${details([['Design', statusBadge(e.design_status)], ['Implementation', statusBadge(e.implementation_status)], ['Operating effectiveness', statusBadge(e.effectiveness_status)], ['Evidence', esc(e.evidence_codes)], ['Evidence quality', `${score}/25`], ['Rationale', esc(e.rationale)], ['Recommendation', esc(e.recommendation)]])}</article>`;
  }).join('');
}

function renderFindings() {
  const actions = state.data.corrective_actions;
  $('#findingCards').innerHTML = state.data.findings.map(f => `<article class="finding-card"><div class="card-header"><div><span class="eyebrow">Finding ${f.id} · ${esc(f.severity)}</span><h3>${esc(f.title)}</h3></div>${statusBadge(f.status)}</div>${details([['Owner', esc(f.owner)], ['Due', esc(f.due_date)], ['Recommendation', esc(f.recommendation)], ['Residual risk', riskBadge(f.residual_risk)]])}${actions.filter(a => Number(a.finding_id) === Number(f.id)).map(a => `<div class="action-card"><b>${esc(a.action_code)} · ${esc(a.status)}</b><p>${esc(a.action_plan)}</p><small>Retest: ${esc(a.retest_status)} — ${esc(a.retest_notes)}</small></div>`).join('')}</article>`).join('');
}

function renderInterview() {
  const steps = [
    ['Define the approved and candidate baselines', 'TCU 5.2 is approved; TCU 5.3 changes certificate validation, DoIP behavior, and telemetry schema.'],
    ['Show the release comparison', 'Explain the dependency and SBOM differences rather than treating the release as one opaque binary.'],
    ['Run change-impact analysis', 'Trace changes to TARA-TCU-001/002, GWM and TCU controls, requirements, evidence, detections, and claims.'],
    ['Explain evidence staleness', 'Prior evidence remains historically useful but is insufficient for the changed candidate baseline.'],
    ['Triage the SBOM vulnerability', 'Presence is confirmed; reachability and exploitability require vehicle-context analysis; release remains blocked.'],
    ['Review detection engineering', 'The TCU emits a shared event ID, but GWM/fleet mapping does not yet produce one correlated incident.'],
    ['Defend the cybersecurity case', 'Diagnostic, identity, and monitoring claims are not all supported for the candidate release.'],
    ['Calculate the release gate', 'High vulnerability plus mandatory evidence and detection gaps produce a Blocked posture.'],
    ['Close with human authority', 'The tool proposes posture and actions; the authorized release authority decides and accepts residual risk.'],
  ];
  $('#walkthroughSteps').innerHTML = steps.map(([title, body], i) => `<article class="walk-step"><b>${i + 1}</b><h3>${esc(title)}</h3><p>${esc(body)}</p></article>`).join('');
}

function renderAll() {
  populateSelects();
  renderMetrics();
  renderDashboard();
  renderReleases();
  renderImpacts();
  renderVulnerabilities();
  renderLifecycle();
  renderIngest();
  renderDetections();
  renderCase();
  renderGate();
  renderCampaign();
  renderTara();
  renderCrosswalk();
  renderEvaluations();
  renderFindings();
  renderInterview();
  const date = new Date(Date.now() + 7 * 86400000).toISOString().slice(0, 10);
  if (!$('#vDue').value) $('#vDue').value = date;
}

async function recalculate() {
  state.impact = await api('/api/analyze-release', {method: 'POST', body: JSON.stringify({release_code: state.releaseCode})});
  state.gate = state.impact.gate;
  state.data = await api('/api/bootstrap?campaign_id=1');
  renderAll();
  notify('Change-impact and release-gate posture recalculated.');
}

function bindEvents() {
  $$('.nav-item').forEach(button => button.addEventListener('click', () => switchView(button.dataset.view)));
  $$('[data-jump]').forEach(button => button.addEventListener('click', () => switchView(button.dataset.jump)));
  $('#modeSelect').addEventListener('change', event => setMode(event.target.value));
  $('#releaseSelect').addEventListener('change', async event => {
    state.releaseCode = event.target.value;
    localStorage.setItem('autocyber-release', state.releaseCode);
    await loadReleaseViews();
    renderAll();
  });
  $('#compareRelease').addEventListener('click', async () => {
    const base = $('#baseRelease').value;
    const candidate = $('#candidateRelease').value;
    state.releaseCode = candidate;
    state.comparison = await api(`/api/release-comparison?base=${encodeURIComponent(base)}&candidate=${encodeURIComponent(candidate)}`);
    state.impact = await api(`/api/change-impact?release_code=${encodeURIComponent(candidate)}`);
    state.gate = await api(`/api/release-gate?release_code=${encodeURIComponent(candidate)}`);
    $('#releaseSelect').value = candidate;
    renderAll();
    notify('Baseline comparison updated.');
  });
  $('#analyzeRelease').addEventListener('click', () => recalculate().catch(error => notify(error.message, true)));
  $('#dashboardAnalyze').addEventListener('click', () => recalculate().catch(error => notify(error.message, true)));
  $('#refreshGate').addEventListener('click', async () => {
    state.gate = await api(`/api/release-gate?release_code=${encodeURIComponent(state.releaseCode)}`);
    renderGate();
    notify('Release-gate posture recalculated.');
  });
  $$('.arch-node').forEach(button => button.addEventListener('click', () => renderComponent(button.dataset.component)));
  $('#crosswalkSearch').addEventListener('input', renderCrosswalk);
  $('#frameworkFilter').addEventListener('change', renderCrosswalk);

  $('#ingestForm').addEventListener('submit', async event => {
    event.preventDefault();
    try {
      const result = await api('/api/ingest', {method: 'POST', body: JSON.stringify({
        artifact_type: $('#ingestType').value,
        component_code: $('#ingestComponent').value,
        release_code: state.releaseCode,
        file_name: $('#ingestName').value,
        content: $('#ingestContent').value,
      })});
      $('#ingestResult').className = 'callout';
      $('#ingestResult').innerHTML = `<b>${esc(result.artifact_code)}</b><br><span class="hash">SHA-256 ${esc(result.sha256)}</span><pre>${esc(JSON.stringify(result.parsed, null, 2))}</pre>`;
      state.data = await api('/api/bootstrap?campaign_id=1');
      renderIngest();
      notify('Artifact parsed, hashed, and stored locally for analyst confirmation.');
    } catch (error) { notify(error.message, true); }
  });

  $('#vulnerabilityForm').addEventListener('submit', async event => {
    event.preventDefault();
    try {
      await api('/api/vulnerabilities', {method: 'POST', body: JSON.stringify({
        vuln_code: $('#vCode').value,
        release_code: state.releaseCode,
        component_code: $('#vComponent').value,
        affected_component: $('#vLibrary').value,
        affected_versions: $('#vVersion').value,
        severity: $('#vSeverity').value,
        cvss: Number($('#vCvss').value),
        reachability: $('#vReach').value,
        exploitability: $('#vExploit').value,
        status: $('#vStatus').value,
        linked_tara: $('#vTara').value,
        linked_control: $('#vControl').value,
        remediation: $('#vRemediation').value,
        due_date: $('#vDue').value,
      })});
      state.data = await api('/api/bootstrap?campaign_id=1');
      state.gate = await api(`/api/release-gate?release_code=${encodeURIComponent(state.releaseCode)}`);
      renderVulnerabilities(); renderMetrics(); renderGate();
      notify('Vulnerability added and release-gate posture updated.');
    } catch (error) { notify(error.message, true); }
  });

  $('#gateForm').addEventListener('submit', async event => {
    event.preventDefault();
    try {
      await api('/api/release-gates', {method: 'POST', body: JSON.stringify({
        release_code: state.releaseCode,
        decision: $('#gateDecision').value,
        decision_status: $('#gateStatus').value,
        blockers: $('#gateBlockers').value,
        conditions: $('#gateConditions').value,
        residual_risk: $('#gateRisk').value,
        approver: $('#gateApprover').value,
        approved_at: $('#gateApproved').value,
        notes: $('#gateNotes').value,
      })});
      state.data = await api('/api/bootstrap?campaign_id=1');
      state.gate = await api(`/api/release-gate?release_code=${encodeURIComponent(state.releaseCode)}`);
      renderGate();
      notify('Human release decision recorded in the local audit trail.');
    } catch (error) { notify(error.message, true); }
  });
}

async function init() {
  try {
    setMode(state.mode);
    bindEvents();
    await loadData();
  } catch (error) {
    notify(error.message, true);
    console.error(error);
  }
}

init();
