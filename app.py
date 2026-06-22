"""Streamlit prototype for the AI Automotive Cybersecurity Incident & Compliance Assistant.

Assignment 5.2: live AI feature added in ai.py. The Streamlit app calls reusable
functions from db.py instead of placing SQL directly in app.py.
"""

import html
from datetime import datetime

import streamlit as st

from db import (
    get_ai_context_for_incident,
    get_all_incidents,
    get_control_summary,
    get_incident_counts_by_severity,
    get_incident_overview,
    get_incidents_by_severity,
    get_incidents_with_assets,
    get_kpi_summary,
    get_open_mitigations,
)
from ai import generate_incident_summary

st.set_page_config(
    page_title="AI Automotive Cybersecurity Incident & Compliance Assistant",
    page_icon="🚗",
    layout="wide",
)

st.markdown(
    """
    <style>
    .block-container { padding-top: 2.5rem; padding-bottom: 2rem; }
    .small-note { color: #9ca3af; font-size: 0.92rem; }
    .wrapped-table { width: 100%; border-collapse: collapse; table-layout: fixed; margin-bottom: 1.4rem; font-size: 0.86rem; }
    .wrapped-table th { background-color: #1f2937; color: #f9fafb; font-weight: 700; text-align: left; padding: 0.55rem; border: 1px solid #374151; white-space: normal; overflow-wrap: anywhere; vertical-align: top; }
    .wrapped-table td { padding: 0.55rem; border: 1px solid #374151; white-space: normal; overflow-wrap: anywhere; vertical-align: top; line-height: 1.35; }
    .wrapped-table tr:nth-child(even) td { background-color: rgba(255, 255, 255, 0.025); }
    .table-scroll { width: 100%; overflow-x: visible; }
    .col-compact { width: 4rem; text-align: center; }
    .col-id { width: 4.8rem; text-align: center; }
    .col-date { width: 8rem; }
    .col-short { width: 7.5rem; }
    .col-medium { width: 10rem; }
    .col-long { width: 18rem; }
    .detail-card {
        border: 1px solid rgba(156, 163, 175, 0.35);
        border-radius: 8px;
        padding: 1rem 1.15rem;
        margin-bottom: 1rem;
        background: rgba(255, 255, 255, 0.03);
    }
    .detail-card h4 { margin: 0 0 0.7rem 0; }
    .detail-card p { margin: 0.45rem 0; line-height: 1.45; }
    .item-card {
        border: 1px solid rgba(156, 163, 175, 0.28);
        border-radius: 8px;
        padding: 0.9rem 1rem;
        margin-bottom: 0.85rem;
        background: rgba(255, 255, 255, 0.025);
    }
    .item-card p { margin: 0.35rem 0; line-height: 1.45; overflow-wrap: anywhere; }
    .item-card .field-label { font-weight: 700; }
    .brief-card {
        border: 1px solid rgba(156, 163, 175, 0.28);
        border-radius: 12px;
        padding: 1rem 1.05rem;
        margin-bottom: 0.85rem;
        background: linear-gradient(145deg, rgba(255,255,255,0.045), rgba(255,255,255,0.018));
        min-height: 11rem;
    }
    .brief-card h4 { margin: 0 0 0.6rem 0; font-size: 1.02rem; }
    .brief-card p { margin: 0; line-height: 1.58; }
    .brief-recommendation { border-left: 5px solid #22c55e; }
    .brief-missing { border-left: 5px solid #f59e0b; }
    .record-grid-card {
        border: 1px solid rgba(156, 163, 175, 0.28);
        border-radius: 10px;
        padding: 0.9rem 1rem;
        margin-bottom: 0.85rem;
        background: rgba(255, 255, 255, 0.025);
    }
    .record-grid-card h4 { margin: 0 0 0.7rem 0; }
    .record-grid-card .meta { color: #cbd5e1; font-size: 0.9rem; margin-bottom: 0.45rem; }
    .record-grid-card .body { line-height: 1.52; margin-top: 0.55rem; }
    .inc-grid {
        display: grid;
        grid-template-columns: repeat(4, 1fr);
        gap: 0.45rem;
        margin-bottom: 1rem;
    }
    .inc-badge {
        border: 1px solid rgba(156,163,175,0.28);
        border-radius: 7px;
        padding: 0.45rem 0.65rem;
        background: rgba(255,255,255,0.03);
    }
    .inc-label {
        font-size: 0.62rem;
        color: #64748b;
        text-transform: uppercase;
        letter-spacing: 0.06em;
        margin-bottom: 0.15rem;
    }
    .inc-value {
        font-size: 0.88rem;
        font-weight: 700;
        color: #f1f5f9;
        overflow-wrap: anywhere;
    }
    .sev-critical { color: #f87171; }
    .sev-high     { color: #fb923c; }
    .sev-medium   { color: #facc15; }
    .sev-low      { color: #4ade80; }
    </style>
    """,
    unsafe_allow_html=True,
)

COMPACT_COLUMNS = {
    "likelihood", "impact", "risk_score", "model_year", "mapped_incident_count",
    "incident_count", "average_risk_score"
}
ID_COLUMNS = {"incident_id", "vehicle_id", "control_id", "risk_assessment_id", "evidence_id", "mitigation_id"}
DATE_COLUMNS = {"detected_at", "resolved_at", "collected_at", "due_date", "assessed_at"}
SHORT_COLUMNS = {"severity", "status", "risk_rating", "make", "ecu_zone", "attack_vector", "control_type", "framework_name", "evidence_type", "completion_status"}
LONG_COLUMNS = {"description", "tara_notes", "gap_notes", "action_description", "evidence_summary", "control_name", "control_description", "evidence_reference", "mitigation_summary", "linked_controls", "compliance_gaps"}
COLUMN_LABELS = {
    "incident_id": "ID",
    "vehicle_id": "Veh ID",
    "model_year": "Year",
    "connectivity_type": "Connectivity",
    "affected_component": "Component",
    "framework_name": "Framework",
    "clause_reference": "Control Ref",
    "mapped_incident_count": "Mapped",
    "action_description": "Action",
    "completion_status": "Status",
    "risk_score": "Risk Score",
    "tara_notes": "TARA Notes",
}


def _format_cell(value):
    if value is None:
        return ""
    value_text = str(value)
    if value_text.lower() == "nan":
        return ""
    return html.escape(value_text)


def _format_detail_value(value):
    """Return a safe display value for card fields."""
    if value is None:
        return ""
    value_text = str(value)
    if value_text.lower() == "nan":
        return ""
    return html.escape(value_text)


def _display_value(value):
    """Return a readable non-HTML value for native Streamlit field output."""
    if value is None:
        return "N/A"
    value_text = str(value)
    if value_text.strip() == "" or value_text.lower() in {"nan", "none", "<na>"}:
        return "N/A"
    return value_text


def _has_display_value(value):
    """Return True when a record field has meaningful display content."""
    return _display_value(value) != "N/A"


def _record_value(record, *keys):
    """Return the first present, non-empty value from a pandas row-like object."""
    for key in keys:
        if key in record and _has_display_value(record.get(key)):
            return _display_value(record.get(key))
    return "N/A"


def _write_labeled_value(label, value):
    """Write a professional label/value pair with natural text wrapping."""
    st.markdown(f"**{label}:**")
    st.write(value)


def _column_class(column_name):
    if column_name in COMPACT_COLUMNS:
        return "col-compact"
    if column_name in ID_COLUMNS:
        return "col-id"
    if column_name in DATE_COLUMNS:
        return "col-date"
    if column_name in LONG_COLUMNS:
        return "col-long"
    if column_name in SHORT_COLUMNS:
        return "col-short"
    return "col-medium"


def show_table(data, fallback_message="No records to display."):
    """Render a compact wrapped table for readable dashboard display."""
    if data is None or data.empty:
        st.info(fallback_message)
        return

    headers = "".join(
        f'<th class="{_column_class(str(column))}">{html.escape(COLUMN_LABELS.get(str(column), str(column)))}</th>'
        for column in data.columns
    )
    rows = []
    for _, row in data.iterrows():
        cells = "".join(
            f'<td class="{_column_class(str(column))}">{_format_cell(row[column])}</td>'
            for column in data.columns
        )
        rows.append(f"<tr>{cells}</tr>")

    rows_html = "\n".join(rows)
    table_html = f"""
    <div class="table-scroll">
        <table class="wrapped-table">
            <thead><tr>{headers}</tr></thead>
            <tbody>{rows_html}</tbody>
        </table>
    </div>
    """
    st.markdown(table_html, unsafe_allow_html=True)


def _render_record_card(title, metadata, body=None):
    """Render a compact card with a title, metadata rows, and optional body text."""
    meta_html = "".join(
        f'<div class="meta"><strong>{html.escape(label)}:</strong> {_format_detail_value(value)}</div>'
        for label, value in metadata
    )
    body_html = ""
    if body:
        body_html = f'<div class="body">{_format_detail_value(body)}</div>'
    st.markdown(
        f'<div class="record-grid-card"><h4>{html.escape(str(title))}</h4>{meta_html}{body_html}</div>',
        unsafe_allow_html=True,
    )


def show_controls_cards(controls):
    """Render mapped controls as compact cards in a two column layout."""
    if controls is None or controls.empty:
        st.info("No mapped controls found for this incident.")
        return

    columns = st.columns(2)
    for position, (_, row) in enumerate(controls.iterrows()):
        gap_value = _display_value(row.get("compliance_gap_identified"))
        gap_label = "Yes" if gap_value in {"1", "True", "true"} else "No"
        metadata = [
            ("Framework", _display_value(row.get("framework_name"))),
            ("Control Ref", _display_value(row.get("clause_reference"))),
            ("Type", _display_value(row.get("control_type"))),
            ("Compliance Gap", gap_label),
        ]
        with columns[position % 2]:
            _render_record_card(
                _display_value(row.get("control_name")),
                metadata,
                _display_value(row.get("gap_notes")),
            )


def show_evidence_cards(evidence):
    """Render evidence items as concise cards in a two column layout."""
    if evidence is None or evidence.empty:
        st.info("No evidence items found for this incident.")
        return

    columns = st.columns(2)
    for position, (_, row) in enumerate(evidence.iterrows()):
        metadata = [
            ("Reference", _display_value(row.get("evidence_reference"))),
            ("Collected", _display_value(row.get("collected_at"))),
        ]
        with columns[position % 2]:
            _render_record_card(
                _display_value(row.get("evidence_type")),
                metadata,
                _display_value(row.get("description")),
            )


def show_mitigation_cards(mitigations):
    """Render mitigation actions as concise cards in a two column layout."""
    if mitigations is None or mitigations.empty:
        st.info("No mitigation actions found for this incident.")
        return

    columns = st.columns(2)
    for position, (_, row) in enumerate(mitigations.iterrows()):
        metadata = [
            ("Owner", _display_value(row.get("owner"))),
            ("Due Date", _display_value(row.get("due_date"))),
            ("Status", _display_value(row.get("completion_status"))),
        ]
        with columns[position % 2]:
            _render_record_card(
                "Mitigation Action",
                metadata,
                _display_value(row.get("action_description")),
            )


AI_BRIEF_HEADINGS = [
    "Incident Summary",
    "Affected Vehicle & ECU Zone",
    "Attack Vector & Severity Rationale",
    "Risk Score Justification",
    "Mapped Compliance Controls",
    "Evidence Status",
    "Open Mitigations",
    "Recommended Next Action",
    "Missing Evidence",
]


def parse_ai_brief(ai_brief):
    """Parse the fixed nine section AI response into display cards."""
    sections = {}
    current_heading = None
    current_lines = []

    for raw_line in ai_brief.splitlines():
        line = raw_line.strip()
        matched_heading = None
        for heading in AI_BRIEF_HEADINGS:
            if line == f"{heading}:" or line == heading:
                matched_heading = heading
                break

        if matched_heading:
            if current_heading is not None:
                sections[current_heading] = " ".join(current_lines).strip()
            current_heading = matched_heading
            current_lines = []
        elif current_heading is not None and line:
            current_lines.append(line)

    if current_heading is not None:
        sections[current_heading] = " ".join(current_lines).strip()

    return sections


def render_ai_brief(ai_brief):
    """Display the analyst brief as readable dashboard cards."""
    sections = parse_ai_brief(ai_brief)
    if len(sections) < 7:
        st.markdown(ai_brief)
        return

    for row_start in range(0, len(AI_BRIEF_HEADINGS), 2):
        row_headings = AI_BRIEF_HEADINGS[row_start:row_start + 2]
        columns = st.columns(len(row_headings))
        for column, heading in zip(columns, row_headings):
            text = sections.get(heading, "Insufficient database evidence.")
            extra_class = ""
            if heading == "Recommended Next Action":
                extra_class = " brief-recommendation"
            elif heading == "Missing Evidence":
                extra_class = " brief-missing"
            with column:
                st.markdown(
                    f'<div class="brief-card{extra_class}"><h4>{html.escape(heading)}</h4><p>{_format_detail_value(text)}</p></div>',
                    unsafe_allow_html=True,
                )


def _severity_class(severity):
    """Return the CSS modifier class for a severity value."""
    return {
        "Critical": "sev-critical",
        "High":     "sev-high",
        "Medium":   "sev-medium",
        "Low":      "sev-low",
    }.get(severity, "")


def _render_compact_incident_header(row):
    """Render a 4-column badge grid summarising the selected incident.

    Replaces the stacked-card expander with a compact read-only summary so the
    analyst can see all 12 key fields at a glance without scrolling.
    """
    rv = lambda *keys: _record_value(row, *keys)

    sev     = rv("severity")
    sev_cls = _severity_class(sev)
    lik     = rv("likelihood")
    imp     = rv("impact")
    lik_imp = f"{lik} / {imp}" if lik != "N/A" else "N/A"

    yr, mk, mdl = rv("model_year"), rv("make"), rv("model")
    vehicle_parts = [p for p in [yr, mk, mdl] if p != "N/A"]
    vehicle = " ".join(vehicle_parts) if vehicle_parts else "N/A"

    badges = [
        ("Incident ID",         html.escape(rv("incident_id"))),
        ("Severity",            f'<span class="{html.escape(sev_cls)}">{html.escape(sev)}</span>'),
        ("Status",              html.escape(rv("status"))),
        ("Risk Score",          html.escape(rv("risk_score"))),
        ("Vehicle",             html.escape(vehicle)),
        ("ECU Zone",            html.escape(rv("ecu_zone"))),
        ("Connectivity",        html.escape(rv("connectivity_type"))),
        ("Attack Vector",       html.escape(rv("attack_vector"))),
        ("Component",           html.escape(rv("affected_component"))),
        ("Detected At",         html.escape(rv("detected_at"))),
        ("Resolved At",         html.escape(rv("resolved_at"))),
        ("Likelihood / Impact", html.escape(lik_imp)),
    ]

    cells = "".join(
        f'<div class="inc-badge"><div class="inc-label">{label}</div><div class="inc-value">{value}</div></div>'
        for label, value in badges
    )
    st.markdown(f'<div class="inc-grid">{cells}</div>', unsafe_allow_html=True)


_REPORT_CSS = """
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto,
                 "Helvetica Neue", Arial, sans-serif;
    font-size: 13px; line-height: 1.55;
    background: #0f172a; color: #e2e8f0; padding: 2rem;
}
.report-header {
    border: 1px solid rgba(99,102,241,0.5); border-radius: 10px;
    padding: 1.4rem 1.6rem; margin-bottom: 1.2rem;
    background: rgba(99,102,241,0.08);
}
.report-title { font-size: 1.1rem; font-weight: 800; color: #c7d2fe;
    letter-spacing: 0.04em; text-transform: uppercase; margin-bottom: 0.3rem; }
.report-subtitle { font-size: 1rem; font-weight: 600; color: #f1f5f9; margin-bottom: 0.6rem; }
.badge-row { display: flex; flex-wrap: wrap; gap: 0.45rem; margin: 0.55rem 0; }
.badge { border-radius: 4px; padding: 0.18rem 0.6rem; font-size: 0.73rem;
    font-weight: 700; letter-spacing: 0.04em; text-transform: uppercase; }
.badge-critical { background:#7f1d1d; color:#fca5a5; border:1px solid #ef4444; }
.badge-high     { background:#7c2d12; color:#fdba74; border:1px solid #f97316; }
.badge-medium   { background:#713f12; color:#fde68a; border:1px solid #eab308; }
.badge-low      { background:#14532d; color:#86efac; border:1px solid #22c55e; }
.badge-neutral  { background:rgba(255,255,255,0.08); color:#cbd5e1; border:1px solid rgba(255,255,255,0.15); }
.report-meta { font-size: 0.8rem; color: #94a3b8; margin-top: 0.45rem; }
.report-meta span { margin-right: 1.4rem; }
.summary-grid {
    display: grid; grid-template-columns: repeat(4, 1fr);
    gap: 0.5rem; margin-bottom: 1.2rem;
}
.summary-cell { background:rgba(255,255,255,0.04); border:1px solid rgba(255,255,255,0.1);
    border-radius:6px; padding:0.4rem 0.65rem; }
.summary-label { font-size:0.62rem; color:#64748b; text-transform:uppercase;
    letter-spacing:0.06em; margin-bottom:0.12rem; }
.summary-value { font-size:0.88rem; font-weight:700; color:#f1f5f9; word-break:break-word; }
.summary-value.critical { color:#f87171; }
.summary-value.high     { color:#fb923c; }
.summary-value.medium   { color:#facc15; }
.summary-value.low      { color:#4ade80; }
.sections-grid { display:grid; grid-template-columns:1fr 1fr; gap:0.7rem; }
.section-card {
    border:1px solid rgba(255,255,255,0.1); border-radius:8px;
    padding:0.9rem 1rem; background:rgba(255,255,255,0.03); break-inside:avoid;
}
.section-card.full-width { grid-column: 1 / -1; }
.section-card.green { border-color:rgba(74,222,128,0.45); background:rgba(74,222,128,0.06); }
.section-card.amber { border-color:rgba(251,191,36,0.45); background:rgba(251,191,36,0.06); }
.section-heading { font-size:0.68rem; font-weight:800; text-transform:uppercase;
    letter-spacing:0.08em; color:#64748b; margin-bottom:0.5rem; }
.section-heading.green { color:#4ade80; }
.section-heading.amber { color:#fbbf24; }
.section-body { font-size:0.82rem; line-height:1.6; color:#cbd5e1;
    white-space:pre-wrap; word-break:break-word; }
.report-footer { margin-top:1.8rem; padding-top:0.7rem;
    border-top:1px solid rgba(255,255,255,0.08);
    font-size:0.72rem; color:#475569; }
@media print {
    body { background:white; color:#1e293b; padding:0; font-size:11px; }
    .report-header { border-color:#6366f1; background:#eef2ff; }
    .report-title { color:#4338ca; }
    .report-subtitle { color:#1e293b; }
    .report-meta { color:#64748b; }
    .summary-cell { background:#f8fafc; border-color:#e2e8f0; }
    .summary-label { color:#64748b; }
    .summary-value { color:#1e293b; }
    .summary-value.critical { color:#dc2626; }
    .summary-value.high     { color:#ea580c; }
    .summary-value.medium   { color:#ca8a04; }
    .summary-value.low      { color:#16a34a; }
    .badge-critical { background:#fee2e2; color:#991b1b; border-color:#dc2626; }
    .badge-high     { background:#fff7ed; color:#9a3412; border-color:#ea580c; }
    .badge-medium   { background:#fefce8; color:#854d0e; border-color:#ca8a04; }
    .badge-low      { background:#f0fdf4; color:#166534; border-color:#16a34a; }
    .badge-neutral  { background:#f8fafc; color:#475569; border-color:#e2e8f0; }
    .section-card         { background:white; border-color:#e2e8f0; }
    .section-card.green   { background:#f0fdf4; border-color:#86efac; }
    .section-card.amber   { background:#fffbeb; border-color:#fde68a; }
    .section-heading       { color:#64748b; }
    .section-heading.green { color:#16a34a; }
    .section-heading.amber { color:#d97706; }
    .section-body          { color:#334155; }
    .report-footer         { color:#94a3b8; }
    @page { margin: 1.5cm; }
}
"""


def _build_html_report(incident_row, sections, incident_id, generated_at):
    """Build a self-contained HTML analyst brief report.

    All CSS is embedded. Suitable for printing or saving as PDF via browser.
    """
    rv = lambda *keys: _record_value(incident_row, *keys)

    sev = rv("severity")
    sev_key = sev.lower() if sev in {"Critical", "High", "Medium", "Low"} else "neutral"
    sev_color = {"Critical": "critical", "High": "high", "Medium": "medium", "Low": "low"}.get(sev, "")

    yr, mk, mdl = rv("model_year"), rv("make"), rv("model")
    vehicle_parts = [p for p in [yr, mk, mdl] if p != "N/A"]
    vehicle = " ".join(vehicle_parts) if vehicle_parts else "N/A"

    lik = rv("likelihood")
    imp = rv("impact")
    lik_imp = f"{lik} / {imp}" if lik != "N/A" else "N/A"

    badge_sev = f'<span class="badge badge-{html.escape(sev_key)}">{html.escape(sev)}</span>'
    badge_id  = f'<span class="badge badge-neutral">Incident {html.escape(str(incident_id))}</span>'
    badge_sta = f'<span class="badge badge-neutral">{html.escape(rv("status"))}</span>'
    badge_rs  = f'<span class="badge badge-neutral">Risk Score: {html.escape(rv("risk_score"))}</span>'

    summary_fields = [
        ("Incident ID",         str(incident_id),         ""),
        ("Severity",            sev,                      sev_color),
        ("Status",              rv("status"),             ""),
        ("Risk Score",          rv("risk_score"),         ""),
        ("Vehicle",             vehicle,                  ""),
        ("ECU Zone",            rv("ecu_zone"),           ""),
        ("Connectivity",        rv("connectivity_type"),  ""),
        ("Attack Vector",       rv("attack_vector"),      ""),
        ("Component",           rv("affected_component"), ""),
        ("Detected At",         rv("detected_at"),        ""),
        ("Resolved At",         rv("resolved_at"),        ""),
        ("Likelihood / Impact", lik_imp,                  ""),
    ]
    summary_html = "".join(
        f'<div class="summary-cell"><div class="summary-label">{html.escape(label)}</div>'
        f'<div class="summary-value{(" " + cls) if cls else ""}">{html.escape(value)}</div></div>'
        for label, value, cls in summary_fields
    )

    def _sec(name, extra="", hcls="", full=False):
        body = html.escape(sections.get(name, "Not returned by model."))
        fw   = " full-width" if full else ""
        ec   = f" {extra}" if extra else ""
        hc   = f" {hcls}"  if hcls  else ""
        return (
            f'<div class="section-card{ec}{fw}">'
            f'<div class="section-heading{hc}">{html.escape(name)}</div>'
            f'<div class="section-body">{body}</div>'
            f'</div>'
        )

    sections_html = (
        _sec("Incident Summary", full=True)
        + _sec("Affected Vehicle & ECU Zone")
        + _sec("Attack Vector & Severity Rationale")
        + _sec("Risk Score Justification")
        + _sec("Evidence Status")
        + _sec("Mapped Compliance Controls")
        + _sec("Open Mitigations")
        + _sec("Recommended Next Action", "green", "green")
        + _sec("Missing Evidence",        "amber", "amber")
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Analyst Brief - Incident {html.escape(str(incident_id))}</title>
<style>
{_REPORT_CSS}
</style>
</head>
<body>
<div class="report-header">
  <div class="report-title">Automotive Cybersecurity Incident Analyst Brief</div>
  <div class="report-subtitle">{html.escape(rv("title"))}</div>
  <div class="badge-row">{badge_sev}{badge_id}{badge_sta}{badge_rs}</div>
  <div class="report-meta">
    <span>Vehicle: {html.escape(vehicle)}</span>
    <span>ECU Zone: {html.escape(rv("ecu_zone"))}</span>
    <span>Generated: {html.escape(generated_at)}</span>
  </div>
</div>
<div class="summary-grid">
{summary_html}
</div>
<div class="sections-grid">
{sections_html}
</div>
<div class="report-footer">
  Generated by AI Automotive Cybersecurity Incident &amp; Compliance Assistant
  | Assignment 5.2 | Evidence source: local SQLite database only.
  This brief assists the analyst and does not replace engineering judgment.
</div>
</body>
</html>"""


# ---------------------------------------------------------------------------
# Main Streamlit application
# ---------------------------------------------------------------------------

st.title("AI Automotive Cybersecurity Incident & Compliance Assistant")
st.write(
    """
    This application lets an analyst inspect automotive cybersecurity incidents
    stored in a local SQLite database. The interface calls reusable functions from
    `db.py`, keeping SQL logic out of `app.py`. The integrated AI feature uses
    selected incident evidence, controls, risk assessment, and mitigation data to
    generate a database grounded analyst brief.
    """
)

try:
    # -- Incident Overview -------------------------------------------------------
    st.header("Incident Overview")
    kpis = get_kpi_summary()
    kpi_col1, kpi_col2, kpi_col3, kpi_col4 = st.columns(4)
    kpi_col1.metric("Total Incidents",    kpis["total_incidents"])
    kpi_col2.metric("Critical Incidents", kpis["critical_incidents"])
    kpi_col3.metric("Open Mitigations",   kpis["open_mitigations"])
    kpi_col4.metric("Mapped Controls",    kpis["mapped_controls"])

    st.subheader("All Incidents")
    show_table(get_all_incidents())

    # -- Severity filter ---------------------------------------------------------
    st.header("Filter Incidents by Severity")
    severity = st.selectbox(
        "Choose a severity to inspect",
        ["Critical", "High", "Medium", "Low"],
        index=1,
    )
    st.caption(
        "This section uses the parameterized query function "
        "`get_incidents_by_severity(severity)` from `db.py`."
    )
    show_table(
        get_incidents_by_severity(severity),
        fallback_message="No incidents found for that severity.",
    )

    # -- JOIN result -------------------------------------------------------------
    st.header("JOIN Result: Incidents with Vehicle Assets")
    st.markdown(
        '<p class="small-note">This view joins incident records to related vehicle '        'asset records so the analyst can see VIN, platform, ECU zone, and '        'connectivity context.</p>',
        unsafe_allow_html=True,
    )
    show_table(get_incidents_with_assets())

    # -- Severity summary --------------------------------------------------------
    st.header("Severity Summary")
    severity_counts = get_incident_counts_by_severity()
    show_table(severity_counts)
    if not severity_counts.empty:
        st.bar_chart(severity_counts.set_index("severity")["incident_count"])

    # -- Compliance and mitigation summaries -------------------------------------
    st.header("Compliance Control Mapping Summary")
    show_table(get_control_summary())

    st.header("Open Mitigation Queue")
    show_table(get_open_mitigations())

    # -- Selected incident detail view ------------------------------------------
    st.header("Selected Incident Detail View")
    incident_overview = get_incident_overview()
    incident_options = {
        f"{row.incident_id}: {row.title}": int(row.incident_id)
        for row in incident_overview.itertuples(index=False)
    }
    selected_label = st.selectbox(
        "Choose an incident for detailed evidence review",
        list(incident_options.keys()),
    )
    selected_id = incident_options[selected_label]

    context = get_ai_context_for_incident(selected_id)
    if context["incident"].empty:
        st.warning("No incident record found for that ID.")
    else:
        incident_row = context["incident"].iloc[0]

        # Compact 4-column badge grid -- replaces the old stacked-card expander.
        _render_compact_incident_header(incident_row)

        detail_tab, controls_tab, evidence_tab, mitigations_tab = st.tabs(
            ["Incident Record", "Mapped Controls", "Evidence Items", "Mitigation Actions"]
        )
        with detail_tab:
            # Description and TARA Notes side by side.
            # ID, severity, risk score etc. are already in the compact header.
            desc_col, tara_col = st.columns(2)
            with desc_col:
                with st.container(border=True):
                    st.markdown("**Description**")
                    st.write(_record_value(incident_row, "description"))
            with tara_col:
                with st.container(border=True):
                    st.markdown("**TARA Notes**")
                    st.write(_record_value(incident_row, "tara_notes"))

            if _record_value(incident_row, "linked_controls") != "N/A":
                _write_labeled_value(
                    "Linked Controls",
                    _record_value(incident_row, "linked_controls"),
                )
            if _record_value(incident_row, "compliance_gaps") != "N/A":
                _write_labeled_value(
                    "Compliance Gaps",
                    _record_value(incident_row, "compliance_gaps"),
                )

            with st.expander("Debug: raw database record", expanded=False):
                st.caption("Raw dataframe for technical validation.")
                st.dataframe(context["incident"])

        with controls_tab:
            show_controls_cards(context["controls"])
        with evidence_tab:
            show_evidence_cards(context["evidence"])
        with mitigations_tab:
            show_mitigation_cards(context["mitigation_actions"])

    # -- AI Incident Analyst & Compliance Summary Assistant (Assignment 5.2) -----
    st.header("AI Incident Analyst & Compliance Summary Assistant")
    st.caption(
        "Assignment 5.2: Live AI feature. The model receives only the database "
        "records retrieved above for the selected incident. It cannot query the "
        "database, cannot modify any records, and is instructed not to reference "
        "other incidents or invent details absent from the stored evidence."
    )

    if context["incident"].empty:
        st.warning("Select a valid incident above to enable the AI analyst feature.")
    else:
        st.subheader("Database Evidence for AI Analysis")
        st.markdown(
            f"The selected incident record shown above, together with the related "
            f"records below, forms the exact database evidence passed to the AI model "
            f"for **Incident {selected_id}: {incident_row['title']}**."
        )

        ev_tab_ctrl, ev_tab_ev, ev_tab_mit = st.tabs(
            ["Mapped Controls", "Evidence Items", "Mitigation Actions"]
        )
        with ev_tab_ctrl:
            show_controls_cards(context["controls"])
        with ev_tab_ev:
            show_evidence_cards(context["evidence"])
        with ev_tab_mit:
            show_mitigation_cards(context["mitigation_actions"])

        st.divider()
        st.warning(
            "**Before generating:** The AI brief is generated from the selected database "
            "records only. The application sends that evidence to the configured Anthropic "
            "model but does not independently search the web or retrieve outside incident "
            "information. It does not modify the database. Review the brief critically. "
            "It assists the analyst but does not replace engineering judgment. "
            "Ensure `ANTHROPIC_API_KEY` is set in your `.env` file before clicking."
        )

        if st.button("Generate AI Analyst Brief", type="primary"):
            with st.spinner("Calling AI model. This may take a few seconds..."):
                ai_brief = generate_incident_summary(context)

            error_prefixes = (
                "No database evidence was retrieved",
                "ANTHROPIC_API_KEY is not configured",
                "AI model call failed",
            )
            if any(ai_brief.startswith(p) for p in error_prefixes):
                st.error(ai_brief)
            else:
                st.subheader("AI Generated Analyst Brief")
                st.caption(
                    "Generated from database evidence only. Sections with insufficient "
                    "evidence state so explicitly rather than producing guesses."
                )

                sections = parse_ai_brief(ai_brief)
                render_ai_brief(ai_brief)

                st.divider()
                generated_at = datetime.now().strftime("%Y-%m-%d %H:%M")
                html_report = _build_html_report(
                    incident_row, sections, selected_id, generated_at
                )

                dl_col1, dl_col2 = st.columns([2, 1])
                with dl_col1:
                    st.download_button(
                        label="Download Analyst Brief (HTML)",
                        data=html_report,
                        file_name=f"analyst_brief_incident_{selected_id}.html",
                        mime="text/html",
                        type="primary",
                    )
                with dl_col2:
                    st.download_button(
                        label="Download as plain text",
                        data=ai_brief,
                        file_name=f"analyst_brief_incident_{selected_id}.txt",
                        mime="text/plain",
                    )

            with st.expander(
                "Debug: raw evidence text and full prompt sent to model",
                expanded=False,
            ):
                from ai import format_incident_evidence, build_analyst_prompt
                raw_evidence = format_incident_evidence(context)
                full_prompt  = build_analyst_prompt(raw_evidence)
                st.code(full_prompt, language="text")

except Exception as error:
    st.error(
        "The Streamlit prototype could not load database records. "
        "Run `python seed.py` first and confirm `data/project.db` exists."
    )
    st.exception(error)
