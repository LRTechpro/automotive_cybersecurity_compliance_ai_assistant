# AI Automotive Cybersecurity Incident & Compliance Assistant

Portfolio-style prototype for MS587 — Assignment 5.2. This project stores automotive cybersecurity incident, vehicle, risk, evidence, mitigation, and compliance-control data in a SQLite database, exposes it through a reusable Python database access layer, and displays it through a Streamlit analyst dashboard with an integrated live AI feature.

The project includes three working layers:

1. **Backend database access layer** in `db.py`
2. **AI analyst module** in `ai.py` — calls the Anthropic API with database-grounded evidence
3. **Streamlit front-end** in `app.py` — analyst dashboard with incident detail view and AI brief generation

## Project Structure

```text
final-project/
  README.md
  requirements.txt
  .env.example          ← copy to .env and add your ANTHROPIC_API_KEY
  app.py
  ai.py                 ← NEW in Assignment 5.2
  db.py
  schema.sql
  seed.py
  data/
    project.db
  docs/
    db_access_notes.md
    query_portfolio.md
    streamlit_prototype_notes.md
    video_walkthrough_script.md
```

## Environment Setup

Recommended on Windows (Python 3.13):

```powershell
py -3.13 -m venv .venv313
.\.venv313\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

`requirements.txt` installs: `streamlit`, `pandas`, `anthropic`, and `python-dotenv`.

## API Key Setup (Required for AI Feature)

The AI feature calls the Anthropic API. You must provide your own key:

1. Copy `.env.example` to `.env` in the project root:

```powershell
Copy-Item .env.example .env
```

2. Open `.env` and replace the placeholder with your real key:

```text
ANTHROPIC_API_KEY=sk-ant-...
```

**Do not commit `.env` to version control.** The `.gitignore` already excludes it.  
**Do not submit your real key** with the assignment ZIP — submit `.env.example` only.

## Rebuild the Database

```powershell
python seed.py
```

This creates `data/project.db` from `schema.sql` and loads seed data. Run this before launching the app.

## Test the Database Access Layer

```powershell
python db.py
```

Prints a smoke-test of all key query functions, including `get_ai_context_for_incident()`.

## Run the Streamlit App

```powershell
python -m streamlit run app.py
```

Opens the dashboard at:

```text
http://localhost:8501
```

## Key Backend Functions (`db.py`)

Dashboard queries:

- `get_all_incidents()`
- `get_incidents_by_severity(severity)`
- `get_incidents_with_assets()`
- `get_incident_counts_by_severity()`
- `get_open_mitigations()`
- `get_incident_overview()`
- `get_control_summary()`
- `get_kpi_summary()`

AI evidence retrieval:

- `get_ai_context_for_incident(incident_id)` — returns a dict of DataFrames (incident, controls, evidence, mitigation actions) for the selected incident; this is the only data passed to the AI model.

## AI Feature (`ai.py`)

`ai.py` contains three public functions:

- `format_incident_evidence(context)` — converts the `get_ai_context_for_incident()` result into labeled plain text.
- `build_analyst_prompt(evidence_text)` — wraps the evidence in hard delimiters (`--- DATABASE EVIDENCE START ---` / `--- DATABASE EVIDENCE END ---`) to prevent prompt injection, then prepends the system prompt.
- `generate_incident_summary(context)` — calls `claude-haiku-4-5-20251001` (`max_tok