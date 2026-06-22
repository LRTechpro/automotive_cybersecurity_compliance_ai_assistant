# Assignment 4.2 Video Walkthrough Script

## 0:00-0:30 — Project Overview
This is the Streamlit prototype for my AI Automotive Cybersecurity Incident and Compliance Assistant. The app lets an analyst inspect automotive cybersecurity incidents stored in a local SQLite database. The interface calls functions from `db.py`, so SQL logic stays out of `app.py`.

## 0:30-1:15 — Folder Structure and Files
The project includes `app.py`, `db.py`, `schema.sql`, `seed.py`, `data/project.db`, `README.md`, and the docs folder. `schema.sql` defines the database, `seed.py` rebuilds and populates it, and `db.py` contains the reusable database access functions. The new file for this assignment is `docs/streamlit_prototype_notes.md`.

## 1:15-2:00 — app.py and db.py Connection
In `app.py`, the Streamlit interface imports functions from `db.py`. This keeps the interface thin and reusable. The app uses functions such as `get_all_incidents`, `get_incidents_by_severity`, `get_incidents_with_assets`, `get_incident_counts_by_severity`, and `get_incident_evidence_for_ai`.

## 2:00-4:30 — Run and Demonstrate the App
I run `python seed.py` to rebuild the database, then `python -m streamlit run app.py` to launch the app. The app displays all incidents, lets the user filter incidents by severity, shows a JOIN result connecting incidents to vehicle assets, displays a GROUP BY severity summary, and provides a detail view for a selected incident.

## 4:30-6:00 — Future AI Feature and Next Steps
The future AI placeholder shows where AI integration will be added later. The selected incident evidence can support an AI-generated incident summary, risk explanation, compliance impact review, or mitigation recommendation. One improvement before final submission is to add that AI-generated summary using only database-grounded evidence.
