# Streamlit Prototype Notes

## Question 1: What database-backed information does your Streamlit app display?

The Streamlit app displays automotive cybersecurity incident records from the SQLite database, including incident title, severity, status, attack vector, affected component, detected date, and related vehicle context. It also displays compliance control mapping, open mitigation actions, severity summaries, and selected incident evidence.

## Question 2: What user-controlled filter or selection did you implement?

The app includes a severity `selectbox` that lets the user filter incidents by Critical, High, Medium, or Low severity. It also includes a selected incident `selectbox` that lets the user choose one incident for detailed evidence review.

## Question 3: Which JOIN query result is displayed in your app, and why is it useful?

The app displays the result from `get_incidents_with_assets()`, which joins the `incidents` table to the `vehicles` table. This is useful because an analyst can see the incident together with VIN, make, model, model year, ECU zone, and connectivity type instead of reviewing incident data without vehicle context.

## Question 4: Which aggregation or summary result is displayed in your app?

The app displays `get_incident_counts_by_severity()`, which groups incidents by severity and calculates the incident count and average risk score for each severity level. The app also displays this information as a simple bar chart.

## Question 5: What data does your detail view retrieve?

The detail view retrieves a selected incident's full database-backed context using `get_ai_context_for_incident(incident_id)`. It displays the incident record, related vehicle information, risk assessment fields, TARA notes, mapped controls, evidence items, and mitigation actions.

## Question 6: Where will the future AI feature be added, and what database-resident data will it use?

The future AI feature will be added in the "Future AI Feature Placeholder" section of the Streamlit app. It will use database-resident evidence from `get_incident_evidence_for_ai(incident_id)`, including incident description, vehicle context, risk score, TARA notes, linked controls, compliance gaps, evidence summaries, and mitigation actions.

## Question 7: What is one improvement you plan to make before the final project submission?

One planned improvement is to add an AI-generated incident summary that explains the selected incident, risk level, compliance impact, and recommended mitigation steps using only the database-backed evidence returned from the selected incident detail view.
