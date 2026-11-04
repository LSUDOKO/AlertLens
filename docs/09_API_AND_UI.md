# 09 — API and UI

## 1. REST API (FastAPI, port 8000, docs at `/docs`)

| Method | Path | Purpose |
|---|---|---|
| GET | `/health` | Status, provider, model, version |
| POST | `/analyze` | Body: one alert (any supported format). Query: `audience`, `lang`, `deep=true` (force the LLM path). Returns `AnalysisResult`. |
| POST | `/analyze/batch` | Many alerts, then correlation. Returns results + incidents. |
| GET | `/alerts` / `/alerts/{id}` | Stored analyses |
| GET | `/incidents` / `/incidents/{id}` | Incidents with timeline, graph JSON, predicted next steps |
| GET | `/incidents/{id}/report?format=md\|html\|pdf&lang=en\|hi` | Report export |
| POST | `/actions/{id}/approve` | Body: approver. Moves the action to approved, then simulated |
| POST | `/actions/{id}/reject` | Body: approver, reason |
| POST | `/feedback` | `{alert_id, correct_label, verdict_correct, explanation_rating, comment}` |
| POST | `/retrain` | Retrain with feedback; returns before/after metrics |
| GET | `/similar/{alert_id}` | Top-k similar past cases |
| GET | `/audit` / `/audit/verify` | Log entries / integrity check |
| GET | `/metrics` | Router stats, counts, latency |
| POST | `/stream/replay` | Start replaying the synthetic stream for the live feed |

All responses use the Pydantic schemas. Errors return `{error, detail}` with proper status codes.

## 2. Streamlit UI (port 8501)
Use a dark security theme (`.streamlit/config.toml`). Severity colours: low = grey, medium = amber, high = orange, critical = red. Load the `frontend-design` guidance if available for a distinctive look.

### Home
Project name, one-line pitch, KPI tiles (alerts today, incidents, injections blocked, fast-path %), and buttons "Run hero demo" and "Open live feed".

### 1 · Analyze Alert (main demo page)
- Left: pick a sample, paste JSON, or upload. Format autodetected.
- Right, top to bottom:
  1. **Injection banner** (if any): field, family, inert preview
  2. **Severity card:** score gauge, label, confidence, triage outcome, "Decided by code, not AI", reasons, counterfactuals
  3. **Explanation:** audience tabs (Analyst / Manager / Employee), language toggle (EN / हिन्दी), each claim with a ✅ or ⚠️ badge and an evidence tooltip, grounding score
  4. **ATT&CK:** technique chips plus a "Likely next" panel
  5. **Recommended actions:** cards with risk, Dry run (expander), Approve / Reject, rollback text
  6. **Similar past incidents** (top 3)
  7. **Agent debate** (collapsible transcript)
  8. **Pipeline trace:** stage timings, route taken (fast or LLM)

### 2 · Incidents
List of incidents; detail view with timeline, interactive attack graph (pivot node highlighted), tactic progression, predicted next steps, and an export-report button.

### 3 · Live Feed
Replays the synthetic stream (about 1 alert per second). Rolling table, severity trend line, ATT&CK tactic heatmap, auto-grouping into incidents.

### 4 · Red-Team Lab (wow page)
- Pick a clean alert, choose an injection family and target field, press **Attack**
- Side-by-side: **Naive LLM** vs **AlertLens** with verdict, severity and actions
- Shows exactly which defence layer caught it

### 5 · Benchmark
Renders `results/metrics.json` and the charts; button to re-run a small quick benchmark (about 100 alerts).

### 6 · Feedback
Queue of reviewed alerts, mark correct or wrong, retrain button, before/after metrics chart.

### 7 · Audit Log
Table of entries, a "Verify integrity" button with a green or red result, and a demo "tamper" button that edits a row in a copy of the DB to show detection.

### 8 · Settings
Provider and model selection (read from `.env`, switchable at runtime), feature flags, correlation window.
