"""AlertLens home."""
import sys
from pathlib import Path

# Streamlit Cloud does not put the repo root on the import path.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import streamlit as st

from alertlens.memory import store as db
from alertlens.pipeline.orchestrator import Options
from alertlens.pipeline.service import analyze_batch, hero_alerts
from ui.common import setup, show_kpis

setup("Home")
st.title("AlertLens")
st.subheader("Explains security alerts. Attackers hiding instructions in the logs can't talk it out of the truth.")
st.write("Severity is decided by code. The model only explains, from checked facts, and every action waits for a person. "
         "All data here is synthetic.")
show_kpis()
a, b = st.columns(2)
if a.button("Run hero demo", type="primary", width="stretch"):
    _, incidents = analyze_batch(hero_alerts(), Options())
    st.session_state["incident_id"] = incidents[0].incident_id
    st.switch_page("pages/2_Incidents.py")
if b.button("Open live feed", width="stretch"):
    st.switch_page("pages/3_Live_Feed.py")
with db.db() as conn:
    stats = db.router_stats(conn)
if stats:
    st.subheader("Where alerts went")
    st.dataframe([{"Path": "Fast, no LLM" if k == "fast" else "LLM", "Alerts": v["n"], "Average ms": v["avg_ms"],
                   "Estimated tokens used": v["tokens"]} for k, v in stats.items()], hide_index=True)
