"""Analyst corrections and retraining."""
import sys
from pathlib import Path

# Streamlit Cloud does not put the repo root on the import path.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import plotly.graph_objects as go
import streamlit as st

from alertlens.config import get_settings
from alertlens.feedback.loop import record_feedback, retrain
from alertlens.memory import store as db
from alertlens.pipeline.orchestrator import Options, analyze
from alertlens.schemas import FeedbackIn
from ui.common import setup

setup("Feedback")
st.title("Feedback")
st.write("Correct a verdict, then retrain. The planted example: training data labels misused service tokens as benign.")
if get_settings().public_demo:
    # Visitors share one model, so one person must not be able to retrain it for everyone.
    st.info("Feedback and retraining are turned off on this public demo. Run AlertLens locally to try them.")
    st.stop()
with db.db() as conn:
    rows = db.list_analyses(conn, 200)
    used = conn.execute("SELECT COUNT(*) FROM feedback").fetchone()[0]
if rows:
    with st.form("fb"):
        alert = st.selectbox("Alert", [r["alert_id"] for r in rows],
                             format_func=lambda x: next(f"{x}: {r['label']}, {r['score']}" for r in rows if r["alert_id"] == x))
        truth = st.radio("True label", ["malicious", "benign"], horizontal=True)
        correct = st.checkbox("The verdict was right")
        rating = st.slider("Explanation rating", 1, 5, 4)
        comment = st.text_input("Comment")
        if st.form_submit_button("Save feedback"):
            record_feedback(FeedbackIn(alert_id=alert, correct_label=truth, verdict_correct=correct, explanation_rating=rating, comment=comment))
            st.success("Saved feedback.")
            st.rerun()
else:
    st.info("Nothing has been analysed yet. Analyze an alert first.")
st.metric("Corrections saved", used)
a, b = st.columns(2)
if a.button("Add 20 service token corrections"):
    import random

    from data.generator.scenarios import service_token_abuse

    rng = random.Random(used)
    for i in range(20):
        canon = service_token_abuse(rng)[0][0]
        canon.update(alert_id=f"FB-{used + i}", source_format="native")
        analyze(canon, Options())
        record_feedback(FeedbackIn(alert_id=canon["alert_id"], correct_label="malicious", verdict_correct=False))
    st.rerun()
if b.button("Retrain", type="primary"):
    with st.spinner("Retraining on generated data plus corrections"):
        st.session_state["retrain"] = retrain()
rep = st.session_state.get("retrain")
if rep:
    names = ["Recall on the corrected pattern", "Held-out F1"]
    fig = go.Figure([
        go.Bar(name="Before", x=names, y=[rep["before"]["target_recall"], rep["before"]["held_out"]["f1"]], marker_color="#6F7392"),
        go.Bar(name="After", x=names, y=[rep["after"]["target_recall"], rep["after"]["held_out"]["f1"]], marker_color="#A9B8FF"),
    ])
    fig.update_layout(barmode="group", yaxis_range=[0, 1], paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font_color="#ECE9F5")
    st.plotly_chart(fig, width="stretch")
    st.caption(f"Used {rep['feedback_used']} corrections.")
