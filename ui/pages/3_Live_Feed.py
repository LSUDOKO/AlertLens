"""Replays the synthetic stream at about one alert per second."""
import json

import pandas as pd
import plotly.express as px
import streamlit as st

from alertlens.config import ROOT
from alertlens.correlation.correlator import correlate
from alertlens.memory import store as db
from alertlens.pipeline.orchestrator import Options, analyze
from alertlens.schemas import Alert
from ui.common import SEVERITY, setup, show_kpis

setup("Live feed")
st.title("Live feed")
source = ROOT / "data" / "benchmark" / "alerts.jsonl"
if not source.exists():
    st.error("No stream to replay. Run `make data` first.")
    st.stop()
st.session_state.setdefault("feed_on", False)
st.session_state.setdefault("feed_pos", 200)
a, b = st.columns([1, 5])
if a.button("Stop replay" if st.session_state["feed_on"] else "Start replay", type="primary"):
    st.session_state["feed_on"] = not st.session_state["feed_on"]
    st.rerun()
b.caption("Replays synthetic alerts through the real pipeline.")


@st.fragment(run_every=1.0)
def feed() -> None:
    if st.session_state["feed_on"]:
        lines = source.read_text().splitlines()
        pos = st.session_state["feed_pos"] % len(lines)
        analyze(json.loads(lines[pos]), Options())
        st.session_state["feed_pos"] = pos + 1
    show_kpis()
    with db.db() as conn:
        rows = db.list_analyses(conn, 300)
    if not rows:
        st.info("Nothing analysed yet. Press Start replay.")
        return
    df = pd.DataFrame(rows)
    left, right = st.columns(2)
    trend = df.assign(ts=pd.to_datetime(df["ts"], format="ISO8601", utc=True)).sort_values("ts")
    fig = px.scatter(trend, x="ts", y="score", color="label", color_discrete_map=SEVERITY, title="Severity over time",
                     category_orders={"label": ["critical", "high", "medium", "low"]},
                     labels={"ts": "Alert time", "score": "Score", "label": "Severity"})
    heat = df.explode("tactics").dropna(subset=["tactics"])
    style = dict(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font_color="#ECE9F5", height=340)
    fig.update_layout(**style)
    left.plotly_chart(fig, width="stretch", key="trend")
    if not heat.empty:
        matrix = heat.groupby(["tactics", "label"]).size().unstack(fill_value=0)
        matrix = matrix[[c for c in ["low", "medium", "high", "critical"] if c in matrix.columns]]
        hm = px.imshow(matrix, text_auto=True, aspect="auto", title="ATT&CK tactics by severity", color_continuous_scale=["#22263D", "#A9B8FF"],
                       labels={"x": "Severity", "y": "Tactic", "color": "Alerts"})
        hm.update_layout(**style)
        right.plotly_chart(hm, width="stretch", key="heat")
    with db.db() as conn:
        recent = [Alert.model_validate_json(r[0]) for r in conn.execute("SELECT body FROM alerts ORDER BY ts DESC LIMIT 300")]
    groups = [g for g in correlate(recent) if len(g) > 1]
    st.subheader(f"{len(groups)} groups of linked alerts")
    st.dataframe([{"First alert": g[0].timestamp.isoformat()[:19], "Alerts": len(g), "Linked IDs": ", ".join(a.alert_id for a in g)[:120]}
                  for g in sorted(groups, key=len, reverse=True)[:8]], hide_index=True, width="stretch")
    st.subheader("Latest alerts")
    st.dataframe(df[["ts", "alert_id", "label", "score", "route", "injected"]].head(25), hide_index=True, width="stretch")


feed()
