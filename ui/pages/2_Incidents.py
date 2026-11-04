"""Incidents: timeline, attack graph and next steps."""
import streamlit as st

from alertlens.memory import store as db
from alertlens.render.report import build_report
from ui.common import debate_block, esc, graph_figure, setup, sev_badge

setup("Incidents")
st.title("Incidents")
with db.db() as conn:
    incidents = db.list_incidents(conn)
if not incidents:
    st.info("No incidents yet. Run the hero demo from Home.")
    st.stop()
ids = [i["incident_id"] for i in incidents]
preferred = st.session_state.get("incident_id")
choice = st.selectbox("Incident", ids, index=ids.index(preferred) if preferred in ids else 0,
                      format_func=lambda x: next(f"{x}: {i['severity']['label']}, {len(i['alert_ids'])} alerts" for i in incidents
                                                 if i["incident_id"] == x))
inc = next(i for i in incidents if i["incident_id"] == choice)
st.markdown(f"{sev_badge(inc['severity']['label'])} &nbsp; score {inc['severity']['score']}. {esc(inc['graph_summary'])}",
            unsafe_allow_html=True)
if inc["tactics_sequence"]:
    st.write("Attack stages, in order: " + " > ".join(inc["tactics_sequence"]))
left, right = st.columns([1.1, 1], gap="large")
with left:
    st.subheader("Attack graph")
    st.plotly_chart(graph_figure(inc["graph"]), width="stretch")
    st.caption(f"Red marks the pivot: {inc['pivot']}, the most connected entity.")
with right:
    st.subheader("Timeline")
    for step, row in enumerate(inc["timeline"], 1):
        warn = " Hidden instructions found." if row["injected"] else ""
        st.markdown(f"**{step}. {esc(row['ts'][11:16])}** {esc(row['what'])} ({esc(row['tactic'])}) "
                    f"{sev_badge(row['label'])}{warn}", unsafe_allow_html=True)
    st.subheader("Likely next")
    for p in inc["predicted_next"]:
        st.markdown(f"- **{esc(p['tactic'])}**: watch for {esc(p['watch_for'])}", unsafe_allow_html=True)
    st.caption("A heuristic from a hand-built table, not a certainty.")
with st.expander("Agent debate"):
    with db.db() as conn:
        for aid in inc["alert_ids"]:
            a = db.get_analysis(conn, aid)
            if a and a["agent_transcript"]:
                st.markdown(f"**{esc(aid)}**", unsafe_allow_html=True)
                debate_block(a["agent_transcript"])
st.subheader("Export report")
FORMATS = {"PDF": ("pdf", "en"), "HTML": ("html", "en"), "Markdown": ("md", "en"), "HTML, हिन्दी": ("html", "hi")}
kind = st.radio("Format", list(FORMATS), horizontal=True)
if st.button("Prepare report"):
    st.session_state["report"] = (choice, kind, build_report(choice, *FORMATS[kind]))
ready = st.session_state.get("report")
if ready and ready[:2] == (choice, kind):
    body, media, name = ready[2]
    st.download_button(f"Download {name}", body, file_name=name, mime=media)
