"""The main demo page."""
import json

import streamlit as st

from alertlens.ingest.adapters import UnknownFormatError
from alertlens.ingest.normalise import AlertValidationError
from alertlens.pipeline.orchestrator import Options, analyze
from alertlens.pipeline.service import load_samples
from ui.common import actions_block, debate_block, esc, explanation_block, injection_banner, setup, severity_card

setup("Analyze alert")
st.title("Analyze an alert")
left, right = st.columns([1, 2.2], gap="large")
with left:
    samples = load_samples()
    names = sorted(samples, key=lambda n: (not n.startswith("hero"), n))
    source = st.radio("Alert source", ["Sample", "Paste JSON", "Upload"], horizontal=True)
    obj, error = None, None
    if source == "Sample":
        choice = st.selectbox("Sample", names, index=names.index("hero/hero-2.json"))
        obj = samples[choice]
        st.json(obj, expanded=False)
    else:
        text = st.text_area("Alert JSON", height=260) if source == "Paste JSON" else None
        if source == "Upload" and (up := st.file_uploader("Alert JSON file", type="json")):
            text = up.getvalue().decode("utf-8", "replace")
        if text:
            try:
                obj = json.loads(text)
            except json.JSONDecodeError as exc:
                error = f"This is not valid JSON: {exc}"
    deep = st.checkbox("Force the LLM path", help="Skip the fast path, and run the agents")
    if error:
        st.error(error)
    if st.button("Analyze alert", type="primary", disabled=obj is None):
        try:
            st.session_state["analysis"] = analyze(obj, Options(deep=deep)).model_dump(mode="json")
        except (UnknownFormatError, AlertValidationError) as exc:
            st.error(str(exc))
with right:
    r = st.session_state.get("analysis")
    if not r:
        st.info("Pick an alert and press Analyze alert. The preselected sample hides an instruction in its user agent.")
    else:
        aid = r["alert"]["alert_id"]
        st.caption(f"Alert {aid}, {r['alert']['source_format']} format")
        injection_banner(r["sanitise"])
        severity_card(r["severity"])
        st.subheader("Explanation")
        explanation_block(r, aid)
        st.subheader("ATT&CK")
        st.write(", ".join(f"{t['id']} {t['name']} ({t['tactic']})" for t in r["mitre"]) or "No technique matched.")
        if r["predicted_next"]:
            st.markdown("**Likely next**")
            for p in r["predicted_next"]:
                st.markdown(f"- {esc(p['tactic'])}: watch for {esc(p['watch_for'])}", unsafe_allow_html=True)
            st.caption(r["predicted_next"][0]["note"])
        st.subheader("Recommended actions")
        actions_block(aid, aid)
        st.subheader("Similar past incidents")
        st.dataframe([{"Case": c["case_id"], "Similarity": c["similarity"], "Summary": c["summary"], "Resolution": c["resolution"],
                       "Outcome": c["outcome"]} for c in r["similar_cases"]], hide_index=True)
        with st.expander("Agent debate"):
            debate_block(r["agent_transcript"])
        with st.expander("Pipeline trace"):
            st.write(f"Route: **{r['route']}**. Audit record #{r['audit_seq']}.")
            st.json(r["timings_ms"])
            st.json(r["security_events"], expanded=False)
