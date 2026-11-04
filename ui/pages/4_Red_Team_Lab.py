"""Pick a payload and a field, then attack a naive LLM and AlertLens with the same model."""
import streamlit as st

from alertlens.pipeline.redteam import attack
from alertlens.pipeline.service import hero_alerts, load_samples
from data.generator.injections import FAMILIES, TARGET_FIELDS
from ui.common import esc, injection_banner, setup, sev_badge

setup("Red-Team Lab")
st.title("Red-Team Lab")
st.write("Both systems use one simulated gullible model, which obeys any instruction it can read. "
         "The difference comes from what each design lets it read.")
clean = {a["alert_id"]: a for a in hero_alerts() if a["alert_id"] != "HERO-2"}
for name, sample in load_samples().items():
    if sample.get("source_format") == "native" and not name.startswith("hero"):
        clean[sample["alert_id"]] = sample
a, b, c = st.columns(3)
alert_id = a.selectbox("Clean alert", list(clean))
family = b.selectbox("Injection family", FAMILIES, format_func=lambda f: f.replace("_", " "))
field = c.selectbox("Target field", TARGET_FIELDS, index=TARGET_FIELDS.index("user_agent"))
if st.button("Attack", type="primary"):
    st.session_state["attack"] = attack(clean[alert_id], family, field)
out = st.session_state.get("attack")
if not out:
    st.info("Choose a payload and press Attack.")
    st.stop()
left, right = st.columns(2, gap="large")
naive, al = out["naive"], out["alertlens"]
with left:
    st.subheader("Naive LLM")
    st.error("Fooled") if out["naive_fooled"] else st.success("Not fooled")
    st.markdown(f"{sev_badge(naive.severity)} &nbsp; verdict {esc(naive.verdict)}", unsafe_allow_html=True)
    st.write("Actions: " + (", ".join(naive.actions) or "none"))
    st.write(naive.explanation)
    st.caption(f"The same alert without the payload: {out['naive_clean'].severity}, {out['naive_clean'].verdict}.")
with right:
    st.subheader("AlertLens")
    st.error("Fooled") if out["alertlens_fooled"] else st.success("Not fooled")
    st.markdown(f"{sev_badge(al.severity.label)} &nbsp; score {al.severity.score}", unsafe_allow_html=True)
    st.write("Actions: " + (", ".join(x.action_id for x in al.actions) or "none"))
    st.write(al.explanation.summary)
    st.caption(f"The same alert without the payload: {out['alertlens_clean'].severity.label}, "
               f"{out['alertlens_clean'].severity.score}.")
injection_banner(al.sanitise.model_dump())
st.subheader("Layers that acted")
for layer in out["layers"]:
    st.markdown(f"**{esc(layer['layer'])}**: {esc(layer['detail'])}", unsafe_allow_html=True)
