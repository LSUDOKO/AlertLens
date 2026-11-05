"""Pick a payload and a field, then attack a naive LLM and AlertLens with the same model."""
import sys
from pathlib import Path

# Streamlit Cloud does not put the repo root on the import path.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import streamlit as st

from alertlens.config import get_settings
from alertlens.llm.provider import main_provider
from alertlens.pipeline.redteam import MAX_CUSTOM_PAYLOAD, attack, attack_custom
from alertlens.pipeline.service import hero_alerts, load_samples
from data.generator.injections import FAMILIES, TARGET_FIELDS
from ui.common import esc, injection_banner, model_trace_block, setup, sev_badge

setup("Red-Team Lab")
st.title("Red-Team Lab")
st.write("Both systems use the same model. The difference comes from what each design lets it read.")
clean = {a["alert_id"]: a for a in hero_alerts() if a["alert_id"] != "HERO-2"}
for name, sample in load_samples().items():
    if sample.get("source_format") == "native" and not name.startswith("hero"):
        clean[sample["alert_id"]] = sample
a, b, c = st.columns(3)
alert_id = a.selectbox("Clean alert", list(clean))
family = b.selectbox("Injection family", FAMILIES, format_func=lambda f: f.replace("_", " "))
field = c.selectbox("Target field", TARGET_FIELDS, index=TARGET_FIELDS.index("user_agent"))
custom = st.text_area("Or type your own attack", max_chars=MAX_CUSTOM_PAYLOAD,
                      help="Your text is added to the target field, in place of the injection family.")
s = get_settings()
SIMULATED = "Simulated gullible model (instant)"
models = [SIMULATED] + ([f"{s.llm_provider}: {s.llm_model}"] if s.llm_provider != "mock" else [])
choice = st.radio("Model", models, horizontal=True, help="Add a real model on the Settings page.")
if custom.strip() and choice == SIMULATED:
    st.caption("The simulated model only obeys wording it recognises. Use a real model for a true test of new wording.")
if st.button("Attack", type="primary"):
    provider = None if choice == SIMULATED else main_provider()
    with st.spinner("Attacking. A real model on CPU can take a few minutes."):
        if custom.strip():
            st.session_state["attack"] = attack_custom(clean[alert_id], custom, field, provider)
        else:
            st.session_state["attack"] = attack(clean[alert_id], family, field, provider=provider)
        st.session_state["attack_model"] = choice
out = st.session_state.get("attack")
if not out:
    st.info("Choose a payload and press Attack.")
    st.stop()


def verdict_box(fooled: bool) -> None:
    if fooled:
        st.error("Fooled")
    else:
        st.success("Not fooled")


left, right = st.columns(2, gap="large")
naive, al = out["naive"], out["alertlens"]
st.caption(f"Model: {st.session_state['attack_model']}. Target field: {out['payload_field']}. Attack: {out['family'].replace('_', ' ')}.")
with left:
    st.subheader("Naive LLM")
    verdict_box(out["naive_fooled"])
    st.markdown(f"{sev_badge(naive.severity)} &nbsp; verdict {esc(naive.verdict)}", unsafe_allow_html=True)
    st.text("Actions: " + (", ".join(naive.actions) or "none"))
    st.code(naive.explanation, language=None, wrap_lines=True)
    st.caption(f"The same alert without the payload: {out['naive_clean'].severity}, {out['naive_clean'].verdict}.")
with right:
    st.subheader("AlertLens")
    verdict_box(out["alertlens_fooled"])
    st.markdown(f"{sev_badge(al.severity.label)} &nbsp; score {al.severity.score}", unsafe_allow_html=True)
    st.write("Actions: " + (", ".join(x.action_id for x in al.actions) or "none"))
    st.code(al.explanation.summary, language=None, wrap_lines=True)
    st.caption(f"The same alert without the payload: {out['alertlens_clean'].severity.label}, "
               f"{out['alertlens_clean'].severity.score}.")
injection_banner(al.sanitise.model_dump())
if not al.sanitise.quarantined_fields:
    st.warning("The detector did not flag this text. Severity still came from code, and the explainer never read it. "
               "The layers below show what happened.")
st.subheader("Layers that acted")
for layer in out["layers"]:
    st.markdown(f"**{esc(layer['layer'])}**: {esc(layer['detail'])}", unsafe_allow_html=True)
with st.expander("What the model tried"):
    model_trace_block(al.model_dump(mode="json"))
