"""Runtime settings for this UI process. Keys stay in `.env`, and the API process keeps its own settings."""
import streamlit as st

from alertlens.config import get_settings, update_settings
from ui.common import setup

setup("Settings")
st.title("Settings")
s = get_settings()
if s.public_demo:
    # A visitor must not repoint a shared server at another URL or change settings for everyone.
    st.info("Settings are locked on this public demo. It uses simulated models. Run AlertLens locally to use a real model.")
    st.stop()
kinds = ["mock", "ollama", "openai_compat", "gemini", "anthropic"]
with st.form("settings"):
    provider = st.selectbox("LLM provider", kinds, index=kinds.index(s.llm_provider))
    quarantine = st.selectbox("Extractor provider", kinds, index=kinds.index(s.quarantine_provider))
    model = st.text_input("Model name", s.llm_model)
    url = st.text_input("Base URL", s.llm_base_url)
    window = st.number_input("Correlation window, minutes", 1, 1440, s.correlation_window_min)
    agents = st.checkbox("Multi-agent investigation", s.feature_multi_agent)
    hindi = st.checkbox("Hindi explanations", s.feature_hindi)
    if st.form_submit_button("Save settings"):
        if provider != "mock" and not model:
            st.error("Enter a model name for this provider.")
        else:
            update_settings(llm_provider=provider, quarantine_provider=quarantine, llm_model=model, llm_base_url=url,
                            correlation_window_min=int(window), feature_multi_agent=agents, feature_hindi=hindi)
            st.success("Saved settings. API keys stay in .env.")
st.caption(f"API key {'is set' if s.llm_api_key else 'is not set'}. Mock mode needs none.")
