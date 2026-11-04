"""OpenAI-compatible endpoints. Gemini and Anthropic both expose one, so they share this path."""
from alertlens.config import Settings
from alertlens.llm.provider import HOSTED_DEFAULTS, HttpChatLLM


def make_openai_compat(kind: str, settings: Settings) -> HttpChatLLM:
    if not settings.llm_model:
        raise ValueError(f"LLM_PROVIDER={kind} needs LLM_MODEL set in .env")
    base = HOSTED_DEFAULTS.get(kind, settings.llm_base_url)
    return HttpChatLLM(name=kind, base_url=base, model=settings.llm_model, api_key=settings.llm_api_key)
