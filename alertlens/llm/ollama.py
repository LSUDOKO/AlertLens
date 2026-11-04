"""Local model through Ollama (`LLM_PROVIDER=ollama`)."""
from alertlens.config import Settings
from alertlens.llm.provider import OllamaLLM


def make_ollama(settings: Settings) -> OllamaLLM:
    if not settings.llm_model:
        raise ValueError("LLM_PROVIDER=ollama needs LLM_MODEL set in .env")
    return OllamaLLM(base_url=settings.llm_base_url, model=settings.llm_model)
