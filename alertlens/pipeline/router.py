"""F20: skip the LLM when it would add nothing."""
from __future__ import annotations

from alertlens.config import get_settings

EST_TOKENS_LLM_PATH = 1200  # rough size of one extractor, explainer and three agent calls


def choose_route(p: float, risk: float, known_pattern: bool, deep: bool) -> str:
    low = get_settings().router_llm_threshold
    in_band = low <= p <= 1 - low
    if deep or in_band or risk > 0 or not known_pattern:
        return "llm"
    return "fast"
