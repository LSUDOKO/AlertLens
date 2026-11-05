"""Settings and feature flags, read from the environment and `.env`."""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field, replace
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")


def _env(key: str, default: str) -> str:
    """Read an env var, tolerating inline comments copied from `.env.example`."""
    raw = os.environ.get(key)
    if raw is None:
        return default
    return re.sub(r"\s+#.*$", "", raw).strip() or default


def _flag(key: str, default: bool) -> bool:
    return _env(key, str(default)).lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    llm_provider: str = "mock"
    llm_model: str = ""
    llm_base_url: str = "http://localhost:11434"
    llm_api_key: str = field(default="", repr=False)
    quarantine_provider: str = "mock"
    embeddings: str = "tfidf"
    correlation_window_min: int = 30
    router_llm_threshold: float = 0.35
    feature_multi_agent: bool = True
    feature_hindi: bool = True
    feature_injection_classifier: bool = True
    public_demo: bool = False
    db_path: str = "alertlens.db"
    seed: int = 42
    model_path: str = str(ROOT / "models" / "severity.joblib")
    rule_weights_path: str = str(ROOT / "models" / "rule_weights.json")


def load_settings() -> Settings:
    return Settings(
        llm_provider=_env("LLM_PROVIDER", "mock"),
        llm_model=_env("LLM_MODEL", ""),
        llm_base_url=_env("LLM_BASE_URL", "http://localhost:11434"),
        llm_api_key=_env("LLM_API_KEY", ""),
        quarantine_provider=_env("QUARANTINE_PROVIDER", "mock"),
        embeddings=_env("EMBEDDINGS", "tfidf"),
        correlation_window_min=int(_env("CORRELATION_WINDOW_MIN", "30")),
        router_llm_threshold=float(_env("ROUTER_LLM_THRESHOLD", "0.35")),
        feature_multi_agent=_flag("FEATURE_MULTI_AGENT", True),
        feature_hindi=_flag("FEATURE_HINDI", True),
        feature_injection_classifier=_flag("FEATURE_INJECTION_CLASSIFIER", True),
        public_demo=_flag("PUBLIC_DEMO", False),
        db_path=_env("DB_PATH", "alertlens.db"),
        seed=int(_env("SEED", "42")),
        model_path=_env("MODEL_PATH", str(ROOT / "models" / "severity.joblib")),
        rule_weights_path=_env("RULE_WEIGHTS_PATH", str(ROOT / "models" / "rule_weights.json")),
    )


_current = load_settings()


def get_settings() -> Settings:
    return _current


def update_settings(**changes) -> Settings:
    """Change settings at runtime (Settings page)."""
    global _current
    _current = replace(_current, **changes)
    return _current
