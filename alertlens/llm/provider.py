"""The one door to every LLM. No other module talks to a model.

`call_structured` is what the pipeline uses: it parses into a Pydantic model, retries once,
then falls back to a code-written template. `prompt_log` keeps the exact prompts sent, so
tests assert on real prompts rather than reconstructions.
"""
from __future__ import annotations

import json
import logging
import re
import time
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Protocol, TypeVar

from pydantic import BaseModel, ValidationError

from alertlens.config import Settings, get_settings

log = logging.getLogger(__name__)
T = TypeVar("T", bound=BaseModel)


@dataclass
class LLMResponse:
    text: str
    provider: str
    model: str = ""
    latency_ms: float = 0.0
    tokens: int | None = None
    fallback: bool = False


class LLMProvider(Protocol):
    name: str

    def complete(self, system: str, user: str, *, schema: type[BaseModel] | None = None,
                 temperature: float = 0.0, max_tokens: int = 800) -> LLMResponse: ...


@dataclass
class HttpChatLLM:
    """Any OpenAI-compatible chat endpoint (Groq, OpenRouter, LM Studio, vLLM, Gemini, Anthropic)."""

    name: str
    base_url: str
    model: str
    api_key: str = field(default="", repr=False)
    timeout: float = 300.0

    def complete(self, system, user, *, schema=None, temperature=0.0, max_tokens=800) -> LLMResponse:
        t0 = time.perf_counter()
        body = {
            "model": self.model, "temperature": temperature, "max_tokens": max_tokens,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
        }
        if schema is not None:
            body["response_format"] = {"type": "json_object"}
        data = _post_json(f"{self.base_url.rstrip('/')}/chat/completions", body, self.api_key, self.timeout)
        return LLMResponse(
            text=data["choices"][0]["message"]["content"], provider=self.name, model=self.model,
            latency_ms=(time.perf_counter() - t0) * 1000,
            tokens=(data.get("usage") or {}).get("total_tokens"),
        )


@dataclass
class OllamaLLM:
    """A local model through Ollama."""

    base_url: str
    model: str
    timeout: float = 600.0
    name: str = "ollama"

    def complete(self, system, user, *, schema=None, temperature=0.0, max_tokens=800) -> LLMResponse:
        t0 = time.perf_counter()
        body = {
            "model": self.model, "stream": False,
            "options": {"temperature": temperature, "num_predict": max_tokens, "seed": 42},
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
        }
        if schema is not None:
            body["format"] = schema.model_json_schema()
        data = _post_json(f"{self.base_url.rstrip('/')}/api/chat", body, "", self.timeout)
        tokens = (data.get("prompt_eval_count") or 0) + (data.get("eval_count") or 0)
        return LLMResponse(
            text=data["message"]["content"], provider=self.name, model=self.model,
            latency_ms=(time.perf_counter() - t0) * 1000, tokens=tokens or None,
        )


def _post_json(url: str, body: dict, api_key: str, timeout: float) -> dict:
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    req = urllib.request.Request(url, json.dumps(body).encode(), headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - operator-configured URL
        return json.loads(resp.read())


TRACE_REPLY_LIMIT = 4000


@dataclass
class RecordingProvider:
    """Wraps a provider and keeps the exact prompts it was sent."""

    inner: LLMProvider
    prompt_log: list[dict] = field(default_factory=list)

    @property
    def name(self) -> str:
        return self.inner.name

    def complete(self, system, user, *, schema=None, temperature=0.0, max_tokens=800) -> LLMResponse:
        self.prompt_log.append({"system": system, "user": user, "schema": schema.__name__ if schema else None})
        return self.inner.complete(system, user, schema=schema, temperature=temperature, max_tokens=max_tokens)


@dataclass
class TracingProvider:
    """Wraps a provider and keeps what the model replied, for the "what the model tried" panel."""

    inner: LLMProvider
    trace: list[dict]
    stage: str

    @property
    def name(self) -> str:
        return self.inner.name

    def complete(self, system, user, *, schema=None, temperature=0.0, max_tokens=800) -> LLMResponse:
        entry = {"stage": self.stage, "provider": self.inner.name, "model": getattr(self.inner, "model", ""), "reply": "",
                 "latency_ms": 0, "tokens": None, "error": None}
        self.trace.append(entry)
        try:
            resp = self.inner.complete(system, user, schema=schema, temperature=temperature, max_tokens=max_tokens)
        except Exception as exc:
            entry["error"] = f"{type(exc).__name__}: {str(exc)[:160]}"
            raise
        entry.update(model=resp.model, reply=resp.text[:TRACE_REPLY_LIMIT], latency_ms=round(resp.latency_ms), tokens=resp.tokens)
        return resp


HOSTED_DEFAULTS = {
    "gemini": "https://generativelanguage.googleapis.com/v1beta/openai",
    "anthropic": "https://api.anthropic.com/v1",
}


def build_provider(kind: str, settings: Settings | None = None) -> LLMProvider:
    s = settings or get_settings()
    if kind == "mock":
        from alertlens.llm.mock import MockLLM
        return MockLLM()
    if kind == "ollama":
        from alertlens.llm.ollama import make_ollama
        return make_ollama(s)
    if kind in {"openai_compat", "gemini", "anthropic"}:
        from alertlens.llm.openai_compat import make_openai_compat
        return make_openai_compat(kind, s)
    raise ValueError(f"Unknown LLM provider: {kind!r}")


def main_provider() -> LLMProvider:
    return build_provider(get_settings().llm_provider)


def quarantine_provider() -> LLMProvider:
    return build_provider(get_settings().quarantine_provider)


_FENCE = re.compile(r"^```(?:json)?\s*|\s*```$", re.MULTILINE)


def parse_json_output(text: str, schema: type[T]) -> T:
    """Parse model text into `schema`. Tolerates code fences and prose around one JSON object."""
    cleaned = _FENCE.sub("", text).strip()
    start, end = cleaned.find("{"), cleaned.rfind("}")
    if start == -1 or end == -1:
        raise ValueError("no JSON object in model output")
    return schema.model_validate_json(cleaned[start:end + 1])


@dataclass
class StructuredResult:
    value: BaseModel
    raw_text: str
    fallback: bool
    provider: str
    model: str = ""
    latency_ms: float = 0.0
    tokens: int | None = None
    error: str | None = None


def call_structured(provider: LLMProvider, system: str, user: str, schema: type[T],
                    fallback: Callable[[], T], *, max_tokens: int = 800,
                    extra_check: Callable[[str, T], str | None] | None = None) -> StructuredResult:
    """Call, validate, retry once, then use the template. `extra_check` returns a reason to reject."""
    error: str | None = None
    latency = 0.0
    tokens = None
    model = ""
    for _ in range(2):
        try:
            resp = provider.complete(system, user, schema=schema, temperature=0.0, max_tokens=max_tokens)
            latency += resp.latency_ms
            tokens = resp.tokens
            model = resp.model
            value = parse_json_output(resp.text, schema)
            if extra_check and (reason := extra_check(resp.text, value)):
                # A guard rejection is a safety event, not a formatting slip: do not retry.
                return StructuredResult(fallback(), resp.text, True, provider.name, model, latency, tokens, reason)
            return StructuredResult(value, resp.text, False, provider.name, model, latency, tokens)
        except (ValidationError, ValueError, OSError, KeyError, IndexError, TypeError) as exc:
            error = f"{type(exc).__name__}: {str(exc)[:160]}"
            log.warning("LLM call failed (%s): %s", provider.name, error)
    return StructuredResult(fallback(), "", True, provider.name, model, latency, tokens, error)
