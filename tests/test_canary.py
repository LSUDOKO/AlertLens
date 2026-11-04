import json

from alertlens.llm.provider import LLMResponse, call_structured
from alertlens.pipeline.orchestrator import Options, analyze
from alertlens.safety.canary import leaked
from alertlens.schemas import AgentNote


class EchoLLM:
    """Echoes its system prompt, canary included, in otherwise valid output."""

    name = "echo"

    def complete(self, system, user, *, schema=None, temperature=0.0, max_tokens=800):
        if schema.__name__ == "ExplanationDraft":
            return LLMResponse(json.dumps({"summary": system[-300:], "what_happened": "x", "why_it_matters": "y", "claims": []}), self.name)
        from alertlens.llm.mock import MockLLM

        return MockLLM().complete(system, user, schema=schema)


def test_echoed_canary_triggers_alarm_and_template(hero):
    r = analyze(hero[0], Options(deep=True, persist=False, provider=EchoLLM(), extractor=EchoLLM()))
    assert "prompt_leak" in {e["type"] for e in r.security_events}
    assert r.explanation.safe_fallback and "prompt_leak" in r.explanation.fallback_reasons
    assert "CANARY-" not in r.explanation.summary


def test_leaked():
    assert leaked("xx CANARY-1 yy", "CANARY-1") and not leaked("xx", "CANARY-1") and not leaked("xx", "")


def test_broken_json_retries_once_then_falls_back():
    calls = []

    class Broken:
        name = "broken"

        def complete(self, system, user, *, schema=None, temperature=0.0, max_tokens=800):
            calls.append(1)
            return LLMResponse("not json", self.name)

    out = call_structured(Broken(), "s", "u", AgentNote, lambda: AgentNote(verdict="suspicious"))
    assert len(calls) == 2 and out.fallback and out.value.verdict == "suspicious"


def test_provider_down_falls_back(hero):
    class Down:
        name = "down"

        def complete(self, *a, **k):
            raise OSError("connection refused")

    r = analyze(hero[0], Options(deep=True, persist=False, provider=Down(), extractor=Down()))
    assert r.explanation.safe_fallback and r.explanation.claims and r.severity.label == "critical"


def test_retry_recovers_from_one_bad_output():
    seq = iter(["nope", '{"verdict":"malicious"}'])

    class Flaky:
        name = "flaky"

        def complete(self, *a, **k):
            return LLMResponse(next(seq), self.name)

    out = call_structured(Flaky(), "s", "u", AgentNote, lambda: AgentNote(verdict="benign"))
    assert not out.fallback and out.value.verdict == "malicious"


def test_fenced_json_is_accepted():
    class Fenced:
        name = "f"

        def complete(self, *a, **k):
            return LLMResponse('Sure!\n```json\n{"verdict":"benign"}\n```', self.name)

    assert call_structured(Fenced(), "s", "u", AgentNote, lambda: AgentNote(verdict="malicious")).value.verdict == "benign"
