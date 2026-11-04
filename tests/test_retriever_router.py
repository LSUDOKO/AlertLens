import pytest

from alertlens.config import get_settings, update_settings
from alertlens.ingest.normalise import normalise
from alertlens.memory.retriever import similar_cases
from alertlens.mitre.mapper import map_alert
from alertlens.pipeline.orchestrator import Options, analyze
from alertlens.pipeline.router import choose_route


def test_brute_force_retrieves_brute_force_cases(hero):
    a = normalise(hero[0])
    top = similar_cases(a, map_alert(a))
    assert len(top) == 3
    assert any("failed logins" in c["summary"].lower() or "T1110" in c["techniques"] for c in top)
    assert top[0]["similarity"] >= top[-1]["similarity"]


@pytest.mark.parametrize("p,risk,known,deep,route", [
    (0.99, 0, True, False, "fast"), (0.01, 0, True, False, "fast"), (0.5, 0, True, False, "llm"), (0.99, 0.2, True, False, "llm"),
    (0.99, 0, False, False, "llm"), (0.99, 0, True, True, "llm"),
])
def test_routes(p, risk, known, deep, route):
    assert choose_route(p, risk, known, deep) == route


def test_fast_path_makes_no_llm_call(hero):
    class Forbidden:
        name = "forbidden"

        def complete(self, *a, **k):
            raise AssertionError("fast path called an LLM")

    r = analyze(hero[0], Options(persist=False, provider=Forbidden(), extractor=Forbidden()))
    assert r.route == "fast" and not r.explanation.safe_fallback


def test_bad_provider_name_is_clear():
    from alertlens.llm.provider import build_provider

    with pytest.raises(ValueError, match="Unknown LLM provider"):
        build_provider("nope")
    old = get_settings()
    update_settings(llm_model="")
    with pytest.raises(ValueError, match="LLM_MODEL"):
        build_provider("ollama")
    with pytest.raises(ValueError, match="LLM_MODEL"):
        build_provider("gemini")
    update_settings(llm_model=old.llm_model)
