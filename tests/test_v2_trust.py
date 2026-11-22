"""Provenance, ATT&CK retrieval, the cross-model judge and the evidence-backed agent ledger."""
import json

from alertlens.agents.coordinator import investigate
from alertlens.llm.mock import MockLLM
from alertlens.llm.provider import LLMResponse
from alertlens.llm.quarantined import fact_sources
from alertlens.pipeline.orchestrator import Options, analyze
from alertlens.pipeline.service import hero_alerts
from alertlens.schemas import AgentNote, ExtractedFacts


def hero(i=1):
    return hero_alerts()[i]


def facts(**kw):
    base = {"action_type": "other", "outcome": "unknown", "is_admin_action": False, "suspicious_tool": "none", "notes_code": []}
    return ExtractedFacts(**{**base, **kw})


def test_fact_sources_say_who_decided_each_fact():
    code = facts(action_type="login", outcome="unknown")
    llm = facts(action_type="file_write", outcome="success")
    src = fact_sources(llm, code, ["action_type"])
    assert src["facts.action_type"] == "code, model overruled"
    assert src["facts.outcome"] == "model"
    assert src["facts.suspicious_tool"] == "code"
    assert all(v == "code" for v in fact_sources(None, code, []).values())


def test_every_claim_key_has_a_provenance_label():
    r = analyze(hero(), Options(persist=False, deep=True, provider=MockLLM(), extractor=MockLLM()))
    for claim in r.explanation.claims:
        for key in claim.evidence:
            assert key in r.provenance, key
    assert r.provenance["alert.user"] == "sensor"
    assert r.provenance["severity.label"] == "code"
    assert any(v == "ATT&CK catalogue" for k, v in r.provenance.items() if k.startswith("mitre."))


def test_attack_description_comes_from_the_catalogue_not_the_alert():
    r = analyze(hero(), Options(persist=False, deep=True, keep_payload=True, provider=MockLLM(), extractor=MockLLM()))
    tech = r.facts_payload["mitre"][0]
    assert tech["description"] and tech["detection"]
    assert "NOTE TO AI" not in json.dumps(r.facts_payload)


class StrictJudge(MockLLM):
    """A judge that rejects the first claim, to check the judge can only remove."""

    def complete(self, system, user, *, schema=None, temperature=0.0, max_tokens=800):
        if schema and schema.__name__ == "JudgeVerdict":
            return LLMResponse(json.dumps({"verdicts": [{"index": 0, "supported": False, "reason": "not in facts"}]}), "strict", "judge")
        return super().complete(system, user, schema=schema, temperature=temperature, max_tokens=max_tokens)


def test_judge_removes_but_never_adds_or_changes_severity():
    base = analyze(hero(), Options(persist=False, deep=True, provider=MockLLM(), extractor=MockLLM()))
    judged = analyze(hero(), Options(persist=False, deep=True, provider=MockLLM(), extractor=MockLLM(), judge=StrictJudge()))
    assert len(judged.explanation.claims) == len(base.explanation.claims) - 1
    assert judged.explanation.removed_claims[-1].reason.startswith("cross-model check")
    assert judged.severity.score == base.severity.score and judged.severity.label == base.severity.label
    assert judged.explanation.judge["removed"] == 1
    assert any(t["stage"] == "judge" for t in judged.model_trace)


def test_judge_is_off_by_default_and_the_mock_stand_in_removes_nothing():
    off = analyze(hero(), Options(persist=False, deep=True, provider=MockLLM(), extractor=MockLLM()))
    assert off.explanation.judge == {}
    on = analyze(hero(), Options(persist=False, deep=True, provider=MockLLM(), extractor=MockLLM(), judge=MockLLM()))
    assert on.explanation.judge["removed"] == 0


class LoudCritic(MockLLM):
    """A critic that objects strongly, with or without real evidence."""

    def __init__(self, evidence):
        self.evidence = evidence

    def complete(self, system, user, *, schema=None, temperature=0.0, max_tokens=800):
        if schema and schema.__name__ == "AgentNote" and "critic agent" in system:
            note = AgentNote(verdict="benign", reasons=["looks routine"], objection_strength=0.9, evidence=self.evidence)
            return LLMResponse(note.model_dump_json(), "loud", "critic")
        return super().complete(system, user, schema=schema, temperature=temperature, max_tokens=max_tokens)


def test_an_objection_counts_only_with_evidence_that_exists():
    r = analyze(hero(), Options(persist=False, deep=True, keep_payload=True, provider=MockLLM(), extractor=MockLLM()))
    payload = r.facts_payload
    made_up = investigate(payload, LoudCritic(["alert.vibes"]))
    real = investigate(payload, LoudCritic(["alert.device_known"]))
    assert not made_up.objection and made_up.transcript[2]["unknown_evidence"] == ["alert.vibes"]
    assert real.objection and real.transcript[2]["evidence"] == ["alert.device_known"]
