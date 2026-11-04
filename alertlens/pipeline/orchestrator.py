"""Runs the stages in order and returns an `AnalysisResult`.

Untrusted text is read only by deterministic code and by the quarantined extractor. Everything after
the extractor works on validated facts and placeholders. Vault values return only at rendering.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass

from alertlens.agents.coordinator import investigate
from alertlens.audit import chain
from alertlens.config import get_settings
from alertlens.ingest.adapters import vendor_extra
from alertlens.ingest.normalise import clean_identifier, normalise
from alertlens.llm.explainer import build_facts_payload, evidence_map, explain, strip_markup
from alertlens.llm.provider import LLMProvider, build_provider, main_provider, quarantine_provider
from alertlens.llm.quarantined import deterministic_facts, extract_facts
from alertlens.llm.templates import explanation_template
from alertlens.memory import store as db
from alertlens.memory.retriever import similar_cases
from alertlens.mitre.mapper import RULE_CATALOGUE, map_alert
from alertlens.mitre.predictor import predict_next
from alertlens.pipeline.router import EST_TOKENS_LLM_PATH, choose_route
from alertlens.remediation.recommender import filter_suggestions, recommend
from alertlens.render.audience import context_from, render_all
from alertlens.safety.canary import leaked
from alertlens.safety.injection import scan_alert
from alertlens.safety.pii import Vault
from alertlens.safety.state_lock import lock, state_intact, tamper_attempt
from alertlens.safety.verifier import verify_claims, verify_prose
from alertlens.schemas import Alert, AnalysisResult, Claim, Explanation, SanitiseReport, SeverityResult
from alertlens.scoring.scorer import label_of, score_alert, triage_of

log = logging.getLogger(__name__)
GOAL = "explain_alert"


@dataclass
class Options:
    """Switches. Everything defaults on; the benchmark turns layers off for ablations."""

    audience: str = "analyst"
    lang: str = "en"
    deep: bool = False
    persist: bool = True
    db_path: str | None = None
    counterfactuals: bool = True
    provider: LLMProvider | None = None
    extractor: LLMProvider | None = None
    context: dict | None = None
    # Ablation switches. Only the benchmark and the tests turn these off.
    sanitiser: bool = True
    dual_llm: bool = True
    verifier: bool = True
    output_guards: bool = True
    code_severity: bool = True


class Clock:
    def __init__(self):
        self.timings: dict[str, float] = {}
        self._t = time.perf_counter()

    def lap(self, name: str) -> None:
        now = time.perf_counter()
        self.timings[name] = round((now - self._t) * 1000, 2)
        self._t = now


def analyze(obj: dict, options: Options | None = None) -> AnalysisResult:
    """Analyse one alert in any supported format."""
    o = options or Options()
    clock = Clock()
    events: list[dict] = []

    def event(kind: str, **detail) -> None:
        events.append({"type": kind, **detail})

    alert = normalise(obj)
    clock.lap("ingest")
    sanitise = scan_alert(alert) if o.sanitiser else SanitiseReport()
    if sanitise.quarantined_fields:
        event("injection_detected", fields=sanitise.quarantined_fields,
              families=sorted({f.pattern_family for f in sanitise.findings}))
    clock.lap("sanitise")
    severity = score_alert(alert, sanitise, counterfactuals=o.counterfactuals)
    clock.lap("score")
    mitre = map_alert(alert)
    similar = similar_cases(alert, mitre)
    clock.lap("map_and_retrieve")

    known = alert.rule_id in RULE_CATALOGUE
    route = choose_route(severity.p_malicious, sanitise.risk, known, o.deep)
    provider = o.provider or main_provider()
    extractor = o.extractor or (build_provider(get_settings().quarantine_provider) if o.provider is None
                                else o.provider) if route == "llm" else None
    vault = Vault()
    prompt_versions: list[str] = []
    llm_tokens = 0

    if route == "llm":
        outcome = extract_facts(alert, sanitise if o.sanitiser else None, vault, extractor or quarantine_provider())
        facts = outcome.facts
        prompt_versions.append(outcome.prompt_version)
        llm_tokens += outcome.call.tokens or 0
        if outcome.conflicts:
            event("fact_conflict", fields=outcome.conflicts)
        if outcome.call.error == "prompt_leak":
            event("prompt_leak", stage="extractor")
    else:
        facts = deterministic_facts(alert)
    clock.lap("extract")

    payload = build_facts_payload(alert, facts, severity, mitre, sanitise, vault, similar, o.context)
    evidence = evidence_map(payload)
    state, digest = lock(alert.alert_id, severity, payload["severity"])

    agent_transcript: list[dict] = []
    if route == "llm" and get_settings().feature_multi_agent:
        debate = investigate(payload, provider)
        agent_transcript = debate.transcript
        if debate.objection:
            # Code applies this. It can only send the alert to a person, never lower the score.
            severity.triage = triage_of(severity.p_malicious, sanitise.risk, critic_objection=True)
            severity.confidence = round(severity.confidence * debate.confidence_factor, 4)
            payload["severity"]["severity.triage"] = severity.triage
            evidence = evidence_map(payload)
            state, digest = lock(alert.alert_id, severity, payload["severity"])
            event("critic_objection", confidence=severity.confidence)
    clock.lap("agents")

    fallback_reasons: list[str] = []
    suggested: list[str] = []
    template = explanation_template(payload)
    if route == "llm":
        result = explain(payload, provider, raw_alert=alert.raw if not o.dual_llm else None,
                         check_canary=o.output_guards)
        prompt_versions.append(result.prompt_version)
        llm_tokens += result.call.tokens or 0
        draft = result.call.value
        suggested = list(draft.suggested_action_ids)
        if result.call.fallback:
            fallback_reasons.append(result.call.error or "model output rejected")
            if result.call.error == "prompt_leak":
                event("prompt_leak", stage="explainer")
        if o.output_guards:
            prose = " ".join([draft.summary, draft.what_happened, draft.why_it_matters,
                              *[c.text for c in draft.claims]])
            if phrase := tamper_attempt(prose, severity.label):
                event("state_tamper", phrase=phrase[:80])
            if not state_intact(state, digest, severity, payload["severity"]):
                event("state_tamper", phrase="task state changed")
                raise RuntimeError("Task state changed during analysis")
            if leaked(prose, result.canary):
                event("prompt_leak", stage="explainer")
                draft = template
                fallback_reasons.append("prompt_leak")
    else:
        draft = template
    clock.lap("explain")

    if o.verifier:
        kept, removed, grounding = verify_claims(draft.claims, evidence, severity.label)
        if removed:
            event("unsupported_claims", count=len(removed), reasons=[c.reason for c in removed][:3])
        reasons = [r for r in (verify_prose(t, evidence, severity.label)
                               for t in (draft.summary, draft.what_happened, draft.why_it_matters)) if r]
        if reasons:
            fallback_reasons += reasons
            prose_src = template
        else:
            prose_src = draft
        if not kept:
            kept, _, grounding = verify_claims(template.claims, evidence, severity.label)
            fallback_reasons.append("no claim survived verification")
    else:
        kept = [Claim(text=c.text, evidence=c.evidence, key=c.key, status="verified") for c in draft.claims]
        removed, grounding, prose_src = [], 1.0, draft
    clock.lap("verify")

    _, rejected = filter_suggestions(suggested)
    if rejected:
        event("unsafe_action_blocked", ids=[str(r)[:40] for r in rejected][:5])
    actions = recommend(alert, severity, sanitise, mitre, suggested)
    for action in actions:
        action.instance_id = f"{alert.alert_id}:{action.action_id}"
    clock.lap("recommend")

    def final(text: str) -> str:
        return vault.restore(strip_markup(text))

    for claim in [*kept, *removed]:
        claim.text = final(claim.text)
    explanation = Explanation(
        summary=final(prose_src.summary), what_happened=final(prose_src.what_happened),
        why_it_matters=final(prose_src.why_it_matters), claims=kept, removed_claims=removed,
        grounding_score=grounding, audience=o.audience, language=o.lang,
        safe_fallback=bool(fallback_reasons), fallback_reasons=fallback_reasons,
    )
    entry = RULE_CATALOGUE.get(alert.rule_id, {})
    view = {
        "user": clean_identifier(alert.user), "host": clean_identifier(alert.host),
        "src_ip": clean_identifier(alert.src_ip), "dst_ip": clean_identifier(alert.dst_ip),
        "title": entry.get("title", "a detection rule"), "rule_id": payload["alert"]["alert.rule_id"],
        "rule_level": alert.rule_level, "event_count": alert.event_count, "criticality": alert.asset_criticality,
        "volume_mb": facts.data_volume_mb, "geo_country": payload["alert"].get("alert.geo_country"),
        "tool": facts.suspicious_tool,
    }
    renderings = render_all(explanation, context_from(view, severity, mitre, sanitise, actions),
                            hindi=get_settings().feature_hindi)
    predicted = predict_next(_tactics(mitre))

    if not o.code_severity:
        _apply_llm_severity(severity, alert, provider)
    clock.lap("render")

    audit_seq = 0
    result_obj = AnalysisResult(
        alert=alert, sanitise=sanitise, facts=facts, severity=severity, mitre=mitre, explanation=explanation,
        renderings=renderings, actions=actions, similar_cases=similar, predicted_next=predicted,
        agent_transcript=agent_transcript, route=route, timings_ms=clock.timings, audit_seq=audit_seq,
        security_events=events,
    )
    if o.persist:
        _persist(result_obj, o, prompt_versions, EST_TOKENS_LLM_PATH if route == "llm" else 0)
    return result_obj


def _tactics(mitre: list[dict]) -> list[str]:
    seen: list[str] = []
    for t in mitre:
        if t["tactic"] not in seen:
            seen.append(t["tactic"])
    return seen


def _apply_llm_severity(severity: SeverityResult, alert: Alert, provider: LLMProvider) -> None:
    """Ablation only: what happens if the model reads the raw alert and decides severity."""
    from alertlens.pipeline.redteam import naive_verdict

    verdict = naive_verdict(alert.raw, provider)
    severity.label = verdict.severity
    severity.score = {"low": 15.0, "medium": 45.0, "high": 70.0, "critical": 90.0}[verdict.severity]
    if verdict.verdict == "benign":
        severity.triage = "auto_close_candidate"


def _persist(result: AnalysisResult, o: Options, prompt_versions: list[str], tokens: int) -> None:
    total_ms = sum(result.timings_ms.values())
    with db.db(o.db_path) as conn:
        for ev in result.security_events:
            chain.append(conn, "pipeline", ev["type"], {"alert_id": result.alert.alert_id, **ev})
        result.audit_seq = chain.append(conn, "pipeline", "analysis", {
            "alert_id": result.alert.alert_id, "label": result.severity.label, "score": result.severity.score,
            "triage": result.severity.triage, "route": result.route, "grounding": result.explanation.grounding_score,
            "prompt_versions": prompt_versions, "actions": [a.action_id for a in result.actions],
        })
        db.save_analysis(conn, result)
        db.bump_router(conn, result.route, total_ms, tokens)


__all__ = ["Options", "analyze", "label_of", "vendor_extra"]
