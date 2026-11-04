"""F2 and F10: severity and triage, decided by code. No LLM output is read here."""
from __future__ import annotations

from alertlens.schemas import SanitiseReport, SeverityResult, Triage
from alertlens.scoring.counterfactual import find_counterfactuals
from alertlens.scoring.features import READABLE, extract, to_vector
from alertlens.scoring.model import load_model
from alertlens.scoring.rules import score_rules

RULE_WEIGHT, MODEL_WEIGHT = 0.5, 0.5  # equal: rules stay explainable, the model catches combinations
MAX_INJECTION_BUMP = 5.0  # enough to block auto-close and flag it; small, so payloads cannot flood the queue
THRESHOLDS = [(78.0, "critical"), (55.0, "high"), (30.0, "medium")]


def label_of(score: float) -> str:
    for cut, label in THRESHOLDS:
        if score >= cut:
            return label
    return "low"


def injection_bump(risk: float) -> float:
    """A hidden instruction raises severity and can never lower it."""
    return round(MAX_INJECTION_BUMP * risk, 2)


def score_features(features: dict[str, float], risk: float) -> tuple[float, float, float, float, list]:
    """Return (final score, base score, p_malicious, bump, fired rules)."""
    rule_score, fired = score_rules(features)
    p = float(load_model().p_malicious([to_vector(features)])[0])
    base = round(RULE_WEIGHT * rule_score + MODEL_WEIGHT * 100 * p, 2)
    bump = injection_bump(risk)
    return round(min(100.0, base + bump), 2), base, p, bump, fired


def triage_of(p: float, risk: float, critic_objection: bool = False) -> Triage:
    """Never auto-closes. `auto_close_candidate` is only a suggestion for a person."""
    if critic_objection:
        return "needs_human"
    if p > 0.6:
        return "escalate"
    if p < 0.1 and risk == 0:
        return "auto_close_candidate"
    return "needs_human"


def _model_reasons(features: dict[str, float], limit: int = 2) -> list[str]:
    importances = load_model().importances
    active = [(importances.get(k, 0.0), k) for k, v in features.items() if v and k in READABLE]
    active.sort(reverse=True)
    return [f"Model signal: {READABLE[k]}" for _, k in active[:limit]]


def score_alert(alert, sanitise: SanitiseReport, *, counterfactuals: bool = True) -> SeverityResult:
    features = extract(alert)
    score, base, p, bump, fired = score_features(features, sanitise.risk)
    reasons = [f"{reason} (+{points:g})" if points > 0 else f"{reason} ({points:g})" for _, reason, points in fired[:4]]
    reasons += _model_reasons(features)
    if bump:
        reasons.append(f"Hidden instructions found in the alert (+{bump:g})")
    label = label_of(score)
    return SeverityResult(
        score=score, label=label, p_malicious=round(p, 4), confidence=round(max(p, 1 - p), 4), reasons=reasons,
        counterfactuals=find_counterfactuals(features, label, sanitise.risk) if counterfactuals else [],
        triage=triage_of(p, sanitise.risk), base_score=base, injection_bump=bump,
    )
