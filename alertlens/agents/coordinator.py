"""F9: Triage, Investigator, Critic, then a coordinator. All agents see facts only.

The coordinator is code. A strong objection can lower confidence and send the alert to a person.
It cannot change the severity score or close anything.
"""
from __future__ import annotations

import json
import secrets
from dataclasses import dataclass

from alertlens.llm.provider import call_structured
from alertlens.llm.quarantined import load_prompt
from alertlens.llm.templates import agent_template
from alertlens.safety.canary import leaked
from alertlens.schemas import AgentNote

OBJECTION_THRESHOLD = 0.5


def run_agent(role: str, task: str, payload: dict, provider) -> tuple[AgentNote, bool]:
    _, template = load_prompt("agent")
    canary = f"CANARY-{secrets.token_hex(4)}"
    system = template.format(role=role, task=task, canary=canary)
    user = f"<<FACTS>>{json.dumps(payload, ensure_ascii=False, default=str)}<<END-FACTS>>"
    call = call_structured(provider, system, user, AgentNote, lambda: agent_template(role, payload), max_tokens=300,
                           extra_check=lambda text, _: "prompt_leak" if leaked(text, canary) else None)
    return call.value, call.fallback


@dataclass
class Debate:
    transcript: list[dict]
    objection: bool
    confidence_factor: float
    final_verdict: str


def ledger_entry(agent: str, note: AgentNote, fallback: bool, keys: dict[str, object]) -> dict:
    """One agent's turn, with each cited key checked against the facts it was given."""
    valid = [k for k in note.evidence if k in keys]
    return {"agent": agent, "verdict": note.verdict, "reasons": note.reasons, "evidence": valid,
            "unknown_evidence": [k for k in note.evidence if k not in keys][:5], "fallback": fallback}


def investigate(payload: dict, provider) -> Debate:
    """Three agents, then a code coordinator. A challenge counts only when it cites facts that exist."""
    from alertlens.agents import critic, investigator, triage
    from alertlens.llm.explainer import evidence_map

    keys = evidence_map(payload)
    triage_note, tf = triage.run(payload, provider)
    inv_note, inf = investigator.run(payload, provider)
    critic_note, cf = critic.run(payload, provider)
    critic_entry = ledger_entry("Critic", critic_note, cf, keys)
    backed = bool(critic_entry["evidence"])
    strength = critic_note.objection_strength if backed else 0.0
    objection = strength >= OBJECTION_THRESHOLD
    factor = round(1 - 0.5 * strength, 3)
    final = "needs human review" if objection else triage_note.verdict
    if objection:
        why = "The critic objected with evidence, so a person should review this."
    elif critic_note.objection_strength >= OBJECTION_THRESHOLD:
        why = "The critic objected but cited no facts that exist, so the objection was set aside."
    else:
        why = "No strong objection."
    transcript = [
        ledger_entry("Triage", triage_note, tf, keys),
        ledger_entry("Investigator", inv_note, inf, keys),
        {**critic_entry, "objection_strength": critic_note.objection_strength, "objection_counted": objection},
        {"agent": "Coordinator", "verdict": final, "reasons": [why], "evidence": critic_entry["evidence"] if objection else []},
    ]
    return Debate(transcript, objection, factor, final)
