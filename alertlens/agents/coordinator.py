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


def investigate(payload: dict, provider) -> Debate:
    from alertlens.agents import critic, investigator, triage

    triage_note, tf = triage.run(payload, provider)
    inv_note, inf = investigator.run(payload, provider)
    critic_note, cf = critic.run(payload, provider)
    objection = critic_note.objection_strength >= OBJECTION_THRESHOLD
    factor = round(1 - 0.5 * critic_note.objection_strength, 3)
    final = "needs human review" if objection else triage_note.verdict
    transcript = [
        {"agent": "Triage", "verdict": triage_note.verdict, "reasons": triage_note.reasons, "fallback": tf},
        {"agent": "Investigator", "verdict": inv_note.verdict, "reasons": inv_note.reasons, "fallback": inf},
        {"agent": "Critic", "verdict": critic_note.verdict, "reasons": critic_note.reasons,
         "objection_strength": critic_note.objection_strength, "fallback": cf},
        {"agent": "Coordinator", "verdict": final,
         "reasons": ["The critic objected, so a person should review this." if objection else "No strong objection."]},
    ]
    return Debate(transcript, objection, factor, final)
