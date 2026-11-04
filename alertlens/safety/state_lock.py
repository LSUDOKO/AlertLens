"""F12: freeze goal, severity and evidence before any LLM step, and detect any attempt to change them."""
from __future__ import annotations

import hashlib
import json
import re

from pydantic import BaseModel, ConfigDict

_TAMPER = re.compile(
    r"\b(set|change|lower|downgrade|reduce)\b.{0,30}\b(severity|priority|verdict)\b"
    r"|\bseverity\b.{0,12}\b(should be|is now|to)\b\s*(low|none|medium)\b"
    r"|\bnew (task|goal|instructions?)\b|\bsummari[sz]e the weather\b"
    r"|\b(false positive|safe to close|authori[sz]ed activity|this activity was authori[sz]ed|close (the )?ticket)\b",
    re.IGNORECASE,
)


class TaskState(BaseModel):
    model_config = ConfigDict(frozen=True)

    goal: str
    alert_id: str
    severity_score: float
    severity_label: str
    triage: str
    evidence_hash: str

    def digest(self) -> str:
        return hashlib.sha256(json.dumps(self.model_dump(), sort_keys=True).encode()).hexdigest()


def lock(alert_id: str, severity, evidence: dict) -> tuple[TaskState, str]:
    state = TaskState(
        goal="explain_alert", alert_id=alert_id, severity_score=severity.score, severity_label=severity.label,
        triage=severity.triage,
        evidence_hash=hashlib.sha256(json.dumps(evidence, sort_keys=True, default=str).encode()).hexdigest(),
    )
    return state, state.digest()


def state_intact(state: TaskState, digest: str, severity, evidence: dict) -> bool:
    """Recompute from the live objects, so a mutation anywhere in the pipeline shows up."""
    return lock(state.alert_id, severity, evidence)[1] == digest


def tamper_attempt(text: str, label: str) -> str | None:
    """Return the offending phrase if model output tries to change the outcome.

    Stating the code-decided label is fine: this looks for language that steers it elsewhere.
    """
    if label == "low":
        return None
    m = _TAMPER.search(text)
    return m.group(0) if m else None
