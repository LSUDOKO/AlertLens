"""Every data object passed between pipeline stages."""
from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

Severity = Literal["low", "medium", "high", "critical"]
Triage = Literal["auto_close_candidate", "needs_human", "escalate"]
Audience = Literal["analyst", "manager", "employee"]
Language = Literal["en", "hi"]


class Entity(BaseModel):
    kind: Literal["user", "host", "ip", "process", "file", "domain", "hash"]
    value: str
    role: Literal["source", "target", "actor", "object"] | None = None


class Alert(BaseModel):
    alert_id: str
    source_format: Literal["native", "wazuh", "suricata", "sigma"]
    timestamp: datetime
    rule_id: str
    rule_name: str
    rule_level: int = Field(ge=0, le=15)
    category: Literal["authentication", "network", "endpoint", "web", "cloud", "data"]
    src_ip: str | None = None
    dst_ip: str | None = None
    user: str | None = None
    host: str | None = None
    process: str | None = None
    command_line: str | None = None
    file_hash: str | None = None
    url: str | None = None
    geo_country: str | None = None
    device_known: bool | None = None
    event_count: int = Field(default=1, ge=0)
    asset_criticality: Literal["low", "medium", "high", "crown_jewel"] = "medium"
    user_privilege: Literal["standard", "admin", "service"] = "standard"
    mitre_hint: list[str] = []
    raw: dict  # the original vendor JSON (UNTRUSTED)
    entities: list[Entity] = []


class InjectionFinding(BaseModel):
    field_path: str
    pattern_family: str
    matched_text_preview: str  # truncated, for UI only
    score: float


class SanitiseReport(BaseModel):
    findings: list[InjectionFinding] = []
    risk: float = 0.0
    quarantined_fields: list[str] = []


class ExtractedFacts(BaseModel):
    """Output of the QUARANTINED LLM. Closed vocabulary only, so it cannot carry instructions."""

    model_config = ConfigDict(extra="forbid")

    action_type: Literal[
        "login", "login_failed", "process_start", "network_conn", "file_write",
        "privilege_change", "data_transfer", "dns_query", "other",
    ]
    outcome: Literal["success", "failure", "unknown"]
    is_admin_action: bool
    suspicious_tool: Literal[
        "none", "powershell", "certutil", "psexec", "mimikatz_like", "curl_wget", "scripting", "other",
    ]
    data_volume_mb: float | None = None
    target_count: int | None = None
    notes_code: list[
        Literal["off_hours", "new_device", "new_geo", "many_failures", "encoded_command",
                "rare_process", "external_dst"]
    ] = []


class SeverityResult(BaseModel):
    score: float  # 0-100
    label: Severity
    p_malicious: float  # calibrated
    confidence: float
    reasons: list[str]
    counterfactuals: list[str] = []
    triage: Triage
    base_score: float = 0.0  # before the deliberate injection bump
    injection_bump: float = 0.0


class Claim(BaseModel):
    text: str
    evidence: list[str]  # field paths, e.g. "alert.src_ip"
    status: Literal["verified", "partially_verified", "unsupported"] = "verified"
    key: str | None = None  # template id, lets Hindi re-render the same verified claim
    reason: str | None = None  # why the verifier downgraded it


class ClaimDraft(BaseModel):
    model_config = ConfigDict(extra="forbid")

    text: str = Field(max_length=400)
    evidence: list[str]
    key: str | None = None


class ExplanationDraft(BaseModel):
    """Output of the PRIVILEGED LLM, before verification."""

    model_config = ConfigDict(extra="forbid")

    summary: str = Field(max_length=600)
    what_happened: str = Field(max_length=800)
    why_it_matters: str = Field(max_length=800)
    claims: list[ClaimDraft]
    suggested_action_ids: list[str] = []


class Explanation(BaseModel):
    summary: str
    what_happened: str
    why_it_matters: str
    claims: list[Claim]
    removed_claims: list[Claim] = []
    grounding_score: float
    audience: Audience = "analyst"
    language: Language = "en"
    safe_fallback: bool = False
    fallback_reasons: list[str] = []


class Action(BaseModel):
    action_id: str  # must exist in playbook.yaml
    title: str
    reason: str
    risk_level: Literal["low", "medium", "high"]
    reversible: bool
    requires_approval: bool
    dry_run_preview: str
    rollback: str
    status: Literal["proposed", "pending_confirmation", "approved", "rejected", "simulated"] = "proposed"
    instance_id: str | None = None
    two_step: bool = False


class AgentNote(BaseModel):
    """One agent's turn. Closed verdict plus short reason codes."""

    model_config = ConfigDict(extra="forbid")

    verdict: Literal["benign", "suspicious", "malicious"]
    reasons: list[str] = []
    objection_strength: float = Field(default=0.0, ge=0.0, le=1.0)


class Incident(BaseModel):
    incident_id: str
    alert_ids: list[str]
    entities: list[Entity]
    tactics_sequence: list[str]
    severity: SeverityResult
    timeline: list[dict]
    graph_summary: str
    predicted_next: list[dict]
    pivot: str | None = None
    graph: dict = {}


class AnalysisResult(BaseModel):
    alert: Alert
    sanitise: SanitiseReport
    facts: ExtractedFacts
    severity: SeverityResult
    mitre: list[dict]
    explanation: Explanation
    renderings: dict[str, dict[str, dict]] = {}
    actions: list[Action]
    similar_cases: list[dict]
    predicted_next: list[dict] = []
    agent_transcript: list[dict] = []
    route: Literal["fast", "llm"]
    incident_id: str | None = None
    timings_ms: dict[str, float]
    audit_seq: int
    security_events: list[dict] = []
    model_trace: list[dict] = []


class NaiveVerdict(BaseModel):
    """What the undefended baseline is asked to return."""

    severity: Severity
    verdict: Literal["benign", "suspicious", "malicious"]
    actions: list[str] = []
    explanation: str = ""


class FeedbackIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    alert_id: str
    correct_label: Literal["benign", "malicious"]
    verdict_correct: bool
    explanation_rating: int | None = Field(default=None, ge=1, le=5)
    comment: str = Field(default="", max_length=1000)


class ResolvedCase(BaseModel):
    case_id: str
    summary: str
    resolution: str
    outcome: Literal["true_positive", "false_positive"]
    techniques: list[str] = []
