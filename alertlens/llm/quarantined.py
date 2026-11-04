"""F11: the quarantined extractor. The only LLM step that reads free text, and it can return only enums."""
from __future__ import annotations

import json
import secrets
from dataclasses import dataclass
from pathlib import Path

from alertlens.ingest.adapters import vendor_extra
from alertlens.llm.provider import LLMProvider, StructuredResult, call_structured
from alertlens.mitre.mapper import RULE_CATALOGUE
from alertlens.safety.canary import leaked
from alertlens.safety.injection import iter_strings, mask
from alertlens.safety.pii import Vault, redact_text
from alertlens.schemas import Alert, ExtractedFacts, SanitiseReport
from alertlens.scoring.features import bytes_out, is_external, is_off_hours, outcome_of, tool_of

PROMPT_DIR = Path(__file__).parent / "prompts"
FREE_TEXT = ("rule_name", "command_line", "url")
_RAW_TEXT_KEYS = {"full_log", "user_agent", "http_user_agent"}


def load_prompt(name: str) -> tuple[str, str]:
    """Return (version, body). The version goes into the audit log."""
    lines = (PROMPT_DIR / f"{name}.txt").read_text().splitlines()
    return lines[0].split("version:")[1].strip(), "\n".join(lines[1:])


def free_text_view(alert: Alert, report: SanitiseReport | None, vault: Vault) -> dict[str, str]:
    """The free-text fields, with quarantined values masked and identifiers redacted."""
    out: dict[str, str] = {}

    def put(path: str, text: str) -> None:
        if report and path in report.quarantined_fields:
            out[path] = mask(path)
            return
        for (_, value), token in sorted(vault.forward.items(), key=lambda kv: -len(kv[0][1])):
            text = text.replace(value, token)
        out[path] = redact_text(text, vault)

    for name in FREE_TEXT:
        if value := getattr(alert, name):
            put(f"alert.{name}", value)
    for path, text in iter_strings(alert.raw, "raw"):
        if path.rsplit(".", 1)[-1] in _RAW_TEXT_KEYS:
            put(path, text)
    return out


def deterministic_facts(alert: Alert) -> ExtractedFacts:
    """The same schema, filled by code. The fast path uses it, and it overrules the LLM on conflict."""
    entry = RULE_CATALOGUE.get(alert.rule_id, {})
    notes = []
    if is_off_hours(alert):
        notes.append("off_hours")
    if alert.device_known is False:
        notes.append("new_device")
    if vendor_extra(alert.raw, "geo_usual") is False:
        notes.append("new_geo")
    if outcome_of(alert) == "failure" and alert.event_count >= 10:
        notes.append("many_failures")
    if " -enc" in (alert.command_line or "").lower():
        notes.append("encoded_command")
    if is_external(alert.dst_ip):
        notes.append("external_dst")
    mb = bytes_out(alert) / 1_000_000
    return ExtractedFacts(
        action_type=entry.get("action", "other"), outcome=outcome_of(alert),
        is_admin_action=alert.user_privilege == "admin", suspicious_tool=tool_of(alert),
        data_volume_mb=round(mb, 1) if mb else None, target_count=None, notes_code=notes,
    )


def reconcile(llm: ExtractedFacts, code: ExtractedFacts) -> tuple[ExtractedFacts, list[str]]:
    """The LLM only fills what code could not determine, so lying inside the enums gains nothing."""
    conflicts = []
    merged = code.model_dump()
    if code.action_type == "other":
        merged["action_type"] = llm.action_type
    elif llm.action_type not in ("other", code.action_type):
        conflicts.append("action_type")
    if code.outcome == "unknown":
        merged["outcome"] = llm.outcome
    elif llm.outcome not in ("unknown", code.outcome):
        conflicts.append("outcome")
    if code.suspicious_tool == "none":
        merged["suspicious_tool"] = llm.suspicious_tool
    elif llm.suspicious_tool != code.suspicious_tool:
        conflicts.append("suspicious_tool")
    merged["is_admin_action"] = code.is_admin_action or llm.is_admin_action
    merged["notes_code"] = sorted(set(code.notes_code) | set(llm.notes_code))
    if merged["data_volume_mb"] is None:
        merged["data_volume_mb"] = llm.data_volume_mb
    merged["target_count"] = llm.target_count
    return ExtractedFacts(**merged), conflicts


@dataclass
class ExtractOutcome:
    facts: ExtractedFacts
    call: StructuredResult
    conflicts: list[str]
    prompt_version: str


def extract_facts(alert: Alert, report: SanitiseReport | None, vault: Vault, provider: LLMProvider) -> ExtractOutcome:
    """Run the quarantined extractor. Random delimiters stop data from closing its own section."""
    version, template = load_prompt("extractor")
    boundary = f"DATA-{secrets.token_hex(3)}"
    canary = f"CANARY-{secrets.token_hex(4)}"
    system = template.format(boundary=boundary, canary=canary, schema=json.dumps(ExtractedFacts.model_json_schema()))
    view = free_text_view(alert, report, vault)
    user = f"<<{boundary}>>\n{json.dumps(view, ensure_ascii=False)}\n<<END-{boundary}>>"
    code = deterministic_facts(alert)
    call = call_structured(provider, system, user, ExtractedFacts, lambda: code,
                           extra_check=lambda text, _: "prompt_leak" if leaked(text, canary) else None, max_tokens=300)
    facts, conflicts = reconcile(call.value, code)
    return ExtractOutcome(facts, call, conflicts, version)
