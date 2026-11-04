"""F3: the privileged explainer. Its prompt is built only from validated facts and placeholders."""
from __future__ import annotations

import json
import re
import secrets
from dataclasses import dataclass

from alertlens.ingest.adapters import vendor_extra
from alertlens.ingest.normalise import clean_identifier
from alertlens.llm.provider import LLMProvider, StructuredResult, call_structured
from alertlens.llm.quarantined import load_prompt
from alertlens.llm.templates import explanation_template
from alertlens.mitre.mapper import RULE_CATALOGUE
from alertlens.safety.canary import leaked
from alertlens.safety.pii import Vault, redact_identifier
from alertlens.schemas import Alert, ExplanationDraft, ExtractedFacts, SanitiseReport, SeverityResult
from alertlens.scoring.features import is_off_hours

_SAFE_RULE = re.compile(r"^[A-Za-z0-9._-]{1,32}$")
_COUNTRY = re.compile(r"^[A-Z]{2}$")
_MARKUP = re.compile(r"<(?!(?:USER|IP|EMAIL|PHONE|HOST|HASH)_\d+>)[^>]*>|\[([^\]]*)\]\([^)]*\)|https?://\S+")


def strip_markup(text: str) -> str:
    return _MARKUP.sub(lambda m: m.group(1) or "", text)


def build_facts_payload(alert: Alert, facts: ExtractedFacts, severity: SeverityResult, mitre: list[dict],
                        sanitise: SanitiseReport, vault: Vault, similar: list[dict] | None = None,
                        context: dict | None = None) -> dict:
    """The whole world of the privileged LLM. Closed values, numbers and placeholders; no raw strings."""
    def ident(kind: str, value) -> str | None:
        return redact_identifier(kind, clean_identifier(value), vault)

    rule_id = alert.rule_id if _SAFE_RULE.match(alert.rule_id) else "unknown"
    entry = RULE_CATALOGUE.get(rule_id, {})
    country = alert.geo_country if alert.geo_country and _COUNTRY.match(alert.geo_country) else None
    mb = facts.data_volume_mb
    payload_alert = {
        "alert.rule_id": rule_id, "alert.rule_title": entry.get("title", "a detection rule"),
        "alert.rule_level": alert.rule_level, "alert.category": alert.category, "alert.event_count": alert.event_count,
        "alert.asset_criticality": alert.asset_criticality, "alert.privilege": alert.user_privilege,
        "alert.user": ident("USER", alert.user), "alert.host": ident("HOST", alert.host),
        "alert.src_ip": ident("IP", alert.src_ip), "alert.dst_ip": ident("IP", alert.dst_ip),
        "alert.device_known": alert.device_known, "alert.geo_country": country,
        "alert.geo_usual": vendor_extra(alert.raw, "geo_usual") if isinstance(vendor_extra(alert.raw, "geo_usual"), bool) else None,
        "alert.off_hours": is_off_hours(alert), "alert.data_volume_mb": mb,
    }
    return {
        "alert": {k: v for k, v in payload_alert.items() if v is not None},
        "facts": {f"facts.{k}": v for k, v in facts.model_dump().items() if v is not None},
        "severity": {"severity.label": severity.label, "severity.score": severity.score,
                     "severity.p_malicious": severity.p_malicious, "severity.triage": severity.triage},
        "mitre": [{"id": t["id"], "name": t["name"], "tactic": t["tactic"]} for t in mitre],
        "sanitise": {"sanitise.injection_found": bool(sanitise.quarantined_fields),
                     "sanitise.families": sorted({f.pattern_family for f in sanitise.findings})},
        "similar": [{"case_id": c["case_id"], "outcome": c["outcome"]} for c in (similar or [])
                    if re.fullmatch(r"[\w-]{1,32}", str(c["case_id"]))],
        "context": context or {},
    }


def evidence_map(payload: dict) -> dict[str, object]:
    """Flatten the payload into the field paths claims can cite."""
    out: dict[str, object] = {}
    for section in ("alert", "facts", "severity", "sanitise"):
        out.update(payload.get(section, {}))
    for i, t in enumerate(payload.get("mitre", [])):
        out[f"mitre.{i}.id"], out[f"mitre.{i}.name"], out[f"mitre.{i}.tactic"] = t["id"], t["name"], t["tactic"]
    return out


@dataclass
class ExplainOutcome:
    call: StructuredResult
    canary: str
    prompt_version: str
    prompt: str
    system: str


def explain(payload: dict, provider: LLMProvider, *, raw_alert: dict | None = None,
            check_canary: bool = True) -> ExplainOutcome:
    """Ask the privileged LLM. `raw_alert` is only ever set by the no-dual-LLM ablation."""
    version, template = load_prompt("explainer")
    canary = f"CANARY-{secrets.token_hex(4)}"
    system = template.format(canary=canary)
    user = f"<<FACTS>>{json.dumps(payload, ensure_ascii=False, default=str)}<<END-FACTS>>"
    if raw_alert is not None:
        user += f"\n<<RAW>>{json.dumps(raw_alert, ensure_ascii=False, default=str)}<<END-RAW>>"
    call = call_structured(provider, system, user, ExplanationDraft, lambda: explanation_template(payload),
                           extra_check=(lambda text, _: "prompt_leak" if leaked(text, canary) else None) if check_canary else None)
    return ExplainOutcome(call, canary, version, user, system)
