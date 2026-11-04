"""Code-written outputs. MockLLM uses them, and every real LLM falls back to them on failure."""
from __future__ import annotations

import json
import re

from alertlens.schemas import AgentNote, ExplanationDraft, ExtractedFacts

_PAYLOAD = re.compile(r"<<FACTS>>(.*)<<END-FACTS>>", re.DOTALL)
ACTION_WORDS = {
    "login_failed": "repeated failed logins", "login": "a login", "process_start": "a process starting",
    "network_conn": "network activity", "file_write": "a file change", "privilege_change": "an account or rights change",
    "data_transfer": "a data transfer", "dns_query": "DNS activity", "other": "unusual activity",
}


def facts_payload(user_prompt: str) -> dict:
    m = _PAYLOAD.search(user_prompt)
    return json.loads(m.group(1)) if m else {}


def explanation_template(p: dict) -> ExplanationDraft:
    """A grounded explanation built only from the facts payload."""
    a, f, s = p.get("alert", {}), p.get("facts", {}), p.get("severity", {})
    mitre = p.get("mitre", [])
    title = a.get("alert.rule_title", "a detection rule")
    label, score = s.get("severity.label", "unknown"), s.get("severity.score", 0)
    claims: list[dict] = []

    def claim(key: str, text: str, *evidence: str) -> None:
        claims.append({"key": key, "text": text, "evidence": list(evidence)})

    claim("rule", f"Rule {a.get('alert.rule_id')} fired at level {a.get('alert.rule_level')}.",
          "alert.rule_id", "alert.rule_level")
    if a.get("alert.event_count", 1) > 1:
        claim("events", f"The sensor counted {a['alert.event_count']} events.", "alert.event_count")
    if a.get("alert.user"):
        claim("user", f"The account involved is {a['alert.user']}.", "alert.user")
    if a.get("alert.src_ip"):
        claim("src", f"The activity came from {a['alert.src_ip']}.", "alert.src_ip")
    if a.get("alert.host"):
        claim("host", f"The affected host is {a['alert.host']}, rated {a.get('alert.asset_criticality')} criticality.",
              "alert.host", "alert.asset_criticality")
    if a.get("alert.dst_ip"):
        claim("dst", f"The destination address was {a['alert.dst_ip']}.", "alert.dst_ip")
    if a.get("alert.data_volume_mb"):
        claim("volume", f"About {a['alert.data_volume_mb']} MB left the host.", "alert.data_volume_mb")
    if a.get("alert.device_known") is False:
        claim("device", "The device was not known for this account.", "alert.device_known")
    if a.get("alert.geo_usual") is False:
        country = a.get("alert.geo_country")
        where = f"The location {country} is unusual" if country else "The location is unusual"
        ev = ["alert.geo_usual"] + (["alert.geo_country"] if country else [])
        claim("geo", f"{where} for this account.", *ev)
    if f.get("facts.suspicious_tool") not in (None, "none"):
        claim("tool", f"The tool type seen was {f['facts.suspicious_tool']}.", "facts.suspicious_tool")
    for i, t in enumerate(mitre[:2]):
        claim(f"technique{i}", f"This matches MITRE ATT&CK {t['id']} ({t['name']}).",
              f"mitre.{i}.id", f"mitre.{i}.name")
    claim("severity", f"Code-based scoring rated this {label}, score {score}.", "severity.label", "severity.score")
    if p.get("sanitise", {}).get("sanitise.injection_found"):
        claim("injection", "Hidden instructions were found in this alert and were not followed.",
              "sanitise.injection_found")
    actor = a.get("alert.user") or a.get("alert.src_ip") or a.get("alert.host") or "an unknown source"
    place = a.get("alert.host") or "the monitored environment"
    what = f"The sensor reported {title} involving {actor} on {place}."
    tactics = sorted({t["tactic"] for t in mitre})
    why = (f"This fits the {', '.join(tactics)} stage of an attack. " if tactics else "No known attack stage matched. ")
    why += f"Code-based scoring rated it {label}."
    return ExplanationDraft(summary=f"{label.capitalize()} severity: {title} involving {actor}.", what_happened=what,
                            why_it_matters=why, claims=claims)


def facts_template(text: str) -> ExtractedFacts:
    """Offline stand-in for the extractor: keyword spotting inside the delimited data only."""
    t = text.lower()
    tool = "none"
    for name, needle in [("mimikatz_like", "mimikatz"), ("psexec", "psexe"), ("certutil", "certutil"),
                         ("powershell", "powershell"), ("curl_wget", "curl")]:
        if needle in t:
            tool = name
            break
    action = "other"
    for name, needles in [("login", ["login success", "accepted login"]), ("login_failed", ["failed login"]),
                          ("login", ["login"]),
                          ("privilege_change", ["administrator", "admin account"]), ("data_transfer", ["transfer", "sent"]),
                          ("dns_query", ["dns"]), ("process_start", ["powershell", "certutil", "psexec"])]:
        if any(n in t for n in needles):
            action = name
            break
    return ExtractedFacts(action_type=action, outcome="unknown", is_admin_action="admin" in t, suspicious_tool=tool,
                          notes_code=["encoded_command"] if " -enc" in t else [])


def agent_template(role: str, p: dict) -> AgentNote:
    """Rule-based agent turns over the facts payload."""
    a, s = p.get("alert", {}), p.get("severity", {})
    prob = s.get("severity.p_malicious", 0.5)
    injected = p.get("sanitise", {}).get("sanitise.injection_found", False)
    if role == "triage":
        verdict = "malicious" if prob > 0.6 or injected else "benign" if prob < 0.1 else "suspicious"
        return AgentNote(verdict=verdict, reasons=[f"calibrated probability {prob}"] + (["hidden_instructions"] if injected else []))
    if role == "investigator":
        ctx = p.get("context", {})
        reasons = []
        if ctx.get("incident_alerts", 1) > 1:
            reasons.append(f"linked to {ctx['incident_alerts']} alerts across {len(ctx.get('tactics', []))} tactics")
        reasons += [f"similar case {c['case_id']} was a {c['outcome']}" for c in p.get("similar", [])[:2]]
        verdict = "malicious" if prob > 0.6 else "suspicious" if prob >= 0.1 else "benign"
        return AgentNote(verdict=verdict, reasons=reasons or ["no linked evidence yet"])
    # critic: look for the innocent explanation
    benign, strength = [], 0.0
    if a.get("alert.category") == "authentication":  # device and location only explain away logins
        if a.get("alert.device_known") is True:
            benign.append("known device")
            strength += 0.3
        if a.get("alert.geo_usual") is True:
            benign.append("usual location")
            strength += 0.25
        if a.get("alert.privilege") in {"admin", "service"} and a.get("alert.off_hours"):
            benign.append("privileged staff often work late")
            strength += 0.2
    if p.get("context", {}).get("incident_alerts", 1) > 1 or injected or prob < 0.1:
        # A chain of alerts or a planted payload outweighs the innocent story, and a
        # verdict that is already benign has nothing to disprove.
        strength = 0.0
        benign = []
    return AgentNote(verdict="benign" if strength >= 0.5 else "suspicious", reasons=benign or ["no strong benign explanation"],
                     objection_strength=round(min(1.0, strength), 2))
