"""F21: one verified explanation, three audiences. Same facts, different framing."""
from __future__ import annotations

from alertlens.render.i18n import hindi_rendering
from alertlens.schemas import Explanation

SEV_DESC = {"low": "low", "medium": "moderate", "high": "serious", "critical": "very serious"}


def context_from(alert_view: dict, severity, mitre: list[dict], sanitise, actions: list) -> dict:
    return {**alert_view, "label": severity.label, "score": severity.score, "triage": severity.triage,
            "techniques": [t["id"] for t in mitre], "technique_names": [t["name"] for t in mitre],
            "tactics": sorted({t["tactic"] for t in mitre}), "injected": bool(sanitise.quarantined_fields),
            "actions": [a.title for a in actions]}


def _entities_line(c: dict) -> str:
    parts = []
    if c.get("user"):
        parts.append(f"Account: {c['user']}.")
    if c.get("host"):
        parts.append(f"Computer: {c['host']}.")
    if c.get("src_ip"):
        parts.append(f"From: {c['src_ip']}.")
    if c.get("dst_ip"):
        parts.append(f"To: {c['dst_ip']}.")
    return " ".join(parts)


def analyst_view(e: Explanation, c: dict) -> dict:
    tech = ", ".join(c["techniques"]) or "none mapped"
    return {"headline": e.summary, "what_happened": e.what_happened, "why_it_matters": e.why_it_matters,
            "next": f"ATT&CK: {tech}. Score {c['score']} ({c['label']}), triage {c['triage']}.",
            "claims": [cl.model_dump() for cl in e.claims]}


def manager_view(e: Explanation, c: dict) -> dict:
    first_action = c["actions"][0] if c["actions"] else "no action yet"
    stage = ", ".join(c["tactics"]) or "no known attack stage"
    return {"headline": f"Risk: {c['label'].upper()}. {c.get('title', 'An alert').capitalize()}.",
            "what_happened": f"{e.what_happened} {_entities_line(c)}",
            "why_it_matters": f"Attack stage: {stage}. Asset value: {c.get('criticality', 'unknown')}. "
                              "If this is real, it could affect business data and service availability.",
            "next": f"Decision needed: approve or reject \"{first_action}\". Nothing runs without approval.",
            "claims": [cl.model_dump() for cl in e.claims]}


def employee_view(e: Explanation, c: dict) -> dict:
    risk = SEV_DESC[c["label"]]
    return {"headline": f"We saw something odd. We rate it as {risk} ({c['label']}).",
            "what_happened": f"Our tools saw {c.get('title', 'something unusual')}. {_entities_line(c)}",
            "why_it_matters": "It may be nothing, but it could mean someone else is using your account. "
                              "We are looking into it now.",
            "next": "Please do not panic. Do not share your password. If you did not do this, call the IT help desk. "
                    "They may ask you to sign in again.",
            "claims": [cl.model_dump() for cl in e.claims]}


VIEWS = {"analyst": analyst_view, "manager": manager_view, "employee": employee_view}


def render_all(e: Explanation, c: dict, hindi: bool = True) -> dict[str, dict[str, dict]]:
    """Return {audience: {language: view}}, built once so the UI can switch without re-analysing."""
    out: dict[str, dict[str, dict]] = {}
    for audience, view in VIEWS.items():
        out[audience] = {"en": view(e, c)}
        if hindi:
            out[audience]["hi"] = hindi_rendering(audience, e, c)
    return out
