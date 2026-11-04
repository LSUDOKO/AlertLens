"""What the API and UI share: analyse, correlate, store, approve. The UI calls this in-process."""
from __future__ import annotations

import json
from pathlib import Path

from alertlens.audit import chain
from alertlens.config import ROOT
from alertlens.correlation.correlator import correlate, incident_id_for
from alertlens.correlation.graph import build_graph, graph_json, graph_summary, pivot_node
from alertlens.ingest.normalise import normalise
from alertlens.memory import store as db
from alertlens.mitre.mapper import RULE_CATALOGUE, map_alert
from alertlens.mitre.predictor import predict_next
from alertlens.pipeline.orchestrator import Options, analyze
from alertlens.remediation import guardrails
from alertlens.schemas import Action, AnalysisResult, Incident, SeverityResult
from alertlens.scoring.scorer import label_of

TACTIC_BONUS, MAX_BONUS = 5.0, 15.0
SAMPLES = ROOT / "data" / "samples"


def build_incident(group: list, results: dict[str, AnalysisResult]) -> Incident:
    """Turn a correlated group of alerts into an incident with timeline, graph and next steps."""
    ids = [a.alert_id for a in group]
    timeline, tactics, entities, seen = [], [], [], set()
    best: SeverityResult | None = None
    for alert in group:
        res = results[alert.alert_id]
        mitre = res.mitre
        tactic = mitre[0]["tactic"] if mitre else "Unmapped"
        if mitre and tactic not in tactics:
            tactics.append(tactic)
        timeline.append({"ts": alert.timestamp.isoformat(), "alert_id": alert.alert_id, "rule_id": alert.rule_id,
                         "what": RULE_CATALOGUE.get(alert.rule_id, {}).get("title", "a detection rule"),
                         "tactic": tactic, "label": res.severity.label, "score": res.severity.score,
                         "injected": bool(res.sanitise.quarantined_fields)})
        for ent in alert.entities:
            key = (ent.kind, ent.value)
            if key not in seen:
                seen.add(key)
                entities.append(ent)
        if best is None or res.severity.score > best.score:
            best = res.severity
    bonus = min(MAX_BONUS, TACTIC_BONUS * max(0, len(tactics) - 1))
    score = round(min(100.0, best.score + bonus), 2)
    severity = best.model_copy(update={
        "score": score, "label": label_of(score), "counterfactuals": [],
        "reasons": [f"Highest alert score {best.score}, plus {bonus:g} for {len(tactics)} attack stages"],
    })
    g = build_graph(group)
    pivot = pivot_node(g)
    return Incident(incident_id=incident_id_for(ids), alert_ids=ids, entities=entities, tactics_sequence=tactics,
                    severity=severity, timeline=timeline, graph_summary=graph_summary(g),
                    predicted_next=predict_next(tactics), pivot=g.nodes[pivot]["label"] if pivot else None,
                    graph=graph_json(g))


def analyze_batch(objs: list[dict], base: Options | None = None, store_incidents: bool = True) -> tuple[list[AnalysisResult], list[Incident]]:
    """Correlate first, so the investigator can see the linked alerts; then analyse each one."""
    base = base or Options()
    alerts = [normalise(o) for o in objs]
    groups = correlate(alerts)
    ctx_by_id: dict[str, dict] = {}
    for group in groups:
        tactics = sorted({t["tactic"] for a in group for t in map_alert(a)})
        for a in group:
            ctx_by_id[a.alert_id] = {"incident_alerts": len(group), "tactics": tactics}
    results: dict[str, AnalysisResult] = {}
    for obj, alert in zip(objs, alerts, strict=True):
        opts = Options(**{**base.__dict__, "context": ctx_by_id[alert.alert_id]})
        results[alert.alert_id] = analyze(obj, opts)
    incidents = [build_incident(g, results) for g in groups]
    for inc in incidents:
        for aid in inc.alert_ids:
            results[aid].incident_id = inc.incident_id
    if base.persist and store_incidents:
        with db.db(base.db_path) as conn:
            for inc in incidents:
                if len(inc.alert_ids) > 1 or inc.severity.label in {"high", "critical"}:
                    db.save_incident(conn, inc)
                    chain.append(conn, "pipeline", "incident", {"incident_id": inc.incident_id, "alerts": inc.alert_ids,
                                                                "severity": inc.severity.label})
            for res in results.values():
                db.save_analysis(conn, res)
    return list(results.values()), incidents


def load_samples() -> dict[str, dict]:
    out = {}
    for path in sorted(Path(SAMPLES).rglob("*.json")):
        out[str(path.relative_to(SAMPLES))] = json.loads(path.read_text())
    return out


def hero_alerts() -> list[dict]:
    return [json.loads(p.read_text()) for p in sorted((Path(SAMPLES) / "hero").glob("*.json"))]


def _load_action(conn, instance_id: str) -> tuple[Action, str]:
    row = conn.execute("SELECT body, alert_id FROM actions WHERE instance_id=?", (instance_id,)).fetchone()
    if not row:
        raise KeyError(instance_id)
    return Action.model_validate_json(row[0]), row[1]


def _save_action(conn, action: Action, approver: str | None) -> None:
    conn.execute("UPDATE actions SET status=?, approver=?, body=? WHERE instance_id=?",
                 (action.status, approver, action.model_dump_json(), action.instance_id))


def approve_action(instance_id: str, approver: str, confirm: bool = False, db_path: str | None = None) -> Action:
    """Simulated only. Moves proposed to simulated, with a second confirmation for high-risk actions."""
    with db.db(db_path) as conn:
        action, alert_id = _load_action(conn, instance_id)
        new = guardrails.next_on_approve(action.status, action.two_step, approver, confirm)
        steps = ["approved", "simulated"] if new == "simulated" else [new]
        for step in steps:
            action.status = step
            chain.append(conn, approver, f"action_{step}", {"instance_id": instance_id, "alert_id": alert_id,
                                                           "action_id": action.action_id})
        _save_action(conn, action, approver)
    return action


def reject_action(instance_id: str, approver: str, reason: str = "", db_path: str | None = None) -> Action:
    with db.db(db_path) as conn:
        action, alert_id = _load_action(conn, instance_id)
        action.status = guardrails.next_on_reject(action.status, approver)
        chain.append(conn, approver, "action_rejected", {"instance_id": instance_id, "alert_id": alert_id,
                                                         "action_id": action.action_id, "reason": reason[:300]})
        _save_action(conn, action, approver)
    return action


def actions_for(alert_id: str, db_path: str | None = None) -> list[Action]:
    with db.db(db_path) as conn:
        rows = conn.execute("SELECT body FROM actions WHERE alert_id=?", (alert_id,)).fetchall()
    return [Action.model_validate_json(r[0]) for r in rows]


def audit_entries(limit: int = 200, db_path: str | None = None) -> list[dict]:
    with db.db(db_path) as conn:
        rows = conn.execute("SELECT seq,ts,actor,event_type,payload,hash FROM audit_log ORDER BY seq DESC LIMIT ?",
                            (limit,)).fetchall()
    return [dict(seq=r[0], ts=r[1], actor=r[2], event_type=r[3], payload=json.loads(r[4]), hash=r[5]) for r in rows]


def audit_verify(db_path: str | None = None) -> dict:
    with db.db(db_path) as conn:
        return chain.verify_chain(conn)
