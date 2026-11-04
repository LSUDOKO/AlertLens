"""SQLite store: one file, stdlib only."""
from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path

from alertlens.config import get_settings

SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts(alert_id TEXT PRIMARY KEY, ts TEXT, body TEXT);
CREATE TABLE IF NOT EXISTS analyses(alert_id TEXT PRIMARY KEY, ts TEXT, label TEXT, score REAL, route TEXT,
    injected INTEGER, tactics TEXT, body TEXT, seq INTEGER);
CREATE TABLE IF NOT EXISTS incidents(incident_id TEXT PRIMARY KEY, severity TEXT, score REAL, body TEXT);
CREATE TABLE IF NOT EXISTS incident_alerts(incident_id TEXT, alert_id TEXT, PRIMARY KEY(incident_id, alert_id));
CREATE TABLE IF NOT EXISTS feedback(id INTEGER PRIMARY KEY AUTOINCREMENT, alert_id TEXT, correct_label TEXT,
    verdict_correct INTEGER, explanation_rating INTEGER, comment TEXT, features TEXT, fired_rules TEXT, ts TEXT);
CREATE TABLE IF NOT EXISTS resolved_cases(case_id TEXT PRIMARY KEY, summary TEXT, resolution TEXT, outcome TEXT, techniques TEXT);
CREATE TABLE IF NOT EXISTS audit_log(seq INTEGER PRIMARY KEY, ts TEXT, actor TEXT, event_type TEXT, payload TEXT,
    payload_hash TEXT, prev_hash TEXT, hash TEXT);
CREATE TABLE IF NOT EXISTS actions(instance_id TEXT PRIMARY KEY, alert_id TEXT, action_id TEXT, status TEXT, approver TEXT,
    body TEXT);
CREATE TABLE IF NOT EXISTS router_stats(route TEXT PRIMARY KEY, n INTEGER, total_ms REAL, tokens INTEGER);
"""


def connect(path: str | None = None) -> sqlite3.Connection:
    conn = sqlite3.connect(path or get_settings().db_path, timeout=15, isolation_level=None)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(SCHEMA)
    return conn


@contextmanager
def db(path: str | None = None):
    conn = connect(path)
    try:
        yield conn
    finally:
        conn.close()


def save_analysis(conn, result) -> None:
    a = result.alert
    tactics = sorted({t["tactic"] for t in result.mitre})
    conn.execute("INSERT OR REPLACE INTO alerts VALUES(?,?,?)", (a.alert_id, a.timestamp.isoformat(), a.model_dump_json()))
    conn.execute("INSERT OR REPLACE INTO analyses VALUES(?,?,?,?,?,?,?,?,?)",
                 (a.alert_id, a.timestamp.isoformat(), result.severity.label, result.severity.score, result.route,
                  int(bool(result.sanitise.quarantined_fields)), json.dumps(tactics), result.model_dump_json(),
                  result.audit_seq))
    for action in result.actions:
        conn.execute("INSERT OR IGNORE INTO actions VALUES(?,?,?,?,?,?)",
                     (action.instance_id, a.alert_id, action.action_id, action.status, None, action.model_dump_json()))


def bump_router(conn, route: str, ms: float, tokens: int) -> None:
    conn.execute("INSERT INTO router_stats VALUES(?,1,?,?) ON CONFLICT(route) DO UPDATE SET n=n+1, total_ms=total_ms+?, "
                 "tokens=tokens+?", (route, ms, tokens, ms, tokens))


def list_analyses(conn, limit: int = 200) -> list[dict]:
    rows = conn.execute("SELECT alert_id, ts, label, score, route, injected, tactics FROM analyses ORDER BY ts DESC LIMIT ?",
                        (limit,)).fetchall()
    return [dict(alert_id=r[0], ts=r[1], label=r[2], score=r[3], route=r[4], injected=bool(r[5]), tactics=json.loads(r[6]))
            for r in rows]


def get_analysis(conn, alert_id: str) -> dict | None:
    row = conn.execute("SELECT body FROM analyses WHERE alert_id=?", (alert_id,)).fetchone()
    return json.loads(row[0]) if row else None


def save_incident(conn, incident) -> None:
    conn.execute("INSERT OR REPLACE INTO incidents VALUES(?,?,?,?)",
                 (incident.incident_id, incident.severity.label, incident.severity.score, incident.model_dump_json()))
    for aid in incident.alert_ids:
        conn.execute("INSERT OR REPLACE INTO incident_alerts VALUES(?,?)", (incident.incident_id, aid))


def list_incidents(conn) -> list[dict]:
    return [json.loads(r[0]) for r in conn.execute("SELECT body FROM incidents ORDER BY score DESC").fetchall()]


def get_incident(conn, incident_id: str) -> dict | None:
    row = conn.execute("SELECT body FROM incidents WHERE incident_id=?", (incident_id,)).fetchone()
    return json.loads(row[0]) if row else None


def kpis(conn) -> dict:
    one = lambda q: conn.execute(q).fetchone()[0] or 0  # noqa: E731
    total, fast = one("SELECT COUNT(*) FROM analyses"), one("SELECT COUNT(*) FROM analyses WHERE route='fast'")
    return {"alerts": total, "incidents": one("SELECT COUNT(*) FROM incidents"),
            "injections": one("SELECT COUNT(*) FROM analyses WHERE injected=1"),
            "fast_path_pct": round(100 * fast / total, 1) if total else 0.0}


def router_stats(conn) -> dict:
    out = {}
    for route, n, ms, tokens in conn.execute("SELECT route, n, total_ms, tokens FROM router_stats"):
        out[route] = {"n": n, "avg_ms": round(ms / n, 1) if n else 0.0, "tokens": tokens}
    return out


def data_dir() -> Path:
    return Path(get_settings().db_path).resolve().parent
