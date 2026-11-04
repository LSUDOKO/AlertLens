"""Analyse alerts and read stored analyses."""
from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Body, HTTPException, Query
from pydantic import BaseModel

from alertlens.memory import store as db
from alertlens.memory.retriever import similar_cases
from alertlens.mitre.mapper import map_alert
from alertlens.pipeline.orchestrator import Options, analyze
from alertlens.pipeline.service import analyze_batch
from alertlens.schemas import Alert, AnalysisResult, Incident

router = APIRouter()
MAX_BATCH = 5000


class BatchOut(BaseModel):
    results: list[AnalysisResult]
    incidents: list[Incident]


@router.post("/analyze", response_model=AnalysisResult)
def analyze_one(alert: dict = Body(...), audience: Literal["analyst", "manager", "employee"] = "analyst",
                lang: Literal["en", "hi"] = "en", deep: bool = False):
    return analyze(alert, Options(audience=audience, lang=lang, deep=deep))


@router.post("/analyze/batch", response_model=BatchOut)
def analyze_many(alerts: list[dict] = Body(...)):
    if len(alerts) > MAX_BATCH:
        raise HTTPException(413, f"At most {MAX_BATCH} alerts per batch")
    results, incidents = analyze_batch(alerts)
    return BatchOut(results=results, incidents=incidents)


@router.get("/alerts")
def list_alerts(limit: int = Query(200, ge=1, le=2000)):
    with db.db() as conn:
        return db.list_analyses(conn, limit)


@router.get("/alerts/{alert_id}")
def get_alert(alert_id: str):
    with db.db() as conn:
        row = db.get_analysis(conn, alert_id)
    if row is None:
        raise KeyError(alert_id)
    return row


@router.get("/similar/{alert_id}")
def similar(alert_id: str, k: int = Query(3, ge=1, le=20)):
    with db.db() as conn:
        row = conn.execute("SELECT body FROM alerts WHERE alert_id=?", (alert_id,)).fetchone()
    if not row:
        raise KeyError(alert_id)
    alert = Alert.model_validate_json(row[0])
    return similar_cases(alert, map_alert(alert), k)
