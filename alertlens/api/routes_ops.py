"""Actions, feedback, retraining, audit, metrics and the replay stream."""
from __future__ import annotations

import threading
import time

from fastapi import APIRouter, Query
from pydantic import BaseModel, ConfigDict, Field

from alertlens.config import ROOT
from alertlens.feedback.loop import record_feedback, retrain
from alertlens.memory import store as db
from alertlens.pipeline import service
from alertlens.schemas import Action, FeedbackIn

router = APIRouter()


class ApproveIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    approver: str = Field(min_length=1, max_length=80)
    confirm: bool = False


class RejectIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    approver: str = Field(min_length=1, max_length=80)
    reason: str = Field(default="", max_length=300)


@router.post("/actions/{instance_id}/approve", response_model=Action)
def approve(instance_id: str, body: ApproveIn):
    return service.approve_action(instance_id, body.approver, body.confirm)


@router.post("/actions/{instance_id}/reject", response_model=Action)
def reject(instance_id: str, body: RejectIn):
    return service.reject_action(instance_id, body.approver, body.reason)


@router.post("/feedback")
def feedback(fb: FeedbackIn):
    record_feedback(fb)
    return {"stored": True}


@router.post("/retrain")
def run_retrain():
    return retrain()


@router.get("/audit")
def audit(limit: int = Query(200, ge=1, le=2000)):
    return service.audit_entries(limit)


@router.get("/audit/verify")
def audit_verify():
    return service.audit_verify()


@router.get("/metrics")
def metrics():
    with db.db() as conn:
        return {"kpis": db.kpis(conn), "router": db.router_stats(conn)}


_replay = {"running": False, "sent": 0}


@router.post("/stream/replay")
def replay(n: int = Query(30, ge=1, le=500), interval: float = Query(1.0, ge=0.0, le=10.0)):
    """Replay part of the synthetic stream into the store, for the live feed."""
    if _replay["running"]:
        return {"started": False, **_replay}
    source = ROOT / "data" / "benchmark" / "alerts.jsonl"
    if not source.exists():
        return {"started": False, "error": "Run `make data` first"}

    def worker():
        import json

        from alertlens.pipeline.orchestrator import Options, analyze

        _replay.update(running=True, sent=0)
        try:
            for line in source.read_text().splitlines()[-n:]:
                analyze(json.loads(line), Options())
                _replay["sent"] += 1
                time.sleep(interval)
        finally:
            _replay["running"] = False

    threading.Thread(target=worker, daemon=True).start()
    return {"started": True, "n": n}
