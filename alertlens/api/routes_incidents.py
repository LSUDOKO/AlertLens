"""Incidents and report export."""
from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Query
from fastapi.responses import Response

from alertlens.memory import store as db
from alertlens.render.report import build_report

router = APIRouter()


@router.get("/incidents")
def incidents():
    with db.db() as conn:
        return db.list_incidents(conn)


@router.get("/incidents/{incident_id}")
def incident(incident_id: str):
    with db.db() as conn:
        row = db.get_incident(conn, incident_id)
    if row is None:
        raise KeyError(incident_id)
    return row


@router.get("/incidents/{incident_id}/report")
def report(incident_id: str, format: Literal["md", "html", "pdf"] = Query("md"), lang: Literal["en", "hi"] = "en"):
    body, media, name = build_report(incident_id, format, lang)
    return Response(body, media_type=media, headers={"Content-Disposition": f'attachment; filename="{name}"'})
