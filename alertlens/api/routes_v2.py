"""Endpoints for the web frontend: samples, the red team, adaptive campaigns and benchmark results."""
from __future__ import annotations

import json
from typing import Literal

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from alertlens.config import ROOT, get_settings
from alertlens.llm.provider import main_provider
from alertlens.pipeline.adaptive import campaign, summarise
from alertlens.pipeline.orchestrator import Options
from alertlens.pipeline.redteam import MAX_CUSTOM_PAYLOAD, attack, attack_custom
from alertlens.pipeline.service import analyze_batch, hero_alerts, load_samples
from data.generator.injections import FAMILIES, PAYLOADS, TARGET_FIELDS

router = APIRouter(prefix="/v2", tags=["v2"])


def _clean_alerts() -> dict[str, dict]:
    out = {a["alert_id"]: a for a in hero_alerts() if a["alert_id"] != "HERO-2"}
    for name, sample in load_samples().items():
        if sample.get("source_format") == "native" and not name.startswith("hero"):
            out[sample["alert_id"]] = sample
    return out


@router.get("/samples")
def samples():
    """Sample alerts to analyse. The hero-2 sample carries a hidden instruction."""
    return [{"name": name, "alert": alert} for name, alert in sorted(load_samples().items(), key=lambda x: (not x[0].startswith("hero"), x[0]))]


@router.get("/redteam/options")
def redteam_options():
    return {"alerts": list(_clean_alerts()), "families": FAMILIES, "fields": TARGET_FIELDS,
            "max_custom_payload": MAX_CUSTOM_PAYLOAD, "real_model": _real_model_allowed(),
            "examples": {f: PAYLOADS[f][0] for f in FAMILIES}}


def _real_model_allowed() -> bool:
    s = get_settings()
    return s.llm_provider != "mock" and not s.public_demo


class AttackIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    alert_id: str = Field(max_length=64)
    field: str = Field(max_length=40)
    family: str | None = Field(default=None, max_length=40)
    payload: str | None = Field(default=None, max_length=MAX_CUSTOM_PAYLOAD)
    model: Literal["simulated", "configured"] = "simulated"


@router.post("/redteam/attack")
def redteam_attack(body: AttackIn):
    alerts = _clean_alerts()
    if body.alert_id not in alerts:
        raise KeyError(body.alert_id)
    if body.field not in TARGET_FIELDS:
        raise HTTPException(422, f"field must be one of {TARGET_FIELDS}")
    if body.model == "configured" and not _real_model_allowed():
        raise HTTPException(403, "A real model is not available on this server")
    provider = main_provider() if body.model == "configured" else None
    if body.payload and body.payload.strip():
        out = attack_custom(alerts[body.alert_id], body.payload, body.field, provider)
    elif body.family in FAMILIES:
        out = attack(alerts[body.alert_id], body.family, body.field, provider=provider)
    else:
        raise HTTPException(422, "Give a payload or a known family")
    return {
        "family": out["family"], "field": out["payload_field"], "dirty_alert": out["dirty_alert"],
        "naive": out["naive"].model_dump(), "naive_clean": out["naive_clean"].model_dump(), "naive_fooled": out["naive_fooled"],
        "alertlens": out["alertlens"].model_dump(mode="json"), "alertlens_fooled": out["alertlens_fooled"],
        "clean": {"label": out["alertlens_clean"].severity.label, "score": out["alertlens_clean"].severity.score,
                  "base_score": out["alertlens_clean"].severity.base_score},
        "layers": out["layers"], "model": "configured" if provider else "simulated",
    }


class AdaptiveIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    alert_id: str = Field(max_length=64)
    field: str = Field(max_length=40)
    seed_text: str = Field(min_length=3, max_length=300)
    steps: int = Field(default=20, ge=1, le=40)
    seed: int = Field(default=0, ge=0, le=10_000)


@router.post("/redteam/adaptive")
def redteam_adaptive(body: AdaptiveIn):
    alerts = _clean_alerts()
    if body.alert_id not in alerts:
        raise KeyError(body.alert_id)
    if body.field not in TARGET_FIELDS:
        raise HTTPException(422, f"field must be one of {TARGET_FIELDS}")
    c = campaign(alerts[body.alert_id], body.field, body.seed_text, steps=body.steps, seed=body.seed)
    return {"summary": summarise([c]), "clean_label": c.clean_label, "clean_base_score": c.clean_base_score,
            "attempts": [{"text": a.text, "ops": a.ops, "risk": a.risk, "detected": a.detected, "label": a.label,
                          "base_score": a.base_score, "triage": a.triage} for a in c.attempts]}


@router.post("/demo/hero")
def hero_demo():
    """Analyse the four linked hero alerts and return the incident they form."""
    results, incidents = analyze_batch(hero_alerts(), Options())
    if not incidents:
        raise HTTPException(500, "The hero alerts did not form an incident")
    return {"incident_id": incidents[0].incident_id, "alert_ids": [r.alert.alert_id for r in results]}


def _read(path: str) -> dict | None:
    p = ROOT / path
    return json.loads(p.read_text()) if p.exists() else None


@router.get("/benchmark")
def benchmark():
    """Committed results only. Nothing is recomputed per request."""
    return {"simulated": _read("results/metrics.json"), "real": _read("results/real/benchmark_100/metrics.json"),
            "explainer_before_after": _read("results/real/explainer_before_after.json"),
            "adaptive": (_read("results/adaptive_redteam.json") or {}).get("summary"),
            "adaptive_meta": (_read("results/adaptive_redteam.json") or {}).get("meta"),
            "faithfulness_verifier": _read("results/faithfulness_verifier.json"),
            "faithfulness_model": _read("results/faithfulness_model.json"),
            "external": _read("results/external_injections.json")}
