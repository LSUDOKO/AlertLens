"""`make faithfulness`: does an explanation depend on its cited evidence?

Two modes, reported separately because they measure different things:

verifier   Delete a claim's cited fields from the evidence and re-check the original claim. Measures whether the
           verifier notices missing evidence. Deterministic, no model needed.
model      Delete a claim's cited fields from the facts, ask the explaining model again, and check whether it still
           states the deleted value. A value that survives was not grounded in that evidence. Needs a real model.

Usage: python -m eval.faithfulness --mode verifier
       python -m eval.faithfulness --mode model --provider ollama --model llama3.2 --alerts 5
"""
from __future__ import annotations

import argparse
import copy
import json
import logging
from dataclasses import replace
from datetime import datetime, timezone

from alertlens.config import ROOT, get_settings
from alertlens.llm.explainer import evidence_map, explain
from alertlens.llm.mock import MockLLM
from alertlens.llm.provider import build_provider
from alertlens.pipeline.orchestrator import Options, analyze
from alertlens.safety.verifier import verify_claims

log = logging.getLogger(__name__)


def ablate(payload: dict, keys: list[str]) -> dict:
    """The same facts with the given evidence keys removed."""
    out = copy.deepcopy(payload)
    for key in keys:
        section, _, rest = key.partition(".")
        if section in {"alert", "facts", "severity", "sanitise"}:
            out.get(section, {}).pop(key, None)
        elif section in {"mitre", "similar"}:
            idx, _, part = rest.partition(".")
            items = out.get(section, [])
            if idx.isdigit() and int(idx) < len(items):
                items[int(idx)].pop(part, None)
        elif section == "context":
            (out.get("context") or {}).pop(rest, None)
    return out


def concrete(value) -> str | None:
    """A value worth looking for in text: not a boolean, not a single character."""
    if isinstance(value, bool) or value is None:
        return None
    text = str(value)
    return text if len(text) >= 2 else None


def load_alerts(n: int) -> list[dict]:
    rows = [json.loads(x) for x in (ROOT / "data" / "benchmark" / "alerts.jsonl").read_text().splitlines()][: n * 6]
    return rows[:: 6][:n] if n else rows


def verifier_mode(n: int) -> dict:
    checked = caught = 0
    for alert in load_alerts(n):
        r = analyze(alert, Options(persist=False, deep=True, keep_payload=True, provider=MockLLM(), extractor=MockLLM()))
        for claim in r.explanation.claims:
            if not claim.evidence:
                continue
            gone = evidence_map(ablate(r.facts_payload, claim.evidence))
            kept, _, _ = verify_claims([claim], gone, r.severity.label)
            checked += 1
            caught += int(not kept or kept[0].status != "verified")
    return {"mode": "verifier", "alerts": n, "claims_checked": checked, "flagged_when_evidence_removed": caught,
            "rate": round(caught / checked, 4) if checked else None}


def model_mode(n: int, provider: str, model_name: str) -> dict:
    model = build_provider(provider, replace(get_settings(), llm_provider=provider, llm_model=model_name))
    rows, tested, survived = [], 0, 0
    for alert in load_alerts(n):
        r = analyze(alert, Options(persist=False, deep=True, keep_payload=True, provider=model, extractor=model))
        evidence = evidence_map(r.facts_payload)
        for claim in [c for c in r.explanation.claims if c.status != "unsupported"][:3]:
            values = {k: concrete(evidence.get(k)) for k in claim.evidence if k in evidence}
            values = {k: v for k, v in values.items() if v}
            if not values:
                continue
            gone = ablate(r.facts_payload, list(values))
            leftover = json.dumps(gone, ensure_ascii=False, default=str).lower()
            # A value still present elsewhere in the facts, in any case, is legitimately available, so it does not count.
            targets = {k: v for k, v in values.items() if v.lower() not in leftover}
            if not targets:
                continue
            again = explain(gone, model).call
            text = " ".join([again.value.summary, again.value.what_happened, again.value.why_it_matters,
                             *[c.text for c in again.value.claims]])
            kept_values = [k for k, v in targets.items() if v.lower() in text.lower()]
            tested += 1
            survived += int(bool(kept_values))
            rows.append({"alert_id": r.alert.alert_id, "claim": claim.text, "removed": targets, "still_stated": kept_values,
                         "fallback": again.fallback})
            log.info("%s | removed %s | still stated %s", r.alert.alert_id, list(targets), kept_values)
    return {"mode": "model", "model": f"{provider}:{model_name}", "alerts": n, "claims_tested": tested,
            "claims_restated_without_evidence": survived, "rate": round(survived / tested, 4) if tested else None, "rows": rows}


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    p = argparse.ArgumentParser()
    p.add_argument("--mode", choices=["verifier", "model"], default="verifier")
    p.add_argument("--alerts", type=int, default=50)
    p.add_argument("--provider", default="ollama")
    p.add_argument("--model", default="llama3.2")
    a = p.parse_args()
    out = verifier_mode(a.alerts) if a.mode == "verifier" else model_mode(a.alerts, a.provider, a.model)
    out["date"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    path = ROOT / "results" / f"faithfulness_{a.mode}.json"
    path.write_text(json.dumps(out, indent=1, ensure_ascii=False) + "\n")
    log.info("%s", {k: v for k, v in out.items() if k != "rows"})


if __name__ == "__main__":
    main()
