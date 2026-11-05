"""Run one injected alert on a local Ollama model and save every prompt and reply as evidence.

Usage: python -m scripts.real_model_proof --model llama3.2 --out results/real/proof_trace.json
"""
from __future__ import annotations

import argparse
import json
from dataclasses import replace
from pathlib import Path
from urllib.request import urlopen

from alertlens.config import ROOT, get_settings
from alertlens.llm.provider import build_provider
from alertlens.pipeline.orchestrator import Options, analyze
from alertlens.pipeline.redteam import naive_verdict


class Trace:
    """Passes calls to the real provider and keeps what went in and came out."""

    def __init__(self, inner):
        self.inner, self.name, self.model, self.calls = inner, inner.name, inner.model, []

    def complete(self, system, user, **kw):
        resp = self.inner.complete(system, user, **kw)
        self.calls.append({"system_head": system[:160], "user": user, "reply": resp.text, "provider": resp.provider,
                           "model": resp.model, "latency_ms": round(resp.latency_ms), "tokens": resp.tokens})
        return resp


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--model", default="llama3.2")
    p.add_argument("--alert-id", default="ALR-42-000807")
    p.add_argument("--out", type=Path, default=ROOT / "results" / "real" / "proof_trace.json")
    a = p.parse_args()

    s = replace(get_settings(), llm_provider="ollama", llm_model=a.model)
    with urlopen(f"{s.llm_base_url}/api/version", timeout=5) as r:
        server = json.load(r)
    data = ROOT / "data" / "benchmark"
    alerts = [json.loads(x) for x in (data / "alerts.jsonl").read_text().splitlines()]
    truths = [json.loads(x) for x in (data / "ground_truth.jsonl").read_text().splitlines()]
    i = next(n for n, t in enumerate(truths) if t["alert_id"] == a.alert_id)
    payload = truths[i]["injection"]["payload"]

    model = Trace(build_provider("ollama", s))
    naive = naive_verdict(alerts[i], model)
    naive_calls, model.calls = model.calls, []
    result = analyze(alerts[i], Options(persist=False, provider=model, extractor=model))

    # Call 0 is the quarantined extractor, the only stage allowed to read untrusted text.
    privileged = model.calls[1:]
    report = {
        "ollama_version": server["version"], "model": a.model, "alert_id": a.alert_id,
        "true_label": truths[i]["label"], "injection": truths[i]["injection"],
        "naive": {"verdict": naive.model_dump(), "calls": naive_calls, "payload_in_prompt": payload in naive_calls[0]["user"]},
        "alertlens": {
            "route": result.route, "severity": result.severity.label, "score": result.severity.score,
            "triage": result.severity.triage, "injection_fields": result.sanitise.quarantined_fields,
            "grounding": result.explanation.grounding_score, "safe_fallback": result.explanation.safe_fallback,
            "fallback_reasons": result.explanation.fallback_reasons, "summary": result.explanation.summary,
            "claims_kept": [c.text for c in result.explanation.claims],
            "claims_removed": [{"text": c.text, "reason": c.reason} for c in result.explanation.removed_claims],
            "security_events": result.security_events, "calls": model.calls,
            "payload_in_extractor_prompt": payload in model.calls[0]["user"],
            "payload_in_privileged_prompts": any(payload in c["user"] for c in privileged),
        },
    }
    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    summary = {k: v for k, v in report["alertlens"].items() if k != "calls"}
    print(json.dumps({"ollama": server["version"], "naive": naive.model_dump(include={"severity", "verdict"}),
                      "payload_in_naive_prompt": report["naive"]["payload_in_prompt"], "alertlens": summary},
                     indent=1, ensure_ascii=False))
    for n, c in enumerate(model.calls):
        print(f"call {n}: {c['model']} {c['latency_ms']} ms {c['tokens']} tokens: {c['reply'][:110]!r}")


if __name__ == "__main__":
    main()
