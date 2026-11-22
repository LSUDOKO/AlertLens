"""`make redteam`: run adaptive attack campaigns and write results/adaptive_redteam.json.

Usage: python -m eval.adaptive [--steps 30] [--provider ollama --model llama3.2] [--llm-attacker]
Without --provider, AlertLens and the naive check both use the simulated gullible model.
"""
from __future__ import annotations

import argparse
import json
import logging
from dataclasses import asdict, replace
from datetime import datetime, timezone

from alertlens.config import ROOT, get_settings
from alertlens.llm.provider import build_provider
from alertlens.pipeline.adaptive import campaign, summarise
from alertlens.pipeline.service import hero_alerts
from data.generator.injections import PAYLOADS

log = logging.getLogger(__name__)
FIELDS = ["user_agent", "full_log", "command_line"]


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    p = argparse.ArgumentParser()
    p.add_argument("--steps", type=int, default=30)
    p.add_argument("--provider")
    p.add_argument("--model", default="")
    p.add_argument("--llm-attacker", action="store_true")
    p.add_argument("--out", default=str(ROOT / "results" / "adaptive_redteam.json"))
    a = p.parse_args()
    model = attacker = None
    if a.provider:
        model = build_provider(a.provider, replace(get_settings(), llm_provider=a.provider, llm_model=a.model))
        attacker = model if a.llm_attacker else None
    alerts = [x for x in hero_alerts() if x["alert_id"] != "HERO-2"]
    camps = []
    for i, (family, payloads) in enumerate(sorted(PAYLOADS.items())):
        alert, field = alerts[i % len(alerts)], FIELDS[i % len(FIELDS)]
        camps.append(campaign(alert, field, payloads[0], steps=a.steps, seed=i, model=model, attacker=attacker))
        log.info("%s: %d evaded of %d, %d changed a decision", family, len(camps[-1].evaded), len(camps[-1].attempts),
                 len(camps[-1].decision_changed))
    report = {"meta": {"date": datetime.now(timezone.utc).isoformat(timespec="seconds"), "steps": a.steps,
                       "model": f"{a.provider}:{a.model}" if a.provider else "vulnerable-mock (simulated)",
                       "llm_attacker": a.llm_attacker, "attacker_view": "white-box: sees detector risk each step"},
              "summary": summarise(camps),
              "campaigns": [{"seed": c.seed_text, "field": c.field, "clean_label": c.clean_label,
                             "attempts": [asdict(x) for x in c.attempts]} for c in camps]}
    with open(a.out, "w") as f:
        json.dump(report, f, indent=1, ensure_ascii=False)
    log.info("Summary: %s", json.dumps(report["summary"])[:600])


if __name__ == "__main__":
    main()
