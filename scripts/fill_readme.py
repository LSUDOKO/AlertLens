"""Rewrite the README results table from results/metrics.json. Run after `make eval`."""
from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def pct(v) -> str:
    return f"{100 * v:.1f}%"


def table(r: dict) -> str:
    a, d, t = r["asr"], r["detection"], r["triage"]["alertlens"]
    rows = [
        ("Attack success, naive baseline (simulated)", pct(a["naive"])),
        ("Attack success, AlertLens", pct(a["alertlens"])),
        ("AlertLens misses caused by the injection itself", pct(a["alertlens_injection_caused"])),
        ("Detection recall on payload templates", f"{pct(d['recall_known_templates'])} (n={d['known_n']})"),
        ("Detection recall on held-out paraphrases", f"{pct(d['recall_heldout_paraphrases'])} (n={d['heldout_n']})"),
        ("False-positive rate on clean alerts", pct(d["false_positive_rate"])),
        ("Labels lowered by a payload", str(r["invariance"]["labels_lowered"])),
        ("Non-playbook actions", pct(r["unsafe_actions"]["alertlens"])),
        ("Mean grounding score, LLM path", str(r["grounding"]["mean_llm_path"])),
        ("Verdict F1 on synthetic labels", str(t["f1"])),
        ("Calibration error (ECE)", str(r["calibration"]["ece"])),
        ("Correlation pairwise precision", pct(r["correlation"]["precision"])),
        ("Correlation pairwise recall", pct(r["correlation"]["recall"])),
        ("Alerts handled without an LLM", pct(r["routing"]["fast_share"])),
        ("Counterfactual coverage, high or critical", pct(r["counterfactuals"]["coverage"])),
    ]
    m = r["meta"]
    head = f"{m['alerts']} synthetic alerts, {m['injected_malicious']} injected and malicious, seed {m['seed']}, model `{m['model']}`.\n\n"
    return head + "| Metric | Measured |\n|---|---|\n" + "\n".join(f"| {k} | {v} |" for k, v in rows)


def main() -> None:
    path = ROOT / "README.md"
    text = path.read_text()
    block = "<!-- results -->\n" + table(json.loads((ROOT / "results" / "metrics.json").read_text())) + "\n<!-- /results -->"
    if "RESULTS_TABLE" in text:
        text = text.replace("RESULTS_TABLE", block)
    else:
        text = re.sub(r"<!-- results -->.*<!-- /results -->", block, text, flags=re.DOTALL)
    path.write_text(text)


if __name__ == "__main__":
    main()
