"""Numbers in the README must match the generated report."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def pct(v):
    return f"{100 * v:.1f}%"


def test_readme_matches_metrics():
    r = json.loads((ROOT / "results" / "metrics.json").read_text())
    readme = (ROOT / "README.md").read_text()
    for value in [pct(r["asr"]["naive"]), pct(r["asr"]["alertlens"]), pct(r["asr"]["alertlens_injection_caused"]),
                  pct(r["detection"]["recall_known_templates"]), pct(r["detection"]["recall_heldout_paraphrases"]),
                  pct(r["detection"]["false_positive_rate"]), pct(r["correlation"]["precision"]), pct(r["correlation"]["recall"]),
                  pct(r["counterfactuals"]["coverage"]), pct(r["routing"]["fast_share"]), str(r["calibration"]["ece"]),
                  str(r["grounding"]["mean_llm_path"]), str(r["triage"]["alertlens"]["f1"])]:
        assert value in readme, value
    assert "simulated model" in readme.lower()
