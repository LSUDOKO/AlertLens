"""F8: likely next tactics from a hand-built transition table. A heuristic, not a forecast."""
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

from alertlens.mitre.mapper import catalogue

HEDGE = "Heuristic from a hand-built table, not a certainty."
WATCH = {
    "Execution": "new processes launched from unusual parents",
    "Persistence": "new accounts, services or scheduled tasks",
    "Privilege Escalation": "group membership changes and elevation events",
    "Defense Evasion": "security agents stopped or logs cleared",
    "Credential Access": "access to credential stores, more login failures",
    "Discovery": "bulk account queries and internal scans",
    "Lateral Movement": "remote logins between machines that rarely connect",
    "Collection": "archive tools and bulk file reads on servers",
    "Command and Control": "regular beacons to rare destinations",
    "Exfiltration": "large outbound transfers",
    "Impact": "mass file changes, services stopped, backups removed",
    "Initial Access": "more logins from new devices and countries",
}


@lru_cache(maxsize=1)
def _table() -> dict[str, dict[str, float]]:
    return json.loads((Path(__file__).parent / "transitions.json").read_text())


def predict_next(tactics: list[str], top_k: int = 3) -> list[dict]:
    """Weight recent tactics more, and leave out what has already happened."""
    seen = set(tactics)
    scores: dict[str, float] = {}
    for age, tactic in enumerate(reversed(tactics)):
        for nxt, weight in _table().get(tactic, {}).items():
            if nxt not in seen:
                scores[nxt] = scores.get(nxt, 0.0) + weight * (0.5 ** age)
    total = sum(scores.values()) or 1.0
    ranked = sorted(scores.items(), key=lambda kv: (-kv[1], kv[0]))[:top_k]
    out = []
    for tactic, score in ranked:
        examples = [t["id"] + " " + t["name"] for t in catalogue().values() if t["tactic"] == tactic][:2]
        out.append({"tactic": tactic, "weight": round(score / total, 3), "example_techniques": examples,
                    "watch_for": WATCH.get(tactic, ""), "note": HEDGE})
    return out
