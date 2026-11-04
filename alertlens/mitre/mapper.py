"""Alert to ATT&CK techniques, from validated hints and a catalogue of rule ids. Never from free text."""
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

HERE = Path(__file__).parent
# ponytail: a static rule catalogue; load it from the SIEM's rule metadata in a real deployment.
RULE_CATALOGUE: dict[str, dict] = {
    "AL-1001": {"title": "multiple failed logins", "techniques": ["T1110"], "action": "login_failed"},
    "AL-1002": {"title": "a login success after repeated failures", "techniques": ["T1078"], "action": "login"},
    "AL-1003": {"title": "credential stuffing", "techniques": ["T1110.004"], "action": "login_failed"},
    "AL-1004": {"title": "an impossible-travel login", "techniques": ["T1078"], "action": "login"},
    "AL-1005": {"title": "an out-of-hours admin login", "techniques": ["T1078"], "action": "login"},
    "AL-1006": {"title": "a routine user login", "techniques": [], "action": "login"},
    "AL-2001": {"title": "encoded PowerShell execution", "techniques": ["T1059.001", "T1027"], "action": "process_start"},
    "AL-2002": {"title": "certutil fetching a remote file", "techniques": ["T1105"], "action": "process_start"},
    "AL-2003": {"title": "a new local administrator", "techniques": ["T1136", "T1098"], "action": "privilege_change"},
    "AL-2004": {"title": "remote service execution", "techniques": ["T1021.002", "T1569.002"], "action": "process_start"},
    "AL-3001": {"title": "a large outbound transfer", "techniques": ["T1048"], "action": "data_transfer"},
    "AL-3002": {"title": "a suspicious DNS pattern", "techniques": ["T1071.004"], "action": "dns_query"},
    "AL-3003": {"title": "a port scan", "techniques": ["T1046"], "action": "network_conn"},
    "AL-3004": {"title": "a web request to an uncategorised site", "techniques": [], "action": "network_conn"},
    "AL-3005": {"title": "internal host enumeration", "techniques": ["T1018"], "action": "network_conn"},
    "AL-4001": {"title": "a service token used outside its pipeline", "techniques": ["T1078.004"], "action": "other"},
}
TACTIC_ORDER = ["Initial Access", "Execution", "Persistence", "Privilege Escalation", "Defense Evasion",
                "Credential Access", "Discovery", "Lateral Movement", "Collection", "Command and Control",
                "Exfiltration", "Impact"]


@lru_cache(maxsize=1)
def catalogue() -> dict[str, dict]:
    return {t["id"]: t for t in json.loads((HERE / "attack_subset.json").read_text())}


def tactic_weight(tactic: str) -> float:
    """0-1: how far along the attack this tactic usually is."""
    return (TACTIC_ORDER.index(tactic) + 1) / len(TACTIC_ORDER) if tactic in TACTIC_ORDER else 0.0


def map_alert(alert) -> list[dict]:
    """Techniques for an alert. Hints outside the known subset are dropped."""
    ids: list[str] = [h for h in alert.mitre_hint if h in catalogue()]
    entry = RULE_CATALOGUE.get(alert.rule_id)
    if entry:
        ids += [t for t in entry["techniques"] if t not in ids]
    return [catalogue()[i] for i in ids]
