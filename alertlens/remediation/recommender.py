"""F5: actions come only from playbook.yaml. Model output can reorder them, never add to them."""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path

import yaml

from alertlens.ingest.normalise import clean_identifier
from alertlens.schemas import Action, Alert, SanitiseReport, SeverityResult

ORDER = ["low", "medium", "high", "critical"]
INJECTION_BLOCKS_CLOSE = 0.5
MAX_ACTIONS = 5


@lru_cache(maxsize=1)
def playbook() -> dict[str, dict]:
    entries = yaml.safe_load((Path(__file__).parent / "playbook.yaml").read_text())
    return {e["id"]: e for e in entries}


def _render(entry: dict, alert: Alert, reason: str) -> Action:
    ip = clean_identifier(alert.dst_ip) if entry["id"] == "block_ip_at_firewall" and alert.category == "data" else None
    values = {
        "user": clean_identifier(alert.user) or "the account", "host": clean_identifier(alert.host) or "the host",
        "ip": ip or clean_identifier(alert.src_ip) or clean_identifier(alert.dst_ip) or "the address",
        "hash": (clean_identifier(alert.file_hash) or "unknown")[:16],
    }
    return Action(
        action_id=entry["id"], title=entry["title"], reason=reason, risk_level=entry["risk_level"],
        reversible=entry["reversible"], requires_approval=True, two_step=entry.get("two_step", False),
        dry_run_preview=entry["dry_run_template"].format(**values), rollback=entry["rollback_template"].format(**values),
    )


def _applicable(entry: dict, alert: Alert, severity: SeverityResult, sanitise: SanitiseReport, techniques: set[str]) -> bool:
    rank = ORDER.index(severity.label)
    if rank < ORDER.index(entry["min_severity"]):
        return False
    if "max_severity" in entry and rank > ORDER.index(entry["max_severity"]):
        return False
    if entry["id"] == "close_as_benign" and (sanitise.risk > INJECTION_BLOCKS_CLOSE or severity.p_malicious >= 0.1):
        return False
    if entry["id"] in {"disable_user_session", "reset_user_password", "force_mfa_reenrol", "disable_user", "notify_user"} \
            and not clean_identifier(alert.user):
        return False
    if entry["id"] in {"isolate_host", "collect_forensics", "quarantine_file"} and not clean_identifier(alert.host):
        return False
    if entry["id"] == "block_ip_at_firewall" and not (clean_identifier(alert.src_ip) or clean_identifier(alert.dst_ip)):
        return False
    if entry["id"] == "quarantine_file" and not clean_identifier(alert.file_hash):
        return False
    applies = set(entry["applies_to_techniques"])
    return "*" in applies or bool(applies & techniques)


def filter_suggestions(ids: list[str]) -> tuple[list[str], list[str]]:
    """Split model-suggested ids into playbook ids and rejected ones."""
    book = playbook()
    return [i for i in ids if i in book], [i for i in ids if i not in book]


def recommend(alert: Alert, severity: SeverityResult, sanitise: SanitiseReport, mitre: list[dict],
              suggested: list[str] | None = None) -> list[Action]:
    """Pick by technique and severity. Specific actions rank above catch-alls; suggestions move up only."""
    techniques = {t["id"] for t in mitre}
    reason_tail = f"{severity.label} severity"
    chosen = []
    allowed_suggestions = set(filter_suggestions(suggested or [])[0])
    for entry in playbook().values():
        if not _applicable(entry, alert, severity, sanitise, techniques):
            continue
        overlap = sorted(set(entry["applies_to_techniques"]) & techniques)
        reason = f"Fits {', '.join(overlap)} at {reason_tail}" if overlap else f"Standard step at {reason_tail}"
        specific = bool(overlap)
        suggested_rank = entry["id"] in allowed_suggestions
        chosen.append((not suggested_rank, not specific, _render(entry, alert, reason)))
    chosen.sort(key=lambda x: (x[0], x[1]))
    return [c[2] for c in chosen[:MAX_ACTIONS]]
