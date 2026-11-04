"""F6: group alerts that share an entity within a time window, using union-find."""
from __future__ import annotations

import hashlib
from datetime import timedelta

from alertlens.config import get_settings
from alertlens.schemas import Alert

CORRELATION_KINDS = {"user", "host", "ip", "hash", "domain"}
MIN_LINK_LEVEL = 6  # routine low-level noise stays out of incidents; it would chain unrelated alerts together


def _actor(alert: Alert) -> str | None:
    return next((e.value.casefold() for e in alert.entities if e.kind == "user" and e.role == "actor"), None)


def _different_users(a: Alert, b: Alert) -> bool:
    ua, ub = _actor(a), _actor(b)
    return bool(ua and ub and ua != ub)


def correlate(alerts: list[Alert], window_min: int | None = None) -> list[list[Alert]]:
    """Return groups in time order. Failure cases: shared infrastructure over-merges; slow attacks split."""
    window = timedelta(minutes=window_min if window_min is not None else get_settings().correlation_window_min)
    ordered = sorted(alerts, key=lambda a: a.timestamp)
    parent = list(range(len(ordered)))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    last_seen: dict[tuple[str, str], int] = {}
    for i, alert in enumerate(ordered):
        if alert.rule_level < MIN_LINK_LEVEL:
            continue
        for entity in alert.entities:
            if entity.kind not in CORRELATION_KINDS:
                continue
            key = (entity.kind, entity.value.casefold())
            j = last_seen.get(key)
            if j is not None and alert.timestamp - ordered[j].timestamp <= window:
                # A host used by two different accounts is shared infrastructure, not a link.
                if not (entity.kind == "host" and _different_users(alert, ordered[j])):
                    parent[find(i)] = find(j)
            last_seen[key] = i
    groups: dict[int, list[Alert]] = {}
    for i, alert in enumerate(ordered):
        groups.setdefault(find(i), []).append(alert)
    return list(groups.values())


def incident_id_for(alert_ids: list[str]) -> str:
    return "INC-" + hashlib.sha256("|".join(sorted(alert_ids)).encode()).hexdigest()[:8]
