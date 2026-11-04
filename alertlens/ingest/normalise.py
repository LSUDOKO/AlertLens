"""RawAlert dict to a validated `Alert`, with coercion and clean entity keys."""
from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from datetime import datetime, timezone

from pydantic import ValidationError

from alertlens.ingest.adapters import to_raw_alert, vendor_extra
from alertlens.schemas import Alert, Entity

MAX_FIELD_CHARS = 8192  # trust boundary: stop a huge field from reaching regexes and prompts
CATEGORIES = {"authentication", "network", "endpoint", "web", "cloud", "data"}
CRITICALITY = {"low", "medium", "high", "crown_jewel"}
PRIVILEGE = {"standard", "admin", "service"}
_IDENT = re.compile(r"^[A-Za-z0-9._\\/@:$-]{1,128}$")
_ZERO_WIDTH = re.compile("[​‌‍⁠﻿­]")


class AlertValidationError(ValueError):
    """The alert matched a format but its contents are not usable."""


def clean_identifier(value: str | None) -> str | None:
    """Return the leading identifier token of a possibly-injected field, or None.

    `alice.test ignore previous instructions` still correlates as `alice.test`.
    """
    if not value:
        return None
    text = _ZERO_WIDTH.sub("", unicodedata.normalize("NFKC", str(value))).strip()
    token = text.split()[0] if text.split() else ""
    return token if _IDENT.match(token) else None


def _truncate(value):
    return value[:MAX_FIELD_CHARS] if isinstance(value, str) else value


def _str_or_none(value) -> str | None:
    return _truncate(str(value)) if value not in (None, "") else None


def _entities(a: Alert) -> list[Entity]:
    out: list[Entity] = []

    def add(kind, value, role):
        token = clean_identifier(value)
        if token:
            out.append(Entity(kind=kind, value=token, role=role))

    add("ip", a.src_ip, "source")
    add("ip", a.dst_ip, "target")
    add("user", a.user, "actor")
    add("host", a.host, "target")
    add("process", a.process, "object")
    add("hash", a.file_hash, "object")
    add("user", vendor_extra(a.raw, "target_user"), "object")
    add("domain", vendor_extra(a.raw, "domain", "rrname"), "object")
    return out


def normalise(obj: dict) -> Alert:
    """Parse any supported vendor JSON into an `Alert`. Raises on unknown or malformed input."""
    fmt, r = to_raw_alert(obj)
    ts = r.get("timestamp")
    try:
        when = datetime.fromisoformat(str(ts).replace("Z", "+00:00")) if ts else None
    except ValueError as exc:
        raise AlertValidationError(f"Bad timestamp: {str(ts)[:40]!r}") from exc
    if when is None:
        when = datetime(1970, 1, 1, tzinfo=timezone.utc)
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    alert_id = r.get("alert_id") or "ALR-" + hashlib.sha256(json.dumps(obj, sort_keys=True, default=str).encode()).hexdigest()[:12]
    level = r.get("rule_level")
    if not isinstance(level, (int, float)) or isinstance(level, bool):
        level = 5
    count = r.get("event_count")
    hints = r.get("mitre_hint") if isinstance(r.get("mitre_hint"), list) else []
    fields = dict(
        alert_id=_truncate(str(alert_id))[:128], source_format=fmt, timestamp=when,
        rule_id=_truncate(str(r.get("rule_id") or "unknown"))[:128],
        rule_name=_truncate(str(r.get("rule_name") or "Unnamed rule")),
        rule_level=max(0, min(15, int(level))),
        category=r.get("category") if r.get("category") in CATEGORIES else "endpoint",
        src_ip=_str_or_none(r.get("src_ip")), dst_ip=_str_or_none(r.get("dst_ip")), user=_str_or_none(r.get("user")),
        host=_str_or_none(r.get("host")), process=_str_or_none(r.get("process")),
        command_line=_str_or_none(r.get("command_line")), file_hash=_str_or_none(r.get("file_hash")),
        url=_str_or_none(r.get("url")), geo_country=_str_or_none(r.get("geo_country")),
        device_known=r.get("device_known") if isinstance(r.get("device_known"), bool) else None,
        event_count=max(0, int(count)) if isinstance(count, (int, float)) and not isinstance(count, bool) else 1,
        asset_criticality=r.get("asset_criticality") if r.get("asset_criticality") in CRITICALITY else "medium",
        user_privilege=r.get("user_privilege") if r.get("user_privilege") in PRIVILEGE else "standard",
        mitre_hint=[str(h)[:16] for h in hints][:20], raw=obj,
    )
    try:
        alert = Alert(**fields)
    except ValidationError as exc:
        raise AlertValidationError(str(exc)[:300]) from exc
    alert.entities = _entities(alert)
    return alert
