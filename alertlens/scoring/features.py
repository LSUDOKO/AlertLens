"""Alert to numeric features. No LLM output and no free-text meaning reaches the score.

Regexes look only for tool names and flags, and rule lookups use `rule_id`, so appending words to a
string field cannot remove a signal.
"""
from __future__ import annotations

import ipaddress
import math
import re

from alertlens.ingest.adapters import vendor_extra
from alertlens.ingest.normalise import clean_identifier
from alertlens.mitre.mapper import map_alert, tactic_weight
from alertlens.schemas import Alert
from alertlens.scoring.reputation import APPROVED_SCANNERS, BAD_IPS, KNOWN_BAD_HASHES

CRIT = {"low": 0, "medium": 1, "high": 2, "crown_jewel": 3}
FEATURE_NAMES = [
    "rule_level", "asset_criticality", "is_admin", "is_service", "off_hours", "device_unknown", "geo_unusual",
    "bad_ip", "approved_scanner", "external_dst", "log_event_count", "many_failures", "after_failures",
    "known_bad_hash", "tactic_weight", "encoded_command", "suspicious_tool", "log_mb_out", "dns_long",
    "outcome_success", "cat_authentication", "cat_network", "cat_endpoint", "cat_web", "cat_cloud", "cat_data",
]
READABLE = {
    "rule_level": "the rule's level", "asset_criticality": "how critical the asset is", "is_admin": "an admin account",
    "is_service": "a service account", "off_hours": "activity outside business hours", "device_unknown": "an unknown device",
    "geo_unusual": "an unusual location", "bad_ip": "an address on the reputation list",
    "approved_scanner": "an approved scanner", "external_dst": "an external destination",
    "log_event_count": "the number of events", "many_failures": "many failed attempts",
    "after_failures": "success after failures", "known_bad_hash": "a known-bad file",
    "tactic_weight": "the ATT&CK tactic", "encoded_command": "an encoded command", "suspicious_tool": "a suspicious tool",
    "log_mb_out": "the outbound data volume", "dns_long": "long random DNS names",
    "outcome_success": "a successful outcome", "cat_cloud": "cloud activity",
}
TOOL_PATTERNS = [
    ("mimikatz_like", r"mimikatz|sekurlsa|lsadump"), ("psexec", r"psexe"), ("certutil", r"certutil"),
    ("powershell", r"powershell|pwsh"), ("curl_wget", r"\b(curl|wget)\b"), ("scripting", r"\b(wscript|cscript|mshta)\b"),
]
_ENCODED = re.compile(r"\s-e(nc(odedcommand)?)?\s+[A-Za-z0-9+/=]{16,}", re.IGNORECASE)


def tool_of(alert: Alert) -> str:
    text = f"{alert.process or ''} {alert.command_line or ''}"
    for name, pat in TOOL_PATTERNS:
        if re.search(pat, text, re.IGNORECASE):
            return name
    return "none"


def is_external(ip: str | None) -> bool:
    token = clean_identifier(ip)
    if not token:
        return False
    try:
        return not ipaddress.ip_address(token).is_private or token.startswith(("192.0.2.", "198.51.100.", "203.0.113."))
    except ValueError:
        return False


def bytes_out(alert: Alert) -> float:
    v = vendor_extra(alert.raw, "bytes_out")
    return float(v) if isinstance(v, (int, float)) and not isinstance(v, bool) and v >= 0 else 0.0


def outcome_of(alert: Alert) -> str:
    v = vendor_extra(alert.raw, "outcome")
    return v if v in {"success", "failure"} else "unknown"


def is_off_hours(alert: Alert) -> bool:
    return alert.timestamp.hour < 6 or alert.timestamp.hour >= 22


def extract(alert: Alert) -> dict[str, float]:
    """Named features for one alert. Rules and the model both read this dict."""
    src, dst = clean_identifier(alert.src_ip), clean_identifier(alert.dst_ip)
    geo_usual = vendor_extra(alert.raw, "geo_usual")
    domain = clean_identifier(vendor_extra(alert.raw, "domain", "rrname")) or ""
    first_label = domain.split(".")[0] if domain else ""
    techniques = map_alert(alert)
    outcome = outcome_of(alert)
    f = {
        "rule_level": float(alert.rule_level),
        "asset_criticality": float(CRIT[alert.asset_criticality]),
        "is_admin": float(alert.user_privilege == "admin"),
        "is_service": float(alert.user_privilege == "service"),
        "off_hours": float(is_off_hours(alert)),
        "device_unknown": float(alert.device_known is False),
        "geo_unusual": float(geo_usual is False),
        "bad_ip": float(src in BAD_IPS or dst in BAD_IPS),
        "approved_scanner": float(src in APPROVED_SCANNERS),
        "external_dst": float(is_external(alert.dst_ip)),
        "log_event_count": math.log1p(alert.event_count),
        "many_failures": float(outcome == "failure" and alert.event_count >= 10),
        "after_failures": float(alert.rule_id == "AL-1002"),
        "known_bad_hash": float(clean_identifier(alert.file_hash) in KNOWN_BAD_HASHES),
        "tactic_weight": max((tactic_weight(t["tactic"]) for t in techniques), default=0.0),
        "encoded_command": float(bool(_ENCODED.search(alert.command_line or ""))),
        "suspicious_tool": float(tool_of(alert) != "none"),
        "log_mb_out": math.log1p(bytes_out(alert) / 1_000_000),
        "dns_long": float(len(first_label) >= 30),
        "outcome_success": float(outcome == "success"),
    }
    for cat in ("authentication", "network", "endpoint", "web", "cloud", "data"):
        f[f"cat_{cat}"] = float(alert.category == cat)
    return f


def to_vector(features: dict[str, float]) -> list[float]:
    return [features[n] for n in FEATURE_NAMES]
