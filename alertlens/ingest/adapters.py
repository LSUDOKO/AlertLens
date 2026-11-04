"""Vendor JSON to a flat raw dict (F25). Formats are synthetic, modelled on common tools."""
from __future__ import annotations


class UnknownFormatError(ValueError):
    """The JSON matches none of the supported alert formats."""


def detect_format(obj: dict) -> str:
    if not isinstance(obj, dict):
        raise UnknownFormatError("Alert must be a JSON object")
    if isinstance(obj.get("sigma_rule"), dict):
        return "sigma"
    if obj.get("event_type") == "alert" and isinstance(obj.get("alert"), dict):
        return "suricata"
    if isinstance(obj.get("rule"), dict) and "agent" in obj:
        return "wazuh"
    if {"rule_id", "rule_name"} <= obj.keys():
        return "native"
    raise UnknownFormatError(
        "Unknown alert format. Expected native (rule_id, rule_name), Wazuh-style (rule, agent), "
        "Suricata EVE-style (event_type=alert) or Sigma-matched (sigma_rule)."
    )


def _from_wazuh(o: dict) -> dict:
    rule, data, agent = o["rule"], o.get("data") or {}, o.get("agent") or {}
    groups = rule.get("groups") or ["endpoint"]
    return {
        "alert_id": o.get("id"), "timestamp": o.get("timestamp"), "rule_id": rule.get("id"),
        "rule_name": rule.get("description"), "rule_level": rule.get("level"), "category": groups[0],
        "src_ip": data.get("srcip"), "dst_ip": data.get("dstip"), "user": data.get("srcuser"),
        "host": agent.get("name"), "process": data.get("process"), "command_line": data.get("command"),
        "file_hash": data.get("sha256"), "url": data.get("url"), "geo_country": data.get("geo"),
        "device_known": data.get("device_known"), "event_count": data.get("event_count"),
        "asset_criticality": agent.get("criticality"), "user_privilege": data.get("user_privilege"),
        "mitre_hint": (rule.get("mitre") or {}).get("id") or [],
    }


def _from_suricata(o: dict) -> dict:
    al, http, ctx = o["alert"], o.get("http") or {}, o.get("context") or {}
    return {
        "alert_id": o.get("flow_id"), "timestamp": o.get("timestamp"), "rule_id": al.get("signature_id"),
        "rule_name": al.get("signature"), "rule_level": al.get("level", 8), "category": al.get("category", "network"),
        "src_ip": o.get("src_ip"), "dst_ip": o.get("dest_ip"), "user": o.get("user"), "host": o.get("host"),
        "process": o.get("process"), "command_line": o.get("command_line"), "file_hash": ctx.get("file_hash"),
        "url": http.get("url"), "geo_country": ctx.get("geo_country"), "device_known": ctx.get("device_known"),
        "event_count": ctx.get("event_count"), "asset_criticality": ctx.get("asset_criticality"),
        "user_privilege": ctx.get("user_privilege"),
        "mitre_hint": (al.get("metadata") or {}).get("mitre") or [],
    }


def _from_sigma(o: dict) -> dict:
    rule, ev = o["sigma_rule"], o.get("event") or {}
    return {
        "alert_id": o.get("alert_id"), "timestamp": o.get("matched_at"), "rule_id": rule.get("id"),
        "rule_name": rule.get("title"), "rule_level": rule.get("score", 8), "category": rule.get("logsource", "endpoint"),
        "src_ip": ev.get("src_ip"), "dst_ip": ev.get("dst_ip"), "user": ev.get("user"), "host": ev.get("host"),
        "process": ev.get("process"), "command_line": ev.get("command_line"), "file_hash": ev.get("file_hash"),
        "url": ev.get("url"), "geo_country": ev.get("geo_country"), "device_known": ev.get("device_known"),
        "event_count": ev.get("event_count"), "asset_criticality": ev.get("asset_criticality"),
        "user_privilege": ev.get("user_privilege"), "mitre_hint": rule.get("tags") or [],
    }


def _from_native(o: dict) -> dict:
    keys = ["alert_id", "timestamp", "rule_id", "rule_name", "rule_level", "category", "src_ip", "dst_ip", "user", "host",
            "process", "command_line", "file_hash", "url", "geo_country", "device_known", "event_count",
            "asset_criticality", "user_privilege", "mitre_hint"]
    return {k: o.get(k) for k in keys}


ADAPTERS = {"wazuh": _from_wazuh, "suricata": _from_suricata, "sigma": _from_sigma, "native": _from_native}


def to_raw_alert(obj: dict) -> tuple[str, dict]:
    fmt = detect_format(obj)
    return fmt, ADAPTERS[fmt](obj)


def vendor_extra(raw: dict, *keys: str):
    """Find a vendor field wherever the format nested it. Used for numeric/boolean context only."""
    containers = [raw, raw.get("data"), raw.get("context"), raw.get("event"), raw.get("dns"), raw.get("http")]
    for key in keys:
        for box in containers:
            if isinstance(box, dict) and box.get(key) is not None:
                return box[key]
    return None
