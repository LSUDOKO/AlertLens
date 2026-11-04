"""Transparent weighted rules. Each rule reads named features and adds points to a 0-100 score."""
from __future__ import annotations

import json
from pathlib import Path

from alertlens.config import get_settings

RULES: list[tuple[str, str, float, callable]] = [
    ("high_rule_level", "The detection rule fired at a high level", 36, lambda f: f["rule_level"] / 15),
    ("crown_jewel", "The asset is a crown jewel", 16, lambda f: float(f["asset_criticality"] == 3)),
    ("critical_asset", "The asset is rated high criticality", 8, lambda f: float(f["asset_criticality"] == 2)),
    ("admin_account", "An admin account is involved", 8, lambda f: f["is_admin"]),
    ("off_hours", "It happened outside business hours", 6, lambda f: f["off_hours"]),
    ("new_device", "The device is not known", 8, lambda f: f["device_unknown"]),
    ("new_geo", "The location is unusual for this account", 8, lambda f: f["geo_unusual"]),
    ("bad_reputation", "An address is on the reputation list", 15, lambda f: f["bad_ip"]),
    ("known_bad_hash", "The file hash is known to be bad", 20, lambda f: f["known_bad_hash"]),
    ("encoded_command", "The command line is encoded", 12, lambda f: f["encoded_command"]),
    ("suspicious_tool", "A commonly abused tool was used", 8, lambda f: f["suspicious_tool"]),
    ("many_failures", "There were many failed attempts", 8, lambda f: f["many_failures"]),
    ("success_after_failures", "A login succeeded after repeated failures", 14, lambda f: f["after_failures"]),
    ("large_transfer_out", "A large amount of data left for an external address", 18,
     lambda f: float(f["external_dst"] and f["log_mb_out"] > 5.5)),
    ("dns_tunnel_shape", "DNS names look long and random", 12, lambda f: f["dns_long"]),
    ("late_stage_tactic", "The ATT&CK tactic is late in an attack", 10, lambda f: f["tactic_weight"]),
    ("approved_scanner", "The source is the approved scanner", -25, lambda f: f["approved_scanner"]),
]
DEFAULT_WEIGHTS: dict[str, float] = {r[0]: 1.0 for r in RULES}
_cache: dict[str, tuple[float, dict[str, float]]] = {}


def load_weights() -> dict[str, float]:
    """Per-rule multipliers learned from analyst feedback. Default is 1.0."""
    path = Path(get_settings().rule_weights_path)
    if not path.exists():
        return DEFAULT_WEIGHTS
    mtime = path.stat().st_mtime
    key = str(path)
    if key not in _cache or _cache[key][0] != mtime:
        _cache[key] = (mtime, {**DEFAULT_WEIGHTS, **json.loads(path.read_text())})
    return _cache[key][1]


def score_rules(features: dict[str, float]) -> tuple[float, list[tuple[str, str, float]]]:
    """Return (0-100 score, fired rules as (id, reason, points), biggest first)."""
    weights = load_weights()
    fired = []
    for rule_id, reason, points, fn in RULES:
        value = fn(features)
        if value:
            fired.append((rule_id, reason, round(points * float(value) * weights[rule_id], 2)))
    total = sum(p for _, _, p in fired)
    fired.sort(key=lambda x: -abs(x[2]))
    return max(0.0, min(100.0, total)), fired
