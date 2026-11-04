"""F15: the smallest realistic change that drops the label one level, checked by re-scoring."""
from __future__ import annotations

import math
from itertools import combinations

ORDER = ["low", "medium", "high", "critical"]
EDITS: list[tuple[str, callable, callable, str]] = [
    ("device_unknown", lambda f: f["device_unknown"] == 1, lambda f: {"device_unknown": 0.0}, "the device were known"),
    ("geo_unusual", lambda f: f["geo_unusual"] == 1, lambda f: {"geo_unusual": 0.0}, "the location were usual for this account"),
    ("off_hours", lambda f: f["off_hours"] == 1, lambda f: {"off_hours": 0.0}, "it had happened during business hours"),
    ("event_count", lambda f: f["log_event_count"] > math.log1p(3), lambda f: {"log_event_count": math.log1p(1), "many_failures": 0.0},
     "there had been only one attempt"),
    ("asset", lambda f: f["asset_criticality"] >= 2, lambda f: {"asset_criticality": f["asset_criticality"] - 1},
     "the asset were one criticality level lower"),
    ("bad_ip", lambda f: f["bad_ip"] == 1, lambda f: {"bad_ip": 0.0}, "the address were not on the reputation list"),
    ("transfer", lambda f: f["log_mb_out"] > math.log1p(50), lambda f: {"log_mb_out": math.log1p(50)},
     "the transfer had been under 50 MB"),
    ("destination", lambda f: f["external_dst"] == 1, lambda f: {"external_dst": 0.0}, "the destination were internal"),
    ("encoded", lambda f: f["encoded_command"] == 1, lambda f: {"encoded_command": 0.0}, "the command line were not encoded"),
    ("tool", lambda f: f["suspicious_tool"] == 1, lambda f: {"suspicious_tool": 0.0}, "no commonly abused tool were involved"),
    ("hash", lambda f: f["known_bad_hash"] == 1, lambda f: {"known_bad_hash": 0.0}, "the file were not known to be bad"),
    ("dns", lambda f: f["dns_long"] == 1, lambda f: {"dns_long": 0.0}, "the DNS names were short and ordinary"),
    ("privilege", lambda f: f["is_admin"] == 1, lambda f: {"is_admin": 0.0}, "the account were not an admin"),
]


# Last resort, because a person cannot act on it: the rule itself being less confident.
RULE_EDIT = ("rule_level", lambda f: f["rule_level"] >= 4, lambda f: {"rule_level": f["rule_level"] - 4},
             "the detection rule had fired four levels lower")


def find_counterfactuals(features: dict[str, float], label: str, risk: float, limit: int = 2) -> list[str]:
    """Search single edits, then larger sets, up to four. Every candidate is re-scored by the real scorer."""
    from alertlens.scoring.features import to_vector
    from alertlens.scoring.model import load_model
    from alertlens.scoring.rules import score_rules
    from alertlens.scoring.scorer import MODEL_WEIGHT, RULE_WEIGHT, injection_bump, label_of

    if label == "low":
        return []
    target = ORDER[ORDER.index(label) - 1]
    edits = [e for e in EDITS if e[1](features)]
    model = load_model()
    plans = [(edits, size) for size in (1, 2, 3, 4)] + [(edits + [RULE_EDIT], size) for size in (1, 2, 3)]
    for pool, size in plans:
        combos = [c for c in combinations(pool, size) if pool is edits or RULE_EDIT in c]
        if not combos:
            continue
        variants = []
        for combo in combos:
            changed = dict(features)
            for edit in combo:
                changed.update(edit[2](features))
            variants.append(changed)
        probs = model.p_malicious([to_vector(v) for v in variants])
        results = []
        for combo, variant, p in zip(combos, variants, probs, strict=True):
            base = RULE_WEIGHT * score_rules(variant)[0] + MODEL_WEIGHT * 100 * float(p)
            if ORDER.index(label_of(min(100.0, base + injection_bump(risk)))) < ORDER.index(label):
                results.append(f"Would be {target.upper()} if " + " and ".join(e[3] for e in combo) + ".")
        if results:
            return results[:limit]
    return []
