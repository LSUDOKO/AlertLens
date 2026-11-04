"""F18: analyst corrections feed back into the model and the rule weights."""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from alertlens.audit import chain
from alertlens.config import get_settings
from alertlens.memory import store as db
from alertlens.schemas import Alert, FeedbackIn
from alertlens.scoring import model as model_mod
from alertlens.scoring.features import extract, to_vector
from alertlens.scoring.rules import DEFAULT_WEIGHTS, score_rules

log = logging.getLogger(__name__)
FEEDBACK_WEIGHT = 25.0  # one reviewed alert counts for this many generated samples
MIN_RULE_OBSERVATIONS = 5


def record_feedback(fb: FeedbackIn, db_path: str | None = None) -> None:
    """Store a correction with a snapshot of the alert's features. Unknown alerts are rejected."""
    with db.db(db_path) as conn:
        row = conn.execute("SELECT body FROM alerts WHERE alert_id=?", (fb.alert_id,)).fetchone()
        if not row:
            raise KeyError(fb.alert_id)
        features = extract(Alert.model_validate_json(row[0]))
        _, fired = score_rules(features)
        conn.execute("INSERT INTO feedback(alert_id,correct_label,verdict_correct,explanation_rating,comment,features,"
                     "fired_rules,ts) VALUES(?,?,?,?,?,?,?,?)",
                     (fb.alert_id, fb.correct_label, int(fb.verdict_correct), fb.explanation_rating, fb.comment,
                      json.dumps(features), json.dumps([f[0] for f in fired]), datetime.now(timezone.utc).isoformat()))
        chain.append(conn, "analyst", "feedback", {"alert_id": fb.alert_id, "correct_label": fb.correct_label})


def _rule_weights(rows: list[tuple]) -> dict[str, float]:
    """Simple precision update: a rule that keeps firing on benign alerts loses weight, within 0.5 to 1.5."""
    tally: dict[str, list[int]] = {}
    for label, fired in rows:
        for rule in json.loads(fired):
            hit = tally.setdefault(rule, [0, 0])
            hit[0 if label == "malicious" else 1] += 1
    weights = dict(DEFAULT_WEIGHTS)
    for rule, (tp, fp) in tally.items():
        if tp + fp >= MIN_RULE_OBSERVATIONS and rule in weights:
            weights[rule] = round(0.5 + (tp + 1) / (tp + fp + 2), 3)
    return weights


def target_pattern_set(seed: int, n: int = 60) -> tuple[list, list]:
    """A held-out set of the pattern labelled wrong in training, with its true labels."""
    import random

    from data.generator.scenarios import service_token_abuse

    r = random.Random(seed + 777)
    X, y = [], []
    from alertlens.ingest.normalise import normalise

    for i in range(n):
        canon = service_token_abuse(r)[0][0]
        canon["alert_id"] = f"TARGET-{i}"
        X.append(to_vector(extract(normalise({**canon, "source_format": "native"}))))
        y.append(1)
    return X, y


def retrain(db_path: str | None = None, n: int = 3000) -> dict:
    """Retrain with feedback added. Returns before/after metrics on the same held-out sets."""
    s = get_settings()
    before = model_mod.load_model()
    Xh, yh, _ = model_mod.build_dataset(s.seed + 2, max(500, n // 4), training_labels=False)
    Xt, yt = target_pattern_set(s.seed)
    with db.db(db_path) as conn:
        rows = conn.execute("SELECT features, correct_label, fired_rules FROM feedback").fetchall()
    X, y, _ = model_mod.build_dataset(s.seed + 1, n, training_labels=True)
    weights = [1.0] * len(y)
    for features, label, _ in rows:
        X.append(to_vector(json.loads(features)))
        y.append(int(label == "malicious"))
        weights.append(FEEDBACK_WEIGHT)
    after = model_mod.fit(X, y, s.seed, sample_weight=weights)
    report = {
        "feedback_used": len(rows),
        "before": {"held_out": model_mod.evaluate(before, Xh, yh),
                   "target_recall": round(float((before.p_malicious(Xt) >= 0.5).mean()), 4)},
        "after": {"held_out": model_mod.evaluate(after, Xh, yh),
                  "target_recall": round(float((after.p_malicious(Xt) >= 0.5).mean()), 4)},
    }
    after.metrics = {"held_out": report["after"]["held_out"], "feedback_used": len(rows), "seed": s.seed}
    path = Path(s.model_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    import joblib

    joblib.dump(after, path)
    Path(s.rule_weights_path).write_text(json.dumps(_rule_weights([(r[1], r[2]) for r in rows]), indent=2))
    with db.db(db_path) as conn:
        chain.append(conn, "analyst", "retrain", report)
    return report


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    log.info(json.dumps(retrain(), indent=2))


if __name__ == "__main__":
    main()
