"""Learned injection detector, for reworded attacks the rules miss.

Training never reads HELDOUT_PAYLOADS. Positives come from an external dataset (see ATTRIBUTION.md) and the
public templates. Negatives come from that dataset and from clean alert strings on a seed the benchmark does
not use. The threshold is chosen on a validation split, to keep false alarms on alert text rare.
"""
from __future__ import annotations

import csv
import json
import logging
import math
import random
import tempfile
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline, make_pipeline

from alertlens.config import ROOT

log = logging.getLogger(__name__)
DATASET = ROOT / "data" / "external" / "deepset_prompt_injections.csv"
MODEL_PATH = ROOT / "models" / "injection_classifier.joblib"
METRICS_PATH = ROOT / "models" / "injection_classifier.json"
TRAIN_SEED, CLEAN_SEED = 42, 1000
MAX_CLEAN_FPR = 0.01
MIN_WORDS = 4


@dataclass
class Bundle:
    pipe: Pipeline
    threshold: float
    metrics: dict = field(default_factory=dict)


def _external(split: str, label: int) -> list[str]:
    with DATASET.open(encoding="utf-8", newline="") as f:
        return [r["text"] for r in csv.DictReader(f) if r["split"] == split and int(r["label"]) == label]


def _clean_alert_strings() -> list[str]:
    """Free text from clean alerts, on a seed the benchmark does not use."""
    from alertlens.safety.injection import iter_strings
    from data.generator.benign_logs import benign_log_lines
    from data.generator.generate import write_benchmark

    with tempfile.TemporaryDirectory() as tmp:
        write_benchmark(CLEAN_SEED, 600, Path(tmp))
        rows = [json.loads(x) for x in (Path(tmp) / "clean_counterparts.jsonl").read_text().splitlines()]
    alert_text = {text for r in rows for _, text in iter_strings(r["alert"], "") if len(text.split()) >= MIN_WORDS}
    return sorted(alert_text | set(benign_log_lines(CLEAN_SEED)))


def _threshold(pipe: Pipeline, clean: list[str]) -> float:
    """The lowest threshold that keeps false alarms on clean alert text under MAX_CLEAN_FPR, floored at 0.5."""
    scores = sorted(pipe.predict_proba(clean)[:, 1], reverse=True)
    allowed = int(len(scores) * MAX_CLEAN_FPR)
    return max(0.5, math.ceil(float(scores[allowed]) * 10000 + 1) / 10000)


def _fit(pos: list[str], neg: list[str], clean: list[str]) -> Pipeline:
    rng = random.Random(TRAIN_SEED)
    # Attackers keep the real value, so train on attack text that sits after normal alert text too.
    planted = [f"{rng.choice(clean)} {p}" for p in pos]
    texts = pos + planted + neg + clean
    y = [1] * (len(pos) + len(planted)) + [0] * (len(neg) + len(clean))
    pipe = make_pipeline(TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 5), lowercase=True, min_df=2, sublinear_tf=True),
                         LogisticRegression(C=10.0, class_weight="balanced", max_iter=2000, random_state=TRAIN_SEED))
    return pipe.fit(texts, y)


def train() -> Bundle:
    from data.generator.injections import PAYLOADS

    rng = random.Random(TRAIN_SEED)
    pos = _external("train", 1) + [p for family in PAYLOADS.values() for p in family]
    neg = _external("train", 0)
    clean = _clean_alert_strings()
    rng.shuffle(pos), rng.shuffle(neg), rng.shuffle(clean)
    cut_pos, cut_neg, cut_clean = len(pos) // 5, len(neg) // 5, len(clean) // 5
    pipe = _fit(pos[cut_pos:], neg[cut_neg:], clean[cut_clean:])
    threshold = _threshold(pipe, clean[:cut_clean])

    final = _fit(pos, neg, clean)
    test_pos, test_neg = _external("test", 1), _external("test", 0)
    metrics = {
        "threshold": threshold, "train_attacks": len(pos), "train_negatives": len(neg) + len(clean),
        "validation_recall": round(float((pipe.predict_proba(pos[:cut_pos])[:, 1] >= threshold).mean()), 4),
        "validation_clean_fpr": round(float((pipe.predict_proba(clean[:cut_clean])[:, 1] >= threshold).mean()), 4),
        "external_test_recall": round(float((final.predict_proba(test_pos)[:, 1] >= threshold).mean()), 4),
        "external_test_fpr": round(float((final.predict_proba(test_neg)[:, 1] >= threshold).mean()), 4),
        "external_test_n": len(test_pos) + len(test_neg),
    }
    return Bundle(final, threshold, metrics)


@lru_cache(maxsize=1)
def load() -> Bundle:
    """Load the saved model, or train it once if it is missing or unreadable."""
    if MODEL_PATH.exists():
        try:
            return joblib.load(MODEL_PATH)
        except Exception:  # noqa: BLE001 - a stale pickle is only a reason to retrain
            log.warning("Retraining the injection classifier: saved model could not be read")
    bundle = train()
    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, MODEL_PATH)
    METRICS_PATH.write_text(json.dumps(bundle.metrics, indent=2) + "\n")
    return bundle


@lru_cache(maxsize=4096)
def score(text: str) -> float:
    """Probability that this text is an injection, or 0.0 when it is below the threshold or too short."""
    if len(text.split()) < MIN_WORDS:
        return 0.0
    bundle = load()
    p = float(bundle.pipe.predict_proba([text])[0, 1])
    return round(p, 4) if p >= bundle.threshold else 0.0


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    MODEL_PATH.unlink(missing_ok=True)
    load.cache_clear()
    log.info("Injection classifier: %s", load().metrics)


if __name__ == "__main__":
    # Run through the imported module, so the saved model loads from any other process.
    from alertlens.safety.classifier import main as _main

    _main()
