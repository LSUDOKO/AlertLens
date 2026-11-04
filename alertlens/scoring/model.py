"""Calibrated gradient boosting on synthetic labelled alerts. `python -m alertlens.scoring.model` trains it."""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path

import joblib
import numpy as np
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
from sklearn.model_selection import StratifiedKFold

from alertlens.config import ROOT, get_settings
from alertlens.ingest.normalise import normalise
from alertlens.scoring.features import FEATURE_NAMES, extract, to_vector

log = logging.getLogger(__name__)


@dataclass
class ModelBundle:
    clf: CalibratedClassifierCV
    importances: dict[str, float]
    metrics: dict = field(default_factory=dict)

    def p_malicious(self, vectors: list[list[float]]) -> np.ndarray:
        return self.clf.predict_proba(np.asarray(vectors, dtype=float))[:, 1]


def build_dataset(seed: int, n: int, *, training_labels: bool) -> tuple[list[list[float]], list[int], list[str]]:
    """Features come from clean records. The severity model never trains on injection signals."""
    from data.generator.generate import generate

    recs = generate(seed, n, inject=False, training_labels=training_labels)
    X, y, scenarios = [], [], []
    for rec in recs:
        X.append(to_vector(extract(normalise(rec["alert"]))))
        y.append(int(rec["truth"]["label"] == "malicious"))
        scenarios.append(rec["truth"]["scenario"])
    return X, y, scenarios


def fit(X, y, seed: int, sample_weight=None) -> ModelBundle:
    X, y = np.asarray(X, dtype=float), np.asarray(y)
    base = GradientBoostingClassifier(n_estimators=120, max_depth=3, learning_rate=0.08, subsample=0.9, random_state=seed)
    cv = StratifiedKFold(n_splits=3, shuffle=True, random_state=seed)
    clf = CalibratedClassifierCV(base, method="sigmoid", cv=cv)
    clf.fit(X, y, sample_weight=sample_weight)
    importance_model = GradientBoostingClassifier(n_estimators=120, max_depth=3, learning_rate=0.08, subsample=0.9,
                                                  random_state=seed).fit(X, y, sample_weight=sample_weight)
    return ModelBundle(clf, dict(zip(FEATURE_NAMES, importance_model.feature_importances_.tolist(), strict=True)))


def evaluate(bundle: ModelBundle, X, y) -> dict:
    p = bundle.p_malicious(X)
    pred = (p >= 0.5).astype(int)
    return {"n": len(y), "f1": round(float(f1_score(y, pred)), 4), "precision": round(float(precision_score(y, pred)), 4),
            "recall": round(float(recall_score(y, pred)), 4), "accuracy": round(float(accuracy_score(y, pred)), 4)}


def train_and_save(seed: int | None = None, n: int = 4000, path: str | None = None) -> ModelBundle:
    seed = get_settings().seed if seed is None else seed
    X, y, _ = build_dataset(seed + 1, n, training_labels=True)
    bundle = fit(X, y, seed)
    Xh, yh, _ = build_dataset(seed + 2, max(500, n // 4), training_labels=False)
    bundle.metrics = {"held_out": evaluate(bundle, Xh, yh), "train_n": len(y), "seed": seed}
    target = Path(path or get_settings().model_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, target)
    _cache.clear()
    return bundle


_cache: dict[str, tuple[float, ModelBundle]] = {}


def load_model() -> ModelBundle:
    """Load the saved model, training it first if `make train` has not run."""
    path = Path(get_settings().model_path)
    if not path.exists():
        log.info("No model at %s, training one", path)
        train_and_save()
    key, mtime = str(path), path.stat().st_mtime
    if key not in _cache or _cache[key][0] != mtime:
        _cache[key] = (mtime, joblib.load(path))
    return _cache[key][1]


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    bundle = train_and_save()
    out = ROOT / "results" / "model_metrics.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(bundle.metrics, indent=2) + "\n")
    log.info("Model trained: %s", bundle.metrics)


if __name__ == "__main__":
    # Re-import so the pickle records alertlens.scoring.model.ModelBundle, not __main__.ModelBundle.
    from alertlens.scoring.model import main as _main

    _main()
