"""Metric functions. Each takes measured records and returns numbers. Nothing here is a target."""
from __future__ import annotations

import re
from itertools import combinations

import numpy as np

IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def rate(hits: int, total: int) -> float | None:
    return round(hits / total, 4) if total else None


def binary_scores(y_true: list[int], y_pred: list[int]) -> dict:
    tp = sum(t == 1 and p == 1 for t, p in zip(y_true, y_pred, strict=True))
    fp = sum(t == 0 and p == 1 for t, p in zip(y_true, y_pred, strict=True))
    fn = sum(t == 1 and p == 0 for t, p in zip(y_true, y_pred, strict=True))
    tn = sum(t == 0 and p == 0 for t, p in zip(y_true, y_pred, strict=True))
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "accuracy": rate(tp + tn, len(y_true)), "precision": round(precision, 4),
            "recall": round(recall, 4), "f1": round(f1, 4), "fpr": rate(fp, fp + tn)}


def reliability(y_true: list[int], probs: list[float], bins: int = 10) -> dict:
    """Expected calibration error, plus the points for a reliability diagram."""
    y, p = np.asarray(y_true, dtype=float), np.asarray(probs, dtype=float)
    edges = np.linspace(0, 1, bins + 1)
    idx = np.minimum(np.digitize(p, edges[1:-1]), bins - 1)
    ece, points = 0.0, []
    for b in range(bins):
        mask = idx == b
        if mask.any():
            conf, acc = float(p[mask].mean()), float(y[mask].mean())
            ece += mask.mean() * abs(conf - acc)
            points.append({"confidence": round(conf, 4), "observed": round(acc, 4), "n": int(mask.sum())})
    return {"ece": round(float(ece), 4), "points": points}


def pairwise_correlation(groups_pred: list[list[str]], truth_group: dict[str, str]) -> dict:
    """Pairwise precision and recall of incident grouping."""
    def pairs(groups):
        out = set()
        for group in groups:
            out.update(tuple(sorted(pair)) for pair in combinations(group, 2))
        return out

    by_truth: dict[str, list[str]] = {}
    for aid, group in truth_group.items():
        by_truth.setdefault(group, []).append(aid)
    pred, true = pairs(groups_pred), pairs(by_truth.values())
    both = len(pred & true)
    return {"pairs_predicted": len(pred), "pairs_true": len(true), "precision": rate(both, len(pred)), "recall": rate(both, len(true))}


def invented_ips(text: str, alert_json: str) -> list[str]:
    """IP addresses in shown text that do not occur anywhere in the alert."""
    return [ip for ip in IP.findall(text) if ip not in alert_json]
