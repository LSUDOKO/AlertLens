import json

from eval import metrics as m
from eval.run_benchmark import run


def test_binary_scores():
    s = m.binary_scores([1, 1, 0, 0], [1, 0, 0, 1])
    assert (s["tp"], s["fn"], s["tn"], s["fp"], s["f1"], s["fpr"]) == (1, 1, 1, 1, 0.5, 0.5)


def test_reliability_perfect_and_bad():
    assert m.reliability([1, 0], [1.0, 0.0])["ece"] == 0
    assert m.reliability([0, 0], [0.95, 0.95])["ece"] > 0.9


def test_pairwise():
    out = m.pairwise_correlation([["a", "b"], ["c"]], {"a": "1", "b": "1", "c": "1"})
    assert out["precision"] == 1 and out["recall"] == round(1 / 3, 4)


def test_quick_benchmark_writes_every_artifact(tmp_path):
    r = run(120, None, "", tmp_path)
    assert r["meta"]["simulated_model"] is True and r["meta"]["alerts"] == 120
    saved = json.loads((tmp_path / "metrics.json").read_text())
    assert saved["asr"] == r["asr"]
    report = (tmp_path / "benchmark_report.md").read_text()
    assert "Simulated model" in report and "Ablations" in report and "Limitations" in report
    assert (tmp_path / "charts" / "reliability.png").exists()
    assert r["unsafe_actions"]["alertlens"] == 0
    assert r["invariance"]["base_score_identical"] == 1 and r["invariance"]["labels_lowered"] == 0
