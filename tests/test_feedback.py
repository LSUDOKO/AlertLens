import pytest

from alertlens import config
from alertlens.feedback.loop import record_feedback, retrain, target_pattern_set
from alertlens.pipeline.orchestrator import Options, analyze
from alertlens.schemas import FeedbackIn
from alertlens.scoring import model as model_mod
from alertlens.scoring.rules import load_weights


def test_unknown_alert_is_rejected(db_path):
    with pytest.raises(KeyError):
        record_feedback(FeedbackIn(alert_id="nope", correct_label="benign", verdict_correct=True))


def test_twenty_corrections_improve_the_planted_pattern(db_path, tmp_path):
    import random

    from data.generator.scenarios import service_token_abuse

    s = config.get_settings()
    config.update_settings(model_path=str(tmp_path / "m.joblib"), rule_weights_path=str(tmp_path / "w.json"))
    try:
        model_mod.train_and_save(seed=42, n=800)
        X, _ = target_pattern_set(42)
        before = float((model_mod.load_model().p_malicious(X) >= 0.5).mean())
        rng = random.Random(1)
        for i in range(20):
            canon = service_token_abuse(rng)[0][0]
            canon.update(alert_id=f"F{i}", source_format="native")
            analyze(canon, Options())
            record_feedback(FeedbackIn(alert_id=f"F{i}", correct_label="malicious", verdict_correct=False))
        report = retrain(n=800)
        assert report["feedback_used"] == 20
        assert report["after"]["target_recall"] > before
        assert report["after"]["target_recall"] > report["before"]["target_recall"]
        assert report["after"]["held_out"]["f1"] > 0.8
        assert load_weights()["high_rule_level"] > 0
    finally:
        config.update_settings(model_path=s.model_path, rule_weights_path=s.rule_weights_path)
