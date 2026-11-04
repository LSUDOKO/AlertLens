"""Everything runs offline with a small model and a throwaway database."""
from __future__ import annotations

import pytest

from alertlens import config
from alertlens.scoring import model as model_mod


@pytest.fixture(scope="session", autouse=True)
def small_model(tmp_path_factory):
    d = tmp_path_factory.mktemp("models")
    config.update_settings(model_path=str(d / "severity.joblib"), rule_weights_path=str(d / "rule_weights.json"),
                           db_path=str(d / "session.db"), llm_provider="mock", quarantine_provider="mock")
    model_mod.train_and_save(seed=42, n=1200)
    yield


@pytest.fixture()
def db_path(tmp_path):
    path = str(tmp_path / "t.db")
    old = config.get_settings().db_path
    config.update_settings(db_path=path)
    yield path
    config.update_settings(db_path=old)


@pytest.fixture()
def hero():
    from alertlens.pipeline.service import hero_alerts

    return hero_alerts()
