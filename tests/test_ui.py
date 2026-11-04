"""Each page runs through Streamlit's test harness, and any exception fails the test."""
from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

ROOT = Path(__file__).resolve().parent.parent
PAGES = [str(ROOT / "ui/Home.py"), *sorted(str(p) for p in (ROOT / "ui/pages").glob("*.py"))]


@pytest.fixture(autouse=True)
def seeded(db_path):
    from scripts.seed_db import seed

    seed(db_path, benchmark_share=5)


@pytest.mark.parametrize("page", PAGES)
def test_page_runs_clean(page):
    at = AppTest.from_file(page, default_timeout=60).run()
    assert not at.exception, [e.value for e in at.exception]


def test_analyze_shows_injection_banner_and_action_flow():
    at = AppTest.from_file(str(ROOT) + "/ui/pages/1_Analyze_Alert.py", default_timeout=60).run()
    next(b for b in at.button if b.label == "Analyze alert").click().run()
    assert not at.exception, [e.value for e in at.exception]
    html = " ".join(m.value for m in at.markdown)
    assert "Injection attempt detected" in html and "Decided by code, not AI" in html
    assert "<script" not in html
    next(b for b in at.button if b.label == "Approve").click().run()
    assert any("approver name" in e.value for e in at.error)


def test_red_team_attack_runs():
    at = AppTest.from_file(str(ROOT) + "/ui/pages/4_Red_Team_Lab.py", default_timeout=60).run()
    next(b for b in at.button if b.label == "Attack").click().run()
    assert not at.exception, [e.value for e in at.exception]
    assert "Fooled" in [e.value for e in at.error]


def test_audit_buttons():
    at = AppTest.from_file(str(ROOT) + "/ui/pages/7_Audit_Log.py", default_timeout=60).run()
    next(b for b in at.button if b.label == "Verify integrity").click().run()
    assert any("Chain intact" in s.value for s in at.success)
    next(b for b in at.button if b.label == "Run tamper demo on a copy").click().run()
    assert not at.exception, [e.value for e in at.exception]
    assert any("Tamper demo" in e.value for e in at.error)
    assert any("Chain intact" in s.value for s in at.success)


def test_settings_saves():
    from alertlens.config import get_settings, update_settings

    old = get_settings().correlation_window_min
    at = AppTest.from_file(str(ROOT) + "/ui/pages/8_Settings.py", default_timeout=60).run()
    at.number_input[0].set_value(45)
    at.button[0].click().run()
    assert not at.exception and get_settings().correlation_window_min == 45
    update_settings(correlation_window_min=old)


def test_escape_helper():
    from ui.common import esc

    assert esc('<img src=x onerror="a">') == "&lt;img src=x onerror=&quot;a&quot;&gt;"
