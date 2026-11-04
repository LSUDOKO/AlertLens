import pytest

from alertlens.pipeline.orchestrator import Options
from alertlens.pipeline.service import analyze_batch
from alertlens.remediation.guardrails import GuardrailError
from alertlens.render.report import build_report


@pytest.fixture()
def incident(hero, db_path):
    return analyze_batch(hero, Options())[1][0].incident_id


def test_markdown_and_html(incident):
    md = build_report(incident, "md")[0].decode()
    assert "finance.admin.test" in md and "Timeline" in md
    html = build_report(incident, "html")[0].decode()
    assert html.startswith("<!doctype html>") and "base64," in html


def test_hindi_keeps_tokens(incident):
    html = build_report(incident, "html", "hi")[0].decode()
    assert "समयरेखा" in html and "203.0.113.45" in html and "T1078" in html


def test_pdf_opens(incident):
    body, media, name = build_report(incident, "pdf")
    assert body.startswith(b"%PDF") and media == "application/pdf" and name.endswith(".pdf") and len(body) > 2000


def test_hindi_pdf_refused_clearly(incident):
    with pytest.raises(GuardrailError):
        build_report(incident, "pdf", "hi")


def test_unknown_incident(db_path):
    with pytest.raises(KeyError):
        build_report("nope", "md")


def test_html_escapes_alert_text(hero, db_path):
    hero[0]["user"] = "<script>alert(1)</script>"
    inc = analyze_batch(hero[:1], Options())[1][0]
    from alertlens.memory import store as db

    with db.db() as conn:
        db.save_incident(conn, inc)
    assert b"<script>alert" not in build_report(inc.incident_id, "html")[0]
