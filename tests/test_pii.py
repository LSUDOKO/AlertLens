import re

from alertlens.llm.mock import MockLLM
from alertlens.llm.provider import RecordingProvider
from alertlens.pipeline.orchestrator import Options, analyze
from alertlens.safety.pii import Vault, redact_identifier, redact_text

IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b")
ALERT = {"alert_id": "P1", "rule_id": "AL-1002", "rule_name": "Login from 192.0.2.9", "rule_level": 9, "category": "authentication",
         "user": "dana.test", "host": "WS-010", "src_ip": "203.0.113.9", "dst_ip": "10.0.0.8", "timestamp": "2026-03-02T10:00:00Z",
         "full_log": "Mail to dana@example.com, phone +91 98765 43210, session for dana.test on WS-010 from 203.0.113.9"}


def test_no_raw_email_or_ip_in_any_prompt():
    rec = RecordingProvider(MockLLM())
    analyze(ALERT, Options(deep=True, persist=False, provider=rec, extractor=rec))
    assert len(rec.prompt_log) >= 5
    for p in rec.prompt_log:
        text = p["system"] + p["user"]
        assert not EMAIL.search(text)
        assert not IP.search(text)
        assert "dana.test" not in text
        assert "98765" not in text


def test_final_output_restores_real_values():
    r = analyze(ALERT, Options(deep=True, persist=False))
    text = " ".join(c.text for c in r.explanation.claims)
    assert "dana.test" in text and "203.0.113.9" in text and "<USER_" not in text


def test_placeholders_are_stable():
    v = Vault()
    assert redact_identifier("IP", "10.0.0.1", v) == redact_identifier("IP", "10.0.0.1", v) == "<IP_1>"
    assert redact_identifier("IP", "10.0.0.2", v) == "<IP_2>"
    assert redact_identifier("IP", None, v) is None
    assert v.restore("a <IP_2> b <IP_9>") == "a 10.0.0.2 b <IP_9>"


def test_redact_text_handles_each_kind():
    v = Vault()
    out = redact_text("x@example.org 10.1.1.1 2001:db8:0:1 +91 98765 43210 bob.test FIN-DB-01", v)
    for raw in ["x@example.org", "10.1.1.1", "2001:db8", "98765", "bob.test", "FIN-DB-01"]:
        assert raw not in out
