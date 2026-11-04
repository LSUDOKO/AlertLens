import pytest
from fastapi.testclient import TestClient

from alertlens.api.main import app
from alertlens.schemas import AnalysisResult


@pytest.fixture()
def client(db_path):
    return TestClient(app)


def test_health(client):
    body = client.get("/health").json()
    assert body["status"] == "ok" and body["provider"] == "mock"


def test_analyze_returns_schema(client, hero):
    r = client.post("/analyze", json=hero[1], params={"deep": "true", "audience": "manager", "lang": "hi"})
    assert r.status_code == 200
    parsed = AnalysisResult.model_validate(r.json())
    assert parsed.sanitise.quarantined_fields and parsed.explanation.audience == "manager"


def test_unknown_format_is_structured_error(client):
    r = client.post("/analyze", json={"foo": 1})
    assert r.status_code == 422 and r.json()["error"] == "unknown_format"


def test_bad_query_is_structured_error(client, hero):
    r = client.post("/analyze", json=hero[0], params={"audience": "ceo"})
    assert r.status_code == 422 and r.json()["error"] == "invalid_request"


def test_oversized_body_refused(client):
    r = client.post("/analyze", content=b"x" * 10, headers={"content-length": "99999999"})
    assert r.status_code == 413 and r.json()["error"] == "too_large"


def test_batch_incidents_and_report(client, hero):
    r = client.post("/analyze/batch", json=hero)
    assert r.status_code == 200 and len(r.json()["incidents"]) == 1
    iid = r.json()["incidents"][0]["incident_id"]
    assert client.get("/incidents").json()[0]["incident_id"] == iid
    assert client.get(f"/incidents/{iid}").json()["pivot"] == "finance.admin.test"
    for fmt in ["md", "html", "pdf"]:
        assert client.get(f"/incidents/{iid}/report", params={"format": fmt}).status_code == 200
    assert client.get(f"/incidents/{iid}/report", params={"format": "pdf", "lang": "hi"}).status_code == 409
    assert client.get("/incidents/nope").status_code == 404


def test_batch_limit(client):
    assert client.post("/analyze/batch", json=[{}] * 5001).status_code == 413


def test_actions_flow(client, hero):
    client.post("/analyze", json=hero[3])
    ok = client.post("/actions/HERO-4:block_ip_at_firewall/approve", json={"approver": "sam"})
    assert ok.status_code == 200 and ok.json()["status"] == "simulated"
    assert client.post("/actions/HERO-4:block_ip_at_firewall/approve", json={"approver": "sam"}).status_code == 409
    assert client.post("/actions/HERO-4:isolate_host/approve", json={"approver": "sam"}).json()["status"] == "pending_confirmation"
    assert client.post("/actions/HERO-4:collect_forensics/approve", json={}).status_code == 422
    assert client.post("/actions/HERO-4:collect_forensics/reject", json={"approver": "sam", "reason": "x"}).json()["status"] == "rejected"
    assert client.post("/actions/none/approve", json={"approver": "sam"}).status_code == 404


def test_reads_feedback_audit_metrics(client, hero):
    client.post("/analyze", json=hero[0])
    assert client.get("/alerts").json()[0]["alert_id"] == "HERO-1"
    assert client.get("/alerts/HERO-1").json()["alert"]["alert_id"] == "HERO-1"
    assert client.get("/alerts/none").status_code == 404
    assert len(client.get("/similar/HERO-1").json()) == 3
    assert client.get("/similar/none").status_code == 404
    assert client.post("/feedback", json={"alert_id": "HERO-1", "correct_label": "malicious", "verdict_correct": True}).status_code == 200
    assert client.post("/feedback", json={"alert_id": "none", "correct_label": "malicious", "verdict_correct": True}).status_code == 404
    assert client.get("/audit").json()[0]["event_type"] == "feedback"
    assert client.get("/audit/verify").json()["ok"]
    assert client.get("/metrics").json()["kpis"]["alerts"] == 1


def test_replay_streams_alerts(client):
    import time

    r = client.post("/stream/replay", params={"n": 2, "interval": 0})
    assert r.status_code == 200 and "started" in r.json()
    deadline = time.time() + 15
    while time.time() < deadline and client.get("/metrics").json()["kpis"]["alerts"] < 2:
        time.sleep(0.1)
    assert client.get("/metrics").json()["kpis"]["alerts"] == 2
