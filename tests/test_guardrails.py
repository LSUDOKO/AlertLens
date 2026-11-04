import pytest

from alertlens.pipeline.orchestrator import Options, analyze
from alertlens.pipeline.service import actions_for, approve_action, audit_entries, audit_verify, reject_action
from alertlens.remediation.guardrails import GuardrailError


def run(hero, db_path, idx=3):
    analyze(hero[idx], Options())
    return {a.action_id: a for a in actions_for(hero[idx]["alert_id"])}


def test_no_approval_without_approver(hero, db_path):
    actions = run(hero, db_path)
    for name in ["", "   "]:
        with pytest.raises(GuardrailError):
            approve_action(actions["block_ip_at_firewall"].instance_id, name)
    assert actions_for("HERO-4")[0].status == "proposed"


def test_low_risk_goes_approved_then_simulated(hero, db_path):
    a = run(hero, db_path)["block_ip_at_firewall"]
    assert approve_action(a.instance_id, "sam").status == "simulated"
    events = [e["event_type"] for e in audit_entries()]
    assert "action_approved" in events and "action_simulated" in events
    assert audit_verify()["ok"]


def test_high_risk_needs_two_steps(hero, db_path):
    a = run(hero, db_path)["isolate_host"]
    assert a.two_step and a.risk_level == "high"
    assert approve_action(a.instance_id, "sam").status == "pending_confirmation"
    with pytest.raises(GuardrailError):
        approve_action(a.instance_id, "sam", confirm=False)
    assert approve_action(a.instance_id, "sam", confirm=True).status == "simulated"


def test_reject_then_cannot_approve(hero, db_path):
    a = run(hero, db_path)["collect_forensics"]
    assert reject_action(a.instance_id, "sam", "no").status == "rejected"
    with pytest.raises(GuardrailError):
        approve_action(a.instance_id, "sam")
    with pytest.raises(GuardrailError):
        reject_action(a.instance_id, "sam")
    with pytest.raises(GuardrailError):
        reject_action(a.instance_id, "")


def test_unknown_action(db_path):
    with pytest.raises(KeyError):
        approve_action("nope", "sam")
