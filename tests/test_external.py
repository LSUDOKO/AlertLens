"""The external published-attack evaluation's own logic."""
from data.generator.injections import PAYLOADS
from eval.external import target_field, training_overlap


def test_field_hints_map_to_alert_fields():
    assert target_field("injection_vector: user_agent") == "user_agent"
    assert target_field("injection_vector: ssh_username") == "user"
    assert target_field("command-line tag ('-TAG=<string>')") == "command_line"
    assert target_field(None) == "user_agent"


def test_training_overlap_finds_a_training_payload_and_ignores_new_text():
    known = next(p for fam in PAYLOADS.values() for p in fam if len(p) >= 40)
    assert training_overlap([{"text": known}]) == 1
    assert training_overlap([{"text": "zq vexillology parsnip quadrature onboarding marmalade tessellation"}]) == 0
