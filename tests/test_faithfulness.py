"""The faithfulness evaluation's own logic."""
from eval.faithfulness import ablate, concrete


def test_ablate_removes_only_the_cited_keys():
    payload = {"alert": {"alert.user": "<USER_1>", "alert.host": "<HOST_1>"},
               "mitre": [{"id": "T1078", "name": "Valid Accounts", "description": "stolen logins"}], "context": {"incident_alerts": 4}}
    out = ablate(payload, ["alert.user", "mitre.0.description", "context.incident_alerts"])
    assert out["alert"] == {"alert.host": "<HOST_1>"}
    assert "description" not in out["mitre"][0] and out["mitre"][0]["id"] == "T1078"
    assert out["context"] == {}
    assert payload["alert"]["alert.user"] == "<USER_1>"  # the original is untouched


def test_concrete_skips_booleans_and_single_characters():
    assert concrete(True) is None and concrete("a") is None and concrete(None) is None
    assert concrete(15) == "15" and concrete("powershell") == "powershell"
