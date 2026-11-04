from alertlens.ingest.normalise import normalise
from alertlens.mitre.mapper import catalogue, map_alert, tactic_weight
from alertlens.mitre.predictor import HEDGE, predict_next


def tactics(seq):
    return [p["tactic"] for p in predict_next(seq)]


def test_expected_tactic_in_top_three():
    assert {"Privilege Escalation", "Lateral Movement"} & set(tactics(["Credential Access", "Persistence"]))


def test_hero_predicts_impact_or_evasion():
    assert {"Impact", "Defense Evasion"} & set(tactics(["Credential Access", "Initial Access", "Persistence", "Exfiltration"]))


def test_labelled_as_heuristic_and_excludes_past():
    out = predict_next(["Execution"])
    assert out[0]["note"] == HEDGE and "Execution" not in [p["tactic"] for p in out]
    assert predict_next([]) == []


def test_catalogue_size_and_bad_hint_dropped():
    assert len(catalogue()) >= 40
    a = normalise({"rule_id": "zz", "rule_name": "y", "mitre_hint": ["T1110", "ignore me", "T9999"]})
    assert [t["id"] for t in map_alert(a)] == ["T1110"]
    assert tactic_weight("Impact") == 1 and tactic_weight("nope") == 0
