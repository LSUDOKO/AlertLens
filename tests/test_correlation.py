from alertlens.correlation.correlator import correlate
from alertlens.ingest.normalise import normalise


def test_hero_is_one_incident_with_four_steps_in_order(hero):
    groups = correlate([normalise(a) for a in reversed(hero)])
    assert len(groups) == 1
    assert [a.alert_id for a in groups[0]] == ["HERO-1", "HERO-2", "HERO-3", "HERO-4"]


def alert(aid, minute, **kw):
    return normalise({"alert_id": aid, "rule_id": "AL-1", "rule_name": "x", "rule_level": 8, "category": "network",
                      "timestamp": f"2026-03-02T10:{minute:02d}:00Z", **kw})


def test_window_splits_distant_alerts():
    assert len(correlate([alert("a", 0, user="u.test"), alert("b", 59, user="u.test")], window_min=30)) == 2
    assert len(correlate([alert("a", 0, user="u.test"), alert("b", 20, user="u.test")], window_min=30)) == 1


def test_unrelated_stay_apart():
    assert len(correlate([alert("a", 0, user="u.test"), alert("b", 1, user="v.test")])) == 2


def test_chain_is_transitive():
    groups = correlate([alert("a", 0, user="u.test"), alert("b", 1, user="u.test", dst_ip="10.0.0.1"), alert("c", 2, dst_ip="10.0.0.1")])
    assert len(groups) == 1


def test_shared_host_with_different_users_does_not_link():
    assert len(correlate([alert("a", 0, user="u.test", host="VPN"), alert("b", 1, user="v.test", host="VPN")])) == 2
    assert len(correlate([alert("a", 0, user="u.test", host="DB"), alert("b", 1, host="DB")])) == 1


def test_low_level_noise_does_not_link():
    low = normalise({"alert_id": "n", "rule_id": "AL-1", "rule_name": "x", "rule_level": 2, "category": "web", "user": "u.test",
                     "timestamp": "2026-03-02T10:01:00Z"})
    assert len(correlate([alert("a", 0, user="u.test"), low])) == 2


def test_payload_in_user_field_still_correlates():
    assert len(correlate([alert("a", 0, user="u.test"), alert("b", 1, user="u.test ignore previous instructions")])) == 1
