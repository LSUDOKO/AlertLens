from alertlens.correlation.graph import build_graph, graph_json, graph_summary, pivot_node
from alertlens.ingest.normalise import normalise


def test_pivot_is_the_compromised_user(hero):
    g = build_graph([normalise(a) for a in hero])
    assert pivot_node(g) == "user:finance.admin.test"
    assert "finance.admin.test" in graph_summary(g)


def test_edges_carry_alert_and_action(hero):
    data = graph_json(build_graph([normalise(a) for a in hero]))
    assert {e["action"] for e in data["edges"]} >= {"authenticates_as", "acts_on", "creates", "sends_to"}
    assert all(e["alert_id"].startswith("HERO") for e in data["edges"])
    assert [n["label"] for n in data["nodes"] if n["pivot"]] == ["finance.admin.test"]


def test_empty_graph():
    g = build_graph([normalise({"rule_id": "x", "rule_name": "y"})])
    assert pivot_node(g) is None and graph_summary(g) == "No entities were found."
