"""F7: the attack graph is built in code. Graph reasoning does not go through an LLM."""
from __future__ import annotations

import networkx as nx

from alertlens.ingest.adapters import vendor_extra
from alertlens.ingest.normalise import clean_identifier
from alertlens.schemas import Alert

KIND_PRIORITY = {"user": 0, "host": 1, "ip": 2, "hash": 3, "domain": 4, "process": 5, "file": 6}


def build_graph(alerts: list[Alert]) -> nx.MultiDiGraph:
    g = nx.MultiDiGraph()

    def node(kind: str, value) -> str | None:
        token = clean_identifier(value)
        if not token:
            return None
        nid = f"{kind}:{token}"
        g.add_node(nid, kind=kind, label=token)
        return nid

    def edge(a, b, alert: Alert, action: str) -> None:
        if a and b and a != b:
            g.add_edge(a, b, alert_id=alert.alert_id, action=action)

    for a in alerts:
        src, dst = node("ip", a.src_ip), node("ip", a.dst_ip)
        user, host = node("user", a.user), node("host", a.host)
        target = node("user", vendor_extra(a.raw, "target_user"))
        file_hash = node("hash", a.file_hash)
        edge(src, user or host, a, "authenticates_as" if user else "connects_to")
        edge(user, host, a, "acts_on")
        edge(user, target, a, "creates")
        edge(host or src, dst, a, "sends_to")
        edge(host, file_hash, a, "holds")
    return g


def pivot_node(g: nx.MultiDiGraph) -> str | None:
    """The most connected entity; ties prefer accounts, because accounts are what gets stolen."""
    if not g.number_of_nodes():
        return None
    centrality = nx.degree_centrality(g) if g.number_of_nodes() > 1 else dict.fromkeys(g.nodes, 1.0)
    return max(sorted(g.nodes), key=lambda n: (round(centrality[n], 6), -KIND_PRIORITY.get(g.nodes[n]["kind"], 9)))


def graph_summary(g: nx.MultiDiGraph) -> str:
    pivot = pivot_node(g)
    if pivot is None:
        return "No entities were found."
    label = g.nodes[pivot]["label"]
    return (f"{g.number_of_nodes()} entities joined by {g.number_of_edges()} actions. "
            f"The pivot is {g.nodes[pivot]['kind']} {label}, with {g.degree(pivot)} connections.")


def graph_json(g: nx.MultiDiGraph) -> dict:
    pivot = pivot_node(g)
    return {
        "nodes": [{"id": n, "label": d["label"], "kind": d["kind"], "pivot": n == pivot} for n, d in g.nodes(data=True)],
        "edges": [{"source": u, "target": v, "alert_id": d["alert_id"], "action": d["action"]}
                  for u, v, d in g.edges(data=True)],
    }
