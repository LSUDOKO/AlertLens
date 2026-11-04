"""F24: incident reports. Markdown and HTML in English or Hindi, PDF in English."""
from __future__ import annotations

import base64
import html as html_mod
import io
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import networkx as nx  # noqa: E402
from fpdf import FPDF  # noqa: E402
from jinja2 import Environment, FileSystemLoader, select_autoescape  # noqa: E402

from alertlens.audit.chain import verify_chain  # noqa: E402
from alertlens.memory import store as db  # noqa: E402
from alertlens.remediation.guardrails import GuardrailError  # noqa: E402

TEMPLATES = Path(__file__).parent / "templates"
_env = Environment(loader=FileSystemLoader(TEMPLATES), autoescape=select_autoescape(["html"]))
HI = {"title": "घटना रिपोर्ट", "summary": "सारांश", "severity": "गंभीरता", "timeline": "समयरेखा", "graph": "हमले का ग्राफ़",
      "next": "संभावित अगले कदम", "explain": "स्पष्टीकरण", "actions": "कार्रवाइयाँ", "audit": "ऑडिट अंश", "pivot": "मुख्य केंद्र",
      "note": "अगले कदम अनुमान हैं, निश्चितता नहीं। सभी डेटा कृत्रिम है।", "time": "समय", "what": "नियम", "tactic": "चरण", "status": "स्थिति"}
EN = {"title": "Incident report", "summary": "Summary", "severity": "Severity", "timeline": "Timeline", "graph": "Attack graph",
      "next": "Likely next steps", "explain": "Explanation", "actions": "Actions", "audit": "Audit excerpt", "pivot": "Pivot",
      "note": "Next steps are a heuristic, not a certainty. All data is synthetic.", "time": "Time", "what": "What", "tactic": "Stage", "status": "Status"}


def graph_png(graph: dict) -> bytes:
    g = nx.MultiDiGraph()
    for node in graph.get("nodes", []):
        g.add_node(node["id"], label=node["label"], pivot=node["pivot"])
    for edge in graph.get("edges", []):
        g.add_edge(edge["source"], edge["target"])
    fig, ax = plt.subplots(figsize=(7, 4))
    if g.number_of_nodes():
        pos = nx.spring_layout(nx.Graph(g), seed=7)
        colors = ["#D7263D" if g.nodes[n]["pivot"] else "#3A7CA5" for n in g.nodes]
        nx.draw_networkx(g, pos, ax=ax, node_color=colors, node_size=500, font_size=7, edge_color="#888888",
                         labels={n: g.nodes[n]["label"] for n in g.nodes}, connectionstyle="arc3,rad=0.1", arrows=True)
    ax.set_axis_off()
    fig.tight_layout()
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=120)
    plt.close(fig)
    return buf.getvalue()


def collect(incident_id: str, lang: str, db_path: str | None = None) -> dict:
    with db.db(db_path) as conn:
        incident = db.get_incident(conn, incident_id)
        if incident is None:
            raise KeyError(incident_id)
        analyses = [a for a in (db.get_analysis(conn, i) for i in incident["alert_ids"]) if a]
        placeholders = ",".join("?" * len(incident["alert_ids"]))
        rows = conn.execute(f"SELECT body FROM actions WHERE alert_id IN ({placeholders})", incident["alert_ids"]).fetchall()
        audit = conn.execute("SELECT seq, ts, actor, event_type FROM audit_log ORDER BY seq DESC LIMIT 8").fetchall()
        chain_state = verify_chain(conn)
    import json

    views = []
    for a in analyses:
        view = a["renderings"].get("analyst", {}).get(lang) or a["renderings"].get("analyst", {}).get("en") or {}
        views.append({"alert_id": a["alert"]["alert_id"], "headline": view.get("headline", ""),
                      "what": view.get("what_happened", ""), "why": f"{view.get('why_it_matters', '')} {view.get('next', '')}",
                      "grounding": a["explanation"]["grounding_score"]})
    return {"t": HI if lang == "hi" else EN, "lang": lang, "i": incident, "views": views, "actions": [json.loads(r[0]) for r in rows],
            "audit": [{"seq": r[0], "ts": r[1], "actor": r[2], "event": r[3]} for r in audit], "chain": chain_state}


def _latin1(text) -> str:
    """fpdf2's core fonts are latin-1 only."""
    swaps = {"—": "-", "–": "-", "→": "->", "…": "...", "“": '"', "”": '"', "‘": "'", "’": "'"}
    out = str(text)
    for a, b in swaps.items():
        out = out.replace(a, b)
    return out.encode("latin-1", "replace").decode("latin-1")


def render_pdf(ctx: dict) -> bytes:
    i, t = ctx["i"], ctx["t"]
    pdf = FPDF()
    pdf.set_auto_page_break(True, 15)
    pdf.add_page()

    def heading(text, size=13):
        pdf.set_font("Helvetica", "B", size)
        pdf.multi_cell(0, 8, _latin1(text), new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 10)

    def para(text):
        pdf.multi_cell(0, 5.5, _latin1(text), new_x="LMARGIN", new_y="NEXT")

    heading(f"{t['title']}: {i['incident_id']}", 16)
    para(f"{t['severity']}: {i['severity']['label']} ({i['severity']['score']}). {i['graph_summary']}")
    heading(t["timeline"])
    for row in i["timeline"]:
        para(f"{row['ts'][:19]}  {row['what']}  [{row['tactic']}]  {row['label']}")
    heading(t["graph"])
    pdf.image(io.BytesIO(graph_png(i["graph"])), w=170)
    heading(t["next"])
    for row in i["predicted_next"]:
        para(f"{row['tactic']}: watch for {row['watch_for']}")
    para(t["note"])
    heading(t["explain"])
    for v in ctx["views"]:
        para(f"{v['alert_id']}: {v['what']} {v['why']} Grounding {v['grounding']}.")
    heading(t["actions"])
    for a in ctx["actions"]:
        para(f"[{a['status']}] {a['title']}. Dry run: {a['dry_run_preview']} Rollback: {a['rollback']}")
    heading(t["audit"])
    para(f"Chain check: {'intact' if ctx['chain']['ok'] else 'BROKEN at record ' + str(ctx['chain']['first_broken_seq'])}.")
    for row in ctx["audit"]:
        para(f"#{row['seq']} {row['ts'][:19]} {row['actor']} {row['event']}")
    return bytes(pdf.output())


def build_report(incident_id: str, fmt: str, lang: str = "en", db_path: str | None = None) -> tuple[bytes, str, str]:
    """Return (bytes, media type, filename). Hindi PDF is refused because the bundled PDF fonts lack Devanagari."""
    if fmt == "pdf" and lang == "hi":
        raise GuardrailError("Hindi reports are available as HTML. PDF is English only.")
    ctx = collect(incident_id, lang, db_path)
    name = f"{incident_id}_{lang}.{fmt}"
    if fmt == "pdf":
        return render_pdf(ctx), "application/pdf", name
    if fmt == "html":
        img = base64.b64encode(graph_png(ctx["i"]["graph"])).decode()
        return _env.get_template("report.html.j2").render(**ctx, graph_b64=img).encode(), "text/html; charset=utf-8", name
    return _env.get_template("report.md.j2").render(**ctx).encode(), "text/markdown; charset=utf-8", name


__all__ = ["build_report", "collect", "graph_png", "html_mod"]
