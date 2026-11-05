"""Shared UI helpers. Pages call the pipeline in-process, so the demo has no port to fail on.

Every alert-derived value goes through `esc` before `unsafe_allow_html`, because alert text is attacker text.
"""
from __future__ import annotations

import html

import plotly.graph_objects as go
import streamlit as st

from alertlens.config import ROOT, get_settings
from alertlens.memory import store as db
from alertlens.pipeline import service
from alertlens.remediation.guardrails import GuardrailError
from data.generator.generate import write_benchmark
from scripts.seed_db import ensure_seeded

SEVERITY = {"low": "#9AA0B5", "medium": "#E8B23A", "high": "#F0883E", "critical": "#F2545B"}
TRIAGE = {"auto_close_candidate": "Could be closed, after a person checks", "needs_human": "Needs a person",
          "escalate": "Escalate now"}
CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Archivo:wdth,wght@112,600;112,800&family=Atkinson+Hyperlegible:wght@400;700&family=Noto+Sans+Devanagari:wght@400;600&display=swap');
html, body, p, li, label, input, textarea, button { font-family: 'Atkinson Hyperlegible','Noto Sans Devanagari',system-ui,sans-serif; }
h1, h2, h3 { font-family: 'Archivo','Noto Sans Devanagari',system-ui,sans-serif !important; font-stretch: 112%; letter-spacing: -.01em; }
h1 { font-weight: 800 !important; }
.al-sev { display:inline-block; padding:.1rem .6rem; border-radius:3px; font-weight:700; color:#171A2B; }
.al-quarantine { margin:.25rem 0 1rem; padding:.9rem 1rem; color:#ECE9F5; border-left:4px solid #F2545B;
  background:repeating-linear-gradient(135deg,#2E2436 0 10px,#26223A 10px 20px); }
.al-quarantine h4 { margin:0 0 .35rem; color:#FFB3B6; font-size:1.05rem; }
.al-inert { display:block; margin-top:.3rem; color:#A9ACC6; text-decoration:line-through; overflow-wrap:anywhere; }
.al-claim { padding:.35rem 0; border-bottom:1px solid #2F3450; }
.al-ev { color:#A9ACC6; font-size:.85rem; display:block; }
.al-code { color:#A9B8FF; font-weight:700; }
.al-removed { color:#FFB3B6; }
</style>
"""


def setup(title: str) -> None:
    st.set_page_config(page_title=f"{title}: AlertLens", layout="wide")
    st.markdown(CSS, unsafe_allow_html=True)
    if "seeded" not in st.session_state:
        ensure_seeded()
        if not (ROOT / "data" / "benchmark" / "alerts.jsonl").exists():  # a fresh clone on a hosted demo
            write_benchmark(get_settings().seed, 2000, ROOT / "data" / "benchmark")
        st.session_state["seeded"] = True


def esc(value) -> str:
    return html.escape(str(value), quote=True)


def sev_badge(label: str) -> str:
    return f'<span class="al-sev" style="background:{SEVERITY.get(label, "#9AA0B5")}">{esc(label)}</span>'


def show_kpis() -> None:
    with db.db() as conn:
        k = db.kpis(conn)
    a, b, c, d = st.columns(4)
    a.metric("Alerts analysed", k["alerts"])
    b.metric("Incidents", k["incidents"])
    c.metric("Injections caught", k["injections"])
    d.metric("Handled without an LLM", f"{k['fast_path_pct']}%")


def gauge(score: float, label: str) -> go.Figure:
    fig = go.Figure(go.Indicator(
        mode="gauge+number", value=score, number={"font": {"size": 24}},
        gauge={"axis": {"range": [0, 100]}, "bar": {"color": SEVERITY[label]}, "bgcolor": "#22263D",
               "steps": [{"range": [0, 30], "color": "#262A42"}, {"range": [30, 55], "color": "#2A2D45"},
                         {"range": [55, 78], "color": "#2F3049"}, {"range": [78, 100], "color": "#35304A"}]},
    ))
    fig.update_layout(height=190, margin=dict(l=36, r=36, t=24, b=0), paper_bgcolor="rgba(0,0,0,0)", font_color="#ECE9F5")
    return fig


def injection_banner(sanitise: dict) -> None:
    if not sanitise["quarantined_fields"]:
        return
    rows = "".join(
        f'<div><b>{esc(f["field_path"])}</b>: {esc(f["pattern_family"].replace("_", " "))}'
        f'<span class="al-inert">{esc(f["matched_text_preview"])}</span></div>'
        for f in sanitise["findings"][:6]
    )
    st.markdown(f'<div class="al-quarantine" role="alert"><h4>Injection attempt detected and not followed</h4>{rows}</div>',
                unsafe_allow_html=True)


def severity_card(sev: dict) -> None:
    left, right = st.columns([1, 2])
    with left:
        st.plotly_chart(gauge(sev["score"], sev["label"]), width="stretch", key=f"g{id(sev)}")
    with right:
        st.markdown(f'{sev_badge(sev["label"])} &nbsp; <span class="al-code">Decided by code, not AI</span>', unsafe_allow_html=True)
        st.write(f"**{TRIAGE[sev['triage']]}.** Probability malicious {sev['p_malicious']:.2f}, confidence {sev['confidence']:.2f}.")
        for reason in sev["reasons"]:
            st.markdown(f"- {esc(reason)}", unsafe_allow_html=True)
        for cf in sev.get("counterfactuals", []):
            st.caption(cf)


def explanation_block(result: dict, key: str) -> None:
    exp = result["explanation"]
    lang = st.radio("Language", ["English", "हिन्दी"], horizontal=True, key=f"lang_{key}")
    code = "hi" if lang != "English" else "en"
    tabs = st.tabs(["Analyst", "Manager", "Employee"])
    for tab, audience in zip(tabs, ["analyst", "manager", "employee"], strict=True):
        view = result["renderings"].get(audience, {}).get(code) or result["renderings"][audience]["en"]
        with tab:
            st.markdown(f"**{esc(view['headline'])}**", unsafe_allow_html=True)
            st.markdown(f"{esc(view['what_happened'])}", unsafe_allow_html=True)
            st.markdown(f"{esc(view['why_it_matters'])}", unsafe_allow_html=True)
            st.markdown(f"**{esc(view['next'])}**", unsafe_allow_html=True)
            if audience == "analyst":
                for claim in view["claims"]:
                    mark = "✅" if claim["status"] == "verified" else "⚠️"
                    st.markdown(f'<div class="al-claim">{mark} {esc(claim["text"])}'
                                f'<span class="al-ev">Evidence: {esc(", ".join(claim["evidence"]))}</span></div>',
                                unsafe_allow_html=True)
    st.metric("Grounding score", f"{exp['grounding_score']:.2f}", help="Verified claims divided by all claims")
    if exp["safe_fallback"]:
        st.warning("Safe fallback used: model output was rejected, so this text came from a template. "
                   f"Reason: {'; '.join(exp['fallback_reasons'])[:200]}")
    if exp["removed_claims"]:
        with st.expander(f"Removed claims ({len(exp['removed_claims'])})"):
            for claim in exp["removed_claims"]:
                st.markdown(f'<div class="al-removed">{esc(claim["text"])}<span class="al-ev">{esc(claim["reason"])}</span></div>',
                            unsafe_allow_html=True)


def actions_block(alert_id: str, key: str) -> None:
    actions = service.actions_for(alert_id)
    if not actions:
        st.info("No action fits this alert at this severity.")
        return
    approver = st.text_input("Your name, recorded with each decision", key=f"approver_{key}")
    st.caption("Every action is a simulation. Nothing here touches a real system.")
    for action in actions:
        with st.container(border=True):
            st.markdown(f"**{esc(action.title)}**  \nRisk {action.risk_level}, status **{action.status}**. {esc(action.reason)}",
                        unsafe_allow_html=True)
            with st.expander("Dry run and rollback"):
                st.write(action.dry_run_preview)
                st.caption(f"Rollback: {action.rollback}")
            if action.status in {"proposed", "pending_confirmation"}:
                needs_confirm = action.status == "pending_confirmation"
                a, b = st.columns(2)
                label = "Confirm approval" if needs_confirm else "Approve"
                try:
                    if a.button(label, key=f"ok_{key}_{action.action_id}"):
                        service.approve_action(action.instance_id, approver, confirm=needs_confirm)
                        st.rerun()
                    if b.button("Reject", key=f"no_{key}_{action.action_id}"):
                        service.reject_action(action.instance_id, approver)
                        st.rerun()
                except GuardrailError as exc:
                    st.error(str(exc))


def graph_figure(graph: dict) -> go.Figure:
    import networkx as nx

    g = nx.Graph()
    g.add_nodes_from(n["id"] for n in graph["nodes"])
    g.add_edges_from((e["source"], e["target"]) for e in graph["edges"])
    pos = nx.spring_layout(g, seed=7)
    xs, ys = [], []
    for e in graph["edges"]:
        xs += [pos[e["source"]][0], pos[e["target"]][0], None]
        ys += [pos[e["source"]][1], pos[e["target"]][1], None]
    colour = {"user": "#A9B8FF", "host": "#7FC8D8", "ip": "#C7B6F2", "hash": "#E8B23A", "domain": "#9AA0B5"}
    nodes = graph["nodes"]
    fig = go.Figure([
        go.Scatter(x=xs, y=ys, mode="lines", line=dict(color="#4A4F70", width=1), hoverinfo="skip"),
        go.Scatter(x=[pos[n["id"]][0] for n in nodes], y=[pos[n["id"]][1] for n in nodes], mode="markers+text",
                   text=[n["label"] for n in nodes], textposition="top center", hovertext=[f'{n["kind"]}: {n["label"]}' for n in nodes],
                   hoverinfo="text",
                   marker=dict(size=[30 if n["pivot"] else 16 for n in nodes],
                               color=["#F2545B" if n["pivot"] else colour.get(n["kind"], "#9AA0B5") for n in nodes])),
    ])
    fig.update_layout(height=420, showlegend=False, margin=dict(l=10, r=10, t=10, b=10), paper_bgcolor="rgba(0,0,0,0)",
                      plot_bgcolor="rgba(0,0,0,0)", font_color="#ECE9F5",
                      xaxis=dict(visible=False, range=[min(p[0] for p in pos.values()) - 0.4, max(p[0] for p in pos.values()) + 0.4]),
                      yaxis=dict(visible=False, range=[min(p[1] for p in pos.values()) - 0.2, max(p[1] for p in pos.values()) + 0.3]))
    return fig


def model_trace_block(result: dict) -> None:
    """Raw model replies beside what code did with them. Everything is plain text: model output is attacker-shaped."""
    trace = result.get("model_trace") or []
    if not trace:
        st.caption("This alert took the fast path, so no model was called.")
        return
    changes = []
    for ev in result["security_events"]:
        if ev["type"] == "fact_conflict":
            changes.append(f"Code overruled the model's facts: {', '.join(ev['fields'])}")
        elif ev["type"] == "unsafe_action_blocked":
            changes.append(f"Blocked actions outside the playbook: {', '.join(ev['ids'])}")
        elif ev["type"] == "critic_objection":
            changes.append(f"The critic objected, so confidence fell to {ev['confidence']} and a person must review")
        elif ev["type"] == "prompt_leak":
            changes.append(f"Canary token leaked at {ev['stage']}, so that output was discarded")
        elif ev["type"] == "state_tamper":
            changes.append(f"Model text tried to change the outcome: {ev['phrase']}")
    exp = result["explanation"]
    changes += [f"Removed claim: {c['text']} ({c['reason']})" for c in exp["removed_claims"]]
    changes += [f"Template text used: {reason}" for reason in exp["fallback_reasons"]]
    st.markdown("**What code changed**")
    st.text("\n".join(changes) or "Nothing. The model's output passed every check.")
    for n, call in enumerate(trace, 1):
        st.markdown(f"**Call {n}: {esc(call['stage'])}**")
        st.caption(f"{call['provider']}, model {call['model'] or 'unnamed'}, {call['latency_ms']} ms, {call['tokens'] or 'unknown'} tokens")
        if call["error"]:
            st.text(f"Call failed: {call['error']}")
        else:
            st.code(call["reply"], language=None, wrap_lines=True)


def debate_block(transcript: list[dict]) -> None:
    if not transcript:
        st.caption("The agents run on the LLM path. This alert took the fast path.")
        return
    for turn in transcript:
        st.markdown(f"**{esc(turn['agent'])}**: {esc(turn['verdict'])}. {esc('; '.join(turn['reasons']))}", unsafe_allow_html=True)
