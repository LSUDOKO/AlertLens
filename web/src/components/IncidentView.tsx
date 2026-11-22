"use client";
// Four linked alerts become one incident: a force-laid graph of who touched what, a timeline and likely next steps.
import { forceCenter, forceCollide, forceLink, forceManyBody, forceSimulation, type SimulationNodeDatum } from "d3-force";
import { animate, stagger } from "motion";
import { useEffect, useMemo, useRef, useState } from "react";
import { api, type Incident } from "@/lib/api";
import { SeverityBadge } from "./Analyzer";

type N = SimulationNodeDatum & { id: string; label: string; kind: string; pivot?: boolean };
const W = 720, H = 460;

export default function IncidentView() {
  const [inc, setInc] = useState<Incident | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const svg = useRef<SVGSVGElement>(null);

  async function run() {
    setBusy(true); setErr(null);
    try { const hero = await api.heroDemo(); setInc(hero.incident ?? await api.incident(hero.incident_id)); } catch (e) { setErr((e as Error).message); } finally { setBusy(false); }
  }

  const layout = useMemo(() => {
    if (!inc) return null;
    const nodes: N[] = inc.graph.nodes.map((n) => ({ ...n }));
    const links = inc.graph.edges.map((e) => ({ ...e }));
    // Run the simulation to rest up front, with a fixed seed order, so the layout is stable between renders.
    const sim = forceSimulation(nodes)
      .force("link", forceLink(links).id((d) => (d as N).id).distance(175))
      .force("charge", forceManyBody().strength(-1100))
      .force("center", forceCenter(W / 2, H / 2))
      .force("collide", forceCollide(60))
      .stop();
    for (let i = 0; i < 320; i++) sim.tick();
    nodes.forEach((n) => { n.x = Math.max(60, Math.min(W - 60, n.x ?? 0)); n.y = Math.max(40, Math.min(H - 40, n.y ?? 0)); });
    return { nodes, links: links as unknown as { source: N; target: N; action?: string }[] };
  }, [inc]);

  useEffect(() => {
    if (!layout || !svg.current || window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
    animate(svg.current.querySelectorAll(".edge"), { pathLength: [0, 1], opacity: [0, 1] }, { duration: 0.9, delay: stagger(0.05) });
    animate(svg.current.querySelectorAll(".node"), { opacity: [0, 1], scale: [0.4, 1] }, { type: "spring", stiffness: 160, damping: 14, delay: stagger(0.06, { startDelay: 0.3 }) });
  }, [layout]);

  return (
    <section className="section" id="incident" aria-labelledby="in-h">
      <div className="section-head">
        <h2 id="in-h" className="reveal">How a graph turns alerts into one story</h2>
        <p className="reveal">Each alert alone looks small. Linked by shared accounts, hosts and addresses, four alerts become one attack: stuffed passwords, a login, a new admin account and data leaving the network.</p>
      </div>
      {!inc && (
        <div className="incident-empty">
          {/* eslint-disable-next-line @next/next/no-img-element */}
          <img src="/media/folio-ibm704.webp" alt="An IBM 704 operator at the console, printed in red" loading="lazy" />
          <div>
            <p>Run the four planted alerts through the real pipeline and draw the incident they form.</p>
            <button className="btn glass" data-magnetic onClick={run} disabled={busy}>{busy ? "Linking alerts..." : "Build the incident"}</button>
            {err && <p className="error-note">{err}</p>}
          </div>
        </div>
      )}
      {inc && layout && (
        <div className="time-grid">
          <div className="alluvial-wrap">
            <p className="dlabel"><SeverityBadge label={inc.severity.label} /> {inc.graph_summary}</p>
            <svg ref={svg} viewBox={`0 0 ${W} ${H}`} className="graph" role="img" aria-label="Incident graph of accounts, hosts and addresses">
              {layout.links.map((l, i) => (
                <g key={i}>
                  <line className="edge" x1={l.source.x} y1={l.source.y} x2={l.target.x} y2={l.target.y} />
                  <text className="elabel" x={((l.source.x ?? 0) + (l.target.x ?? 0)) / 2} y={((l.source.y ?? 0) + (l.target.y ?? 0)) / 2 - 4}>{(l.action ?? "").replaceAll("_", " ")}</text>
                </g>
              ))}
              {layout.nodes.map((n) => (
                <g key={n.id} transform={`translate(${n.x},${n.y})`}>
                  {/* The inner group animates; the outer one keeps the position, so the two transforms never collide. */}
                  <g className={`node k-${n.kind}${n.pivot ? " pivot" : ""}`}>
                    <circle r={n.pivot ? 22 : 13} />
                    <text y={n.pivot ? 40 : 30} textAnchor="middle">{n.label}</text>
                  </g>
                </g>
              ))}
            </svg>
            <p className="fine">Red marks the pivot: the most connected entity, here the account the attacker took over.</p>
          </div>
          <div className="null-card">
            <p className="dlabel">Timeline</p>
            <ol className="timeline">
              {inc.timeline.map((t) => (
                <li key={t.alert_id}><span className="mono">{t.ts.slice(11, 16)}</span><span>{t.what} <span className="fine">({t.tactic})</span></span><SeverityBadge label={t.label} /></li>
              ))}
            </ol>
            <p className="dlabel" style={{ marginTop: 24 }}>Likely next</p>
            <ul className="modern-list">{inc.predicted_next.map((p) => <li key={p.tactic}><b>{p.tactic}</b>: watch for {p.watch_for}</li>)}</ul>
            <p className="fine">{inc.predicted_next[0]?.note}</p>
          </div>
        </div>
      )}
    </section>
  );
}
