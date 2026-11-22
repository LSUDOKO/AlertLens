"use client";
// The pipeline, step by step, with numbers read from the committed benchmark.
import { animate, inView, scroll, stagger } from "motion";
import { useEffect, useRef } from "react";
import { useApiData } from "./data";

const EASE = [0.22, 1, 0.36, 1] as const;

export default function Steps() {
  const { bench } = useApiData();
  const ref = useRef<HTMLOListElement>(null);
  const s = bench?.simulated;
  const a = bench?.adaptive;
  const items: [string, number | null, string, number][] = [
    ["Read the alert", s?.meta?.alerts ?? null, "synthetic alerts, four vendor formats", 0],
    ["Flag hidden orders", s ? s.detection.recall_known_templates * 100 : null, "% of known attack templates caught", 1],
    ["Score in code", s ? s.triage.alertlens.f1 : null, "verdict F1, with no model output read", 3],
    ["Hold the line", s ? s.invariance.labels_lowered : null, "labels a payload managed to lower", 0],
    ["Explain from facts", s ? s.grounding.alerts_with_invented_ip_caught : null, "alerts where an invented address was caught", 0],
    ["Pick safe actions", s ? s.unsafe_actions.alertlens * 100 : null, "% of actions outside the playbook", 0],
    ["Attack it again", a ? a.attempts : null, `adaptive rewrites, ${a ? a.decision_changed : "0"} changed a decision`, 0],
  ];

  useEffect(() => {
    const ol = ref.current;
    if (!ol || !bench) return;
    const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    const count = () => ol.querySelectorAll<HTMLElement>("[data-count]").forEach((el) => {
      const to = Number(el.dataset.count), d = Number(el.dataset.dec);
      if (reduce) { el.textContent = to.toFixed(d); return; }
      animate(0, to, { duration: 1.6, ease: EASE, onUpdate: (v) => { el.textContent = d ? v.toFixed(d) : Math.round(v).toLocaleString("en-GB"); } });
    });
    if (reduce) { count(); return; }
    const line = ol.querySelector(".steps-line") as SVGElement;
    line.style.transformOrigin = "0 50%";
    const stopScroll = scroll(animate(line, { scaleX: [0, 1] }, { ease: "linear" }), { target: ol, offset: ["start 85%", "end 55%"] });
    const stopView = inView(ol, () => {
      animate(ol.querySelectorAll(".step"), { opacity: [0, 1], y: [24, 0] }, { duration: 0.7, ease: EASE, delay: stagger(0.09) });
      count();
    }, { amount: 0.3 });
    return () => { stopScroll(); stopView(); };
  }, [bench]);

  return (
    <section className="pipeline section" id="how" aria-labelledby="how-h">
      <div className="section-head">
        <h2 id="how-h" className="reveal">From a raw alert to a safe answer</h2>
        <p className="reveal">Seven steps. Every number is read from the committed benchmark, run with a simulated worst-case model.</p>
      </div>
      <ol className="steps" ref={ref}>
        <svg className="steps-line" aria-hidden="true" preserveAspectRatio="none" viewBox="0 0 100 2"><line x1="0" y1="1" x2="100" y2="1" /></svg>
        {items.map(([title, n, label, dec]) => (
          <li className="step" key={title}>
            <strong data-count={n ?? 0} data-dec={dec}>{n === null ? "..." : "0"}</strong>
            <h3>{title}</h3>
            <span>{label}</span>
          </li>
        ))}
      </ol>
    </section>
  );
}
