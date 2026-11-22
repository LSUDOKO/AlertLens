"use client";
// The analyzer: pick a sample or paste an alert, and read everything AlertLens decided and why.
import { useEffect, useMemo, useState } from "react";
import { api, type AnalysisResult, type Sample } from "@/lib/api";
import { useApiData } from "./data";

type Rendering = { headline: string; what_happened: string; why_it_matters: string; next: string; claims: { text: string; status: string; evidence: string[] }[] };
const AUDIENCES = [["analyst", "Analyst"], ["manager", "Manager"], ["employee", "Employee"]] as const;
const SOURCE_TONE: Record<string, string> = { sensor: "pos", code: "pos", "rule catalogue": "pos", "ATT&CK catalogue": "pos", model: "neg", "code, model overruled": "neg" };

function sampleTitle(s: Sample) {
  // Vendor formats name the rule in different places; fall back to the file name.
  const a = s.alert as Record<string, unknown>;
  const pick = (v: unknown): string | null => (typeof v === "string" && v ? v : v && typeof v === "object" ? pick((v as Record<string, unknown>).title ?? (v as Record<string, unknown>).description ?? (v as Record<string, unknown>).signature) : null);
  return pick(a.rule_name) ?? pick(a.rule) ?? pick(a.alert) ?? pick(a.sigma_rule) ?? pick(a.title) ?? s.name.replace(/^.*\//, "").replace(".json", "");
}

export function SeverityBadge({ label }: { label: string }) {
  return <span className={`sev sev-${label}`}>{label}</span>;
}

export default function Analyzer() {
  const { health } = useApiData();
  const [samples, setSamples] = useState<Sample[]>([]);
  const [picked, setPicked] = useState<string>("");
  const [paste, setPaste] = useState("");
  const [mode, setMode] = useState<"sample" | "paste">("sample");
  const [audience, setAudience] = useState<"analyst" | "manager" | "employee">("analyst");
  const [lang, setLang] = useState<"en" | "hi">("en");
  const [deep, setDeep] = useState(false);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    if (!health) return;
    api.samples().then((s) => {
      const first = s.find((x) => x.name.endsWith("hero-2.json")) ?? s[0];
      setSamples(s);
      if (first) { setPicked(first.name); void run(first.alert, false); }
    }).catch((e) => setErr(e.message));
  }, [health]); // eslint-disable-line react-hooks/exhaustive-deps

  async function run(alert?: unknown, deepPath = deep) {
    setErr(null);
    let body = alert;
    if (body === undefined) {
      if (mode === "paste") {
        try { body = JSON.parse(paste); } catch (e) { setErr(`That is not valid JSON: ${(e as Error).message}`); return; }
      } else {
        body = samples.find((s) => s.name === picked)?.alert;
      }
    }
    if (!body) return;
    setBusy(true);
    try { setResult(await api.analyze(body, { audience, lang, deep: deepPath })); } catch (e) { setErr((e as Error).message); } finally { setBusy(false); }
  }


  const view: Rendering | null = useMemo(() => {
    if (!result) return null;
    const r = result.renderings as Record<string, Record<string, Rendering>>;
    return r?.[audience]?.[lang] ?? r?.[audience]?.en ?? null;
  }, [result, audience, lang]);

  return (
    <section className="explorer section" id="analyze" aria-labelledby="an-h">
      <div className="section-head">
        <h2 id="an-h" className="reveal">Alert analyzer</h2>
        <p className="reveal">Pick a sample or paste your own alert in Wazuh, Suricata, Sigma or native JSON. The preselected login hides an instruction in its user agent.</p>
      </div>
      <div className="ex-grid">
        <aside className="ex-side">
          <div className="filters" role="group" aria-label="Alert source">
            <button className={`chip${mode === "sample" ? " on" : ""}`} onClick={() => setMode("sample")}>Samples</button>
            <button className={`chip${mode === "paste" ? " on" : ""}`} onClick={() => setMode("paste")}>Paste JSON</button>
          </div>
          {mode === "sample" ? (
            <ul className="name-list" role="listbox" aria-label="Sample alerts">
              {samples.length === 0 && <li className="list-skel" aria-hidden="true" />}
              {samples.map((s) => (
                <li key={s.name}>
                  <button role="option" aria-selected={picked === s.name} onClick={() => { setPicked(s.name); void run(s.alert); }}>
                    <span className="g">{sampleTitle(s)}</span>
                    <span className="t">{s.name.replace(".json", "")}</span>
                    <span className="p">{s.name.startsWith("hero") ? "story" : String((s.alert as { source_format?: string }).source_format ?? "json")}</span>
                  </button>
                </li>
              ))}
            </ul>
          ) : (
            <div className="paste">
              <label htmlFor="paste-json" className="dlabel">Alert JSON</label>
              <textarea id="paste-json" value={paste} onChange={(e) => setPaste(e.target.value)} rows={12} spellCheck={false}
                placeholder='{"rule_id": "AL-1001", "rule_name": "Multiple failed logins", ...}' />
              <button className="btn glass small" disabled={busy || !paste.trim()} onClick={() => run()}>Analyze alert</button>
            </div>
          )}
          <div className="opts">
            <div className="filters" role="group" aria-label="Reader">
              {AUDIENCES.map(([k, l]) => <button key={k} className={`chip${audience === k ? " on" : ""}`} onClick={() => setAudience(k)}>{l}</button>)}
            </div>
            <div className="filters" role="group" aria-label="Language">
              <button className={`chip${lang === "en" ? " on" : ""}`} onClick={() => setLang("en")}>English</button>
              <button className={`chip${lang === "hi" ? " on" : ""}`} onClick={() => setLang("hi")} lang="hi">हिन्दी</button>
            </div>
            <label className="toggle"><input type="checkbox" checked={deep} onChange={(e) => {
              setDeep(e.target.checked);
              if (mode === "sample") void run(samples.find((x) => x.name === picked)?.alert, e.target.checked);
            }} /> Force the model path</label>
          </div>
        </aside>

        <div className="ex-detail" aria-live="polite" aria-busy={busy}>
          {err && <p className="error-note">{err}</p>}
          {!result && !err && <div className="detail-skel" aria-hidden="true"><span /><span /><span /><span /></div>}
          {result && view && <Detail r={result} view={view} audience={audience} busy={busy} publicDemo={Boolean(health?.public_demo)} />}
        </div>
      </div>
    </section>
  );
}

function Detail({ r, view, audience, busy, publicDemo }: { r: AnalysisResult; view: Rendering; audience: string; busy: boolean; publicDemo: boolean }) {
  const sev = r.severity;
  const findings = r.sanitise.findings ?? [];
  const prov = (r.provenance ?? {}) as Record<string, string>;
  return (
    <div className={busy ? "dim-out" : undefined}>
      <div className="dh">
        <h3>{view.headline}</h3>
        <span className="meta">{r.alert.alert_id} · {r.alert.source_format} · route {r.route}</span>
      </div>
      {r.sanitise.quarantined_fields.length > 0 && (
        <div className="quarantine" role="alert">
          <p className="q-title">Hidden instructions found and not followed</p>
          {findings.slice(0, 5).map((f, i) => (
            <p key={i} className="q-row"><b>{f.field_path}</b> {f.pattern_family.replaceAll("_", " ")}<s>{f.matched_text_preview}</s></p>
          ))}
        </div>
      )}
      <div className="dgrid">
        <div>
          <p className="dlabel">What happened, for the {audience}</p>
          <p className="passage">{view.what_happened}</p>
          <p className="passage">{view.why_it_matters}</p>
          <p className="next-step"><b>Next:</b> {view.next}</p>
          {audience === "analyst" && (
            <>
              <p className="dlabel" style={{ marginTop: 24 }}>Claims, each checked against the alert</p>
              <ul className="claims">
                {r.explanation.claims.map((c, i) => (
                  <li key={i} className={`claim ${c.status}`}>
                    <span className="cstat">{c.status === "verified" ? "verified" : "partly verified"}</span>
                    <span>{c.text}</span>
                    <span className="contrib">
                      {c.evidence.map((k) => <span key={k} className={SOURCE_TONE[prov[k]] ?? ""} title={`Source: ${prov[k] ?? "unknown"}`}>{k} · {prov[k] ?? "?"}</span>)}
                    </span>
                  </li>
                ))}
              </ul>
              {r.explanation.removed_claims.length > 0 && (
                <details className="removed">
                  <summary>{r.explanation.removed_claims.length} claim(s) removed by the checks</summary>
                  {r.explanation.removed_claims.map((c, i) => <p key={i}><s>{c.text}</s> <span className="fine">{c.reason}</span></p>)}
                </details>
              )}
            </>
          )}
        </div>
        <div>
          <p className="dlabel">How serious is it? <span className="code-tag">Decided by code, not AI</span></p>
          <div className="sev-head"><SeverityBadge label={sev.label} /><b>{sev.score}</b><span className="fine">/ 100 · {sev.triage.replaceAll("_", " ")}</span></div>
          <div className="pbar"><span className="name none">Probability malicious</span><span className="track"><span className="fill" style={{ transform: `scaleX(${sev.p_malicious})` }} /></span><span className="val">{sev.p_malicious.toFixed(2)}</span></div>
          <div className="pbar"><span className="name none">Confidence</span><span className="track"><span className="fill" style={{ transform: `scaleX(${sev.confidence})` }} /></span><span className="val">{sev.confidence.toFixed(2)}</span></div>
          <ul className="reasons">{sev.reasons.map((x, i) => <li key={i}>{x}</li>)}</ul>
          {sev.counterfactuals.length > 0 && <p className="fine">{sev.counterfactuals[0]}</p>}
          <p className="dlabel" style={{ marginTop: 20 }}>ATT&amp;CK</p>
          <div className="tags">{(r.mitre as Record<string, string>[]).map((t) => <span key={t.id} className="tag" title={t.short_description}>{t.id} {t.name}</span>)}</div>
          <p className="dlabel" style={{ marginTop: 20 }}>Actions from the fixed playbook</p>
          <ul className="actions">
            {r.actions.map((a) => (
              <li key={a.action_id}><b>{a.title}</b><span className="fine"> risk {a.risk_level} · {a.status}</span>
                <details><summary>Dry run and rollback</summary><p className="fine">{a.dry_run_preview}</p><p className="fine">Rollback: {a.rollback}</p></details>
              </li>
            ))}
          </ul>
          <p className="fine">{publicDemo ? "Approving is turned off on this public demo. Run AlertLens locally to approve or reject." : "Approve or reject in the local app. Every action is simulated."}</p>
        </div>
      </div>
      <ModelTrace r={r} />
    </div>
  );
}

function ModelTrace({ r }: { r: AnalysisResult }) {
  const trace = (r.model_trace ?? []) as { stage: string; provider: string; model: string; latency_ms: number; tokens: number | null; reply: string; error: string | null }[];
  const ledger = (r.agent_transcript ?? []) as { agent: string; verdict: string; reasons: string[]; evidence?: string[]; unknown_evidence?: string[] }[];
  return (
    <div className="eras">
      <p className="dlabel">What the model tried</p>
      {trace.length === 0 ? (
        <p className="fine">This alert took the fast path, so no model was called. Tick &ldquo;Force the model path&rdquo; to see the model at work.</p>
      ) : (
        <>
          <table>
            <thead><tr><th>Agent</th><th>Verdict</th><th>Evidence it cited</th></tr></thead>
            <tbody>
              {ledger.map((t, i) => (
                <tr key={i}><td>{t.agent}</td><td>{t.verdict}</td><td className="fine">{(t.evidence ?? []).join(", ") || "none"}{t.unknown_evidence?.length ? ` (ignored: ${t.unknown_evidence.join(", ")})` : ""}</td></tr>
              ))}
            </tbody>
          </table>
          <details className="trace">
            <summary>{trace.length} raw model replies from {trace[0].provider}, model {trace[0].model || "unnamed"}</summary>
            {trace.map((t, i) => (
              <div key={i}><p className="fine"><b>{t.stage}</b> · {t.latency_ms} ms</p><pre>{t.error ? `Call failed: ${t.error}` : t.reply}</pre></div>
            ))}
          </details>
        </>
      )}
    </div>
  );
}
