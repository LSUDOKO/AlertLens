"use client";
// Every measured result, read from the committed files, each labelled with what it does and does not show.
import { pct } from "@/lib/api";
import { useApiData } from "./data";

function Meter({ label, value, text, hatched }: { label: string; value: number; text: string; hatched?: boolean }) {
  return (
    <div className={`nb${hatched ? " null" : ""}`}>
      <div className="lbl"><span>{label}</span><b>{text}</b></div>
      <div className="tr"><div className="fl" style={{ transform: `scaleX(${Math.max(0, Math.min(1, value))})` }} /></div>
    </div>
  );
}

export default function Results() {
  const { bench, error, waking } = useApiData();
  if (!bench) {
    return (
      <section className="section" id="results">
        <div className="section-head"><h2>Measured, not claimed</h2><p>{waking ? "Waking the API to read the results..." : error}</p></div>
      </section>
    );
  }
  const s = bench.simulated, real = bench.real, ad = bench.adaptive, fv = bench.faithfulness_verifier, fm = bench.faithfulness_model, ext = bench.external;
  const n = real?.meta?.injected_malicious ?? 0;
  return (
    <section className="section" id="results" aria-labelledby="res-h">
      <div className="section-head">
        <h2 id="res-h" className="reveal">Measured, not claimed</h2>
        <p className="reveal">Each card says which model produced it and how large the sample is. Rebuild every number with make eval, make redteam and make faithfulness.</p>
      </div>
      <div className="res-grid">
        <div className="res-card reveal">
          <h3>Attack success, simulated worst case</h3>
          <p>{s.meta.alerts.toLocaleString("en-GB")} synthetic alerts, {s.meta.injected_malicious} of them injected and malicious. The simulated model obeys any instruction it can read.</p>
          <Meter label="Naive prompt" value={s.asr.naive} text={pct(s.asr.naive)} />
          <Meter label="AlertLens" value={s.asr.alertlens} text={pct(s.asr.alertlens)} />
          <Meter label="AlertLens misses caused by the injection" value={s.asr.alertlens_injection_caused} text={pct(s.asr.alertlens_injection_caused)} hatched />
        </div>
        {real && (
          <div className="res-card reveal">
            <h3>On a real model: {real.meta.model.replace("ollama:", "")}</h3>
            <p>{real.meta.alerts} alerts on a laptop CPU, {n} of them injected and malicious. A small sample, so read the counts, not the percentages.</p>
            <Meter label="Naive prompt fooled" value={real.asr.naive} text={`${Math.round(real.asr.naive * n)} of ${n}`} />
            <Meter label="AlertLens fooled" value={real.asr.alertlens} text={`${Math.round(real.asr.alertlens * n)} of ${n}`} />
            <p className="verdict">Turning off the detector, isolation or verifier left this at 0. Letting the model decide severity raised it to {pct(real.ablations?.find((a: { name: string }) => a.name.startsWith("LLM decides"))?.asr ?? null)}. Code-decided severity did the work.</p>
          </div>
        )}
        <div className="res-card reveal">
          <h3>Detecting hidden instructions</h3>
          <p>Rules plus a small classifier trained on a public dataset. The held-out wordings were never used for training.</p>
          <Meter label={`Known templates (n=${s.detection.known_n})`} value={s.detection.recall_known_templates} text={pct(s.detection.recall_known_templates)} />
          <Meter label={`Reworded, held out (n=${s.detection.heldout_n})`} value={s.detection.recall_heldout_paraphrases} text={pct(s.detection.recall_heldout_paraphrases)} />
          <Meter label="False alarms on clean alerts" value={s.detection.false_positive_rate} text={pct(s.detection.false_positive_rate)} hatched />
          {ext?.summary && <Meter label={`Attacks published by other researchers (n=${ext.summary.n})`} value={ext.summary.recall} text={pct(ext.summary.recall)} />}
          {ext?.summary && <p className="fine">Written by other teams for other systems, used only for testing. Missed or not, none of them lowered a severity: {ext.summary.decision_changed} of {ext.summary.n}{ext.full ? `, and ${ext.full.decision_changed} of ${ext.full.n} in the full set of ${ext.full.n} we can test locally but not redistribute` : ""}.</p>}
        </div>
        {ad && (
          <div className="res-card reveal">
            <h3>An adaptive attacker</h3>
            <p>{ad.attempts} rewrites across {ad.campaigns} campaigns, each keeping whatever lowered the detector&apos;s risk.</p>
            <Meter label="Slipped past detection" value={ad.evasion_rate} text={pct(ad.evasion_rate)} />
            <Meter label="Changed a decision" value={ad.decision_changed / Math.max(1, ad.attempts)} text={`${ad.decision_changed} of ${ad.attempts}`} hatched />
            <p className="fine">Some rewrites, like a translation, may no longer carry the original attack, so the evasion rate overstates the detector&apos;s weakness.</p>
          </div>
        )}
        {fv && (
          <div className="res-card reveal">
            <h3>Does a claim depend on its evidence?</h3>
            <p>Delete the facts a claim cites, then check again.</p>
            <Meter label={`Verifier notices missing evidence (${fv.claims_checked} claims)`} value={fv.rate} text={pct(fv.rate)} hatched />
            {fm ? (
              <Meter label={`${fm.model.replace("ollama:", "")} still states a deleted fact (${fm.claims_tested} claims)`} value={fm.rate ?? 0} text={pct(fm.rate)} />
            ) : (
              <p className="fine">The model test on llama3.2 is still running.</p>
            )}
            <p className="fine">The verifier check is a sanity check of our own code, not of the model.</p>
          </div>
        )}
        {bench.explainer_before_after && (
          <div className="res-card reveal">
            <h3>Testing on a real model changed the design</h3>
            <p>The same five alerts on llama3.2, before and after rewriting the explainer prompt and tightening the verifier.</p>
            <Meter label="Mean grounding, before" value={bench.explainer_before_after.before_explainer_v1.summary.mean_grounding} text={String(bench.explainer_before_after.before_explainer_v1.summary.mean_grounding)} hatched />
            <Meter label="Mean grounding, after" value={bench.explainer_before_after.after_explainer_v2.summary.mean_grounding} text={String(bench.explainer_before_after.after_explainer_v2.summary.mean_grounding)} />
            <p className="fine">Alerts with invented action ids: {bench.explainer_before_after.before_explainer_v1.summary.alerts_with_invented_action_ids} before, {bench.explainer_before_after.after_explainer_v2.summary.alerts_with_invented_action_ids} after.</p>
          </div>
        )}
      </div>
    </section>
  );
}
