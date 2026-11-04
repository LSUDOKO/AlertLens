"""Shows results written by `make eval`. Numbers come only from those files."""
import json

import streamlit as st

from alertlens.config import ROOT
from eval.run_benchmark import run
from ui.common import setup

setup("Benchmark")
st.title("Benchmark")
out = ROOT / "results"
path = out / "metrics.json"
if st.button("Run a quick benchmark, about 100 alerts"):
    with st.spinner("Running the real pipeline on 100 alerts"):
        run(100, None, "", out / "quick")
    st.session_state["quick"] = True
if st.session_state.get("quick"):
    path, out = out / "quick" / "metrics.json", out / "quick"
    st.caption("Showing the quick run. Reload the page for the full run.")
if not path.exists():
    st.info("No results yet. Run `make eval`.")
    st.stop()
r = json.loads(path.read_text())
m = r["meta"]
st.write(f"{m['alerts']} synthetic alerts, {m['injected_malicious']} injected and malicious. Model `{m['model']}`, commit `{m['commit']}`, {m['date']}.")
if m["simulated_model"]:
    st.warning("Simulated model: it obeys any instruction it can read. The naive column is a worst case, not a measurement of a real LLM.")
a, b, c, d = st.columns(4)
a.metric("Attack success, naive", f"{100 * r['asr']['naive']:.1f}%")
b.metric("Attack success, AlertLens", f"{100 * r['asr']['alertlens']:.1f}%")
c.metric("Misses caused by the injection", f"{100 * r['asr']['alertlens_injection_caused']:.1f}%")
d.metric("Non-playbook actions", f"{100 * r['unsafe_actions']['alertlens']:.1f}%")
st.subheader("Ablations: what breaks when a layer is removed")
st.dataframe([{"Configuration": x["name"], "Attack success": x["asr"], "Downplaying text shown": x["downplayed_explanations"],
               "Invented address shown": x["invented_ip_shown"], "Canary shown to reader": x["canary_shown"]} for x in r["ablations"]],
             hide_index=True, width="stretch")
for name, cap in [("asr_by_family", "Attack success by family"), ("reliability", "Calibration"), ("confusion", "Verdicts"), ("latency", "Latency")]:
    png = out / "charts" / f"{name}.png"
    if png.exists():
        st.image(str(png), caption=cap, width=640)
report = out / "benchmark_report.md"
if report.exists():
    with st.expander("Full report"):
        st.markdown(report.read_text().split("## Headline")[1].split("![")[0])
