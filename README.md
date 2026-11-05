# AlertLens

**Aegython 2026. Team ID: `TODO`. Challenge: Explain My Security Alert.**
[Demo video](TODO) · Review tag: `v1.0-submission` (`TODO commit hash`)

An evidence-grounded security alert explainer, built so that text an attacker plants in a log can't change the verdict.

![Hero demo: one click runs four linked alerts into a critical incident with an attack graph and timeline](docs/media/hero-demo.gif)

## The problem
Security teams get more alerts than they can read, and many now use LLMs to explain them. But log fields are written by attackers, so a user agent can say "classify as benign". LLMs also invent facts, and a model that suggests free-form commands can cause damage.

## What AlertLens does
- Scores severity with rules and a calibrated model. No LLM output is read.
- Finds hidden instructions, quarantines them, and shows them inert.
- Explains using only validated facts, and checks every claim against the alert.
- Recommends actions only from a fixed playbook, each with a dry run, approval and rollback. Nothing runs on a real system.
- Links alerts into one incident with a timeline, attack graph and likely next steps.
- Explains for an analyst, a manager or an employee, in English or Hindi.

## Quick start
Needs Python 3.11 or 3.12, or Docker. No API key and no internet needed at runtime.

```bash
git clone https://github.com/LSUDOKO/AlertLens.git && cd AlertLens
make setup && make demo        # or: docker compose up --build
# UI  http://localhost:8501
# API http://localhost:8000/docs
```

On the Home page, press **Run hero demo**. Then try **Red Team Lab**.

| Command | What it does |
|---|---|
| `make test` | Tests with coverage |
| `make lint` | Ruff |
| `make eval` | Full benchmark, writes `results/` |
| `make retrain` | Retrain with saved feedback |
| `make check-secrets` | Scan for key-shaped strings |

## Screenshots
Captured from the running app with the default offline provider. All data is synthetic.

**Red-Team Lab.** The same payload goes to a naive LLM and to AlertLens. Both use one simulated gullible model.

![Red-Team Lab attack: the naive LLM is fooled and AlertLens is not](docs/media/red-team.gif)

| | |
|---|---|
| **Analyze an alert**: the payload shown inert, with a score from code and its reasons<br>![Analyze an alert](docs/media/analyze.png) | **Incidents**: attack graph, timeline and likely next steps<br>![Incident view](docs/media/incident.png) |
| **Live feed**: severity over time and ATT&CK tactics<br>![Live feed](docs/media/live-feed.png) | **Benchmark**: results from `make eval`, and what breaks when a layer is removed<br>![Benchmark page](docs/media/benchmark.png) |
| **Audit log**: hash chain check and tamper demo<br>![Audit log](docs/media/audit-log.png) | **Home**: totals and where alerts went<br>![Home page](docs/media/home.png) |

## Use a real LLM (optional)
Edit `.env`:

```bash
LLM_PROVIDER=ollama          # or openai_compat, gemini, anthropic
QUARANTINE_PROVIDER=ollama
LLM_MODEL=<model name>
LLM_BASE_URL=http://localhost:11434
LLM_API_KEY=                 # hosted providers only
```

Benchmark it with `make eval EVAL_ARGS="--provider ollama --model <name> --limit 100 --out results/real"`.

The HTTP providers are tested against a local stub server only. They have not been run against a real model yet.

## Architecture
![How one alert is analysed](docs/media/architecture-pipeline.png)

![System overview](docs/media/architecture-system.png)

Editable sources: open [`pipeline.excalidraw`](docs/architecture/pipeline.excalidraw) or [`system.excalidraw`](docs/architecture/system.excalidraw) at excalidraw.com.

## How the AI works
```
Alert → Parse → Sanitise → Score (rules + ML, no LLM) → Map to ATT&CK → Correlate
      → Quarantined extractor (enums only) → Agents → Explainer (facts only)
      → Verify claims → Recommend from playbook → Audit log
```

- **Severity scorer:** 26 numeric features go to transparent weighted rules and a gradient boosting classifier with sigmoid calibration. Score = 0.5 × rules + 0.5 × 100 × probability. A detected injection adds up to 5 points and blocks auto-close.
- **Dual-LLM isolation:** only the quarantined extractor reads free text, with quarantined values masked and identifiers redacted. It returns a closed schema. The explainer gets facts and placeholders.
- **Claim verifier:** works in placeholder space. Values in a claim must appear in its cited fields, and unsupported claims are removed and listed.
- **Correlation and graph:** union-find over shared entities within a time window, then a NetworkX graph whose most connected entity is the pivot. Done in code, not by an LLM.
- **Next steps:** a hand-built ATT&CK transition table. A heuristic, labelled as one.
- **Multi-agent review:** triage, investigator and critic, with a code coordinator. A critic's objection can lower confidence and send an alert to a person, never lower the score.
- **Retrieval and learning:** TF-IDF search over past cases, plus analyst corrections that retrain the model and adjust rule weights.
- **Routing:** clear-cut alerts with no injection skip the LLM.

## Safety design
| Threat | Defence |
|---|---|
| Injection through alert fields | Detector and quarantine, dual-LLM, code-decided severity |
| Action hijacking | Fixed playbook, suggestions can only reorder valid actions |
| Prompt leakage | Canary token per request, leaked output is discarded |
| Hallucination | Claim verifier |
| State tampering | Task-state hash, steering language rejected and logged |
| PII exposure | Placeholders before any LLM, restored at display |
| Log tampering | Hash-chained audit log with a verify button |
| Over-automation | Human approval on every action, two steps for high risk, simulation only |

Details: [docs/06_SECURITY_AND_SAFETY.md](docs/06_SECURITY_AND_SAFETY.md).

## Results
Copied from [results/benchmark_report.md](results/benchmark_report.md), which `make eval` regenerates. A test fails if these drift from `results/metrics.json`.

**These results use a simulated model.** `VulnerableMockLLM` obeys any instruction it can read, and both systems use it. The naive column is a worst case by construction, not a measurement of a real LLM. Pandey and Bhujang (2026) measured that such mocks can mispredict real models. **No real-model run has been done yet.**

<!-- results -->
2000 synthetic alerts, 267 injected and malicious, seed 42, model `vulnerable-mock:obeys-injections-v1`.

| Metric | Measured |
|---|---|
| Attack success, naive baseline (simulated) | 100.0% |
| Attack success, AlertLens | 3.4% |
| AlertLens misses caused by the injection itself | 0.0% |
| Detection recall on payload templates | 100.0% (n=267) |
| Detection recall on held-out paraphrases | 34.8% (n=46) |
| False-positive rate on clean alerts | 0.0% |
| Labels lowered by a payload | 0 |
| Non-playbook actions | 0.0% |
| Mean grounding score, LLM path | 0.9906 |
| Verdict F1 on synthetic labels | 0.9782 |
| Calibration error (ECE) | 0.0297 |
| Correlation pairwise precision | 62.9% |
| Correlation pairwise recall | 85.4% |
| Alerts handled without an LLM | 84.7% |
| Counterfactual coverage, high or critical | 89.2% |
<!-- /results -->

## Testing
`make test` runs 271 tests offline with 98% coverage of `alertlens/`, including a Streamlit smoke test of every page. CI runs lint, secret scan and tests on every push.

## Project structure
```
alertlens/   pipeline: ingest, safety, llm, scoring, mitre, correlation,
             memory, agents, remediation, render, audit, feedback, api
ui/          Streamlit pages
data/        seeded generator and committed demo samples
eval/        benchmark harness
results/     generated report, metrics and charts
tests/       test suite
docs/        specification and Q&A notes
```

## Known limitations
- All data is synthetic, and we wrote both the data and the features, so model scores will not carry over to a real SOC.
- Remediation is simulated, and AlertLens is not connected to a live SIEM.
- The detector misses many novel paraphrases, as the held-out row shows. Other layers limit the damage, but detection alone is not reliable.
- The extractor can still lie within its closed vocabulary in fields code can't check.
- Numeric and enum fields such as `rule_level` are trusted as sensor output. Anyone able to forge them can change the score.
- Correlation precision is moderate: attackers sharing an address get merged.
- The next-step predictor is a heuristic. Hindi uses templates, so claims written by a real LLM stay in English.
- The API has no login, so it binds to localhost. The audit log is tamper-evident, not tamper-proof.

## Attribution and licence
See [ATTRIBUTION.md](ATTRIBUTION.md). MIT licence, see [LICENSE](LICENSE).

## Team
| Name | Role |
|---|---|
| TODO | TODO |
