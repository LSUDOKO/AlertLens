# 03 — Architecture

## 1. Pipeline overview

```
                        ┌──────────────────────────── UNTRUSTED ZONE ────────────────────────────┐
 Alert (JSON) ──► [Adapters] ──► [Normaliser] ──► [PII Redactor] ──► [Sanitiser / Injection Detector]
  Wazuh-like      Feature 25       Alert model      Feature 16           Feature 1 (+ Feature 13 canaries)
  Suricata-like                                                              │
  Sigma-matched                                                              ▼
                                                              [Quarantined LLM extractor] Feature 11
                                                               raw text → strict JSON facts only
                        └─────────────────────────────────────────────────────┬──────────────────┘
                                                                              ▼
                        ┌──────────────────────────── TRUSTED ZONE ──────────────────────────────┐
                        │  [Severity Scorer: rules + calibrated ML]   Feature 2, 10, 15 (no LLM)   │
                        │  [ATT&CK Mapper] ──► [Next-step Predictor]  Feature 8                    │
                        │  [Correlator] ──► [Attack Graph]            Features 6, 7                │
                        │  [Similar Incidents (RAG)]                  Feature 19                   │
                        │  [Router: template vs LLM]                  Feature 20                   │
                        │  [Multi-agent: Triage → Investigator → Critic]  Feature 9                │
                        │  [Privileged Explainer LLM] (sees facts only, task state locked) 3, 12   │
                        │  [Claim Verifier]                           Feature 4                    │
                        │  [Safe Recommender + Guardrails]            Features 5, 14               │
                        │  [Audience / Language renderer]             Features 21, 22              │
                        └──────────────────────────────────────────────┬───────────────────────────┘
                                                                       ▼
                     [Audit Log (hash chain)] F17   [SQLite store]   [Feedback loop] F18
                                                                       ▼
                         FastAPI  ◄──►  Streamlit dashboard (F23)  ──►  Report export (F24)
                                                                       ▲
                                        Red-team benchmark harness (F26) runs everything offline
```

**Key idea:** untrusted text (anything that came from the alert) is only ever read by (a) deterministic code and (b) the **quarantined** extractor, whose output is forced into a fixed JSON schema of enums, numbers and short identifiers. The **privileged** explainer never sees raw strings, only validated facts. That is why injected instructions can't steer it.

## 2. Processing steps

| # | Stage | Module | Input → Output | LLM? |
|---|---|---|---|---|
| 1 | Adapter | `ingest/adapters.py` | vendor JSON → `RawAlert` | No |
| 2 | Normalise | `ingest/normalise.py` | `RawAlert` → `Alert` | No |
| 3 | Sanitise | `safety/injection.py` | `Alert` → `SanitiseReport` (findings, quarantined fields) | No |
| 4 | Redact | `safety/pii.py` | values → placeholders + vault, applied when each LLM view is built | No |
| 5 | Extract | `llm/quarantined.py` | free-text fields → `ExtractedFacts` (strict schema) | Yes (quarantined) |
| 6 | Score | `scoring/scorer.py` | `Alert` + facts → `SeverityResult` (score, label, confidence, reasons) | No |
| 7 | Counterfactual | `scoring/counterfactual.py` | `Alert` → list of "would be X if Y" | No |
| 8 | ATT&CK map | `mitre/mapper.py` | `Alert` → techniques + tactic | No |
| 9 | Predict next | `mitre/predictor.py` | tactic history → next likely tactics and techniques | No |
| 10 | Correlate | `correlation/correlator.py` | alerts in a window → `Incident`s | No |
| 11 | Graph | `correlation/graph.py` | `Incident` → NetworkX graph + summary | No |
| 12 | Similar | `memory/retriever.py` | `Alert` → top-k past `ResolvedCase` | No |
| 13 | Route | `pipeline/router.py` | decides template vs LLM path | No |
| 14 | Agents | `agents/` | facts → triage verdict, investigation notes, critique | Yes |
| 15 | Explain | `llm/explainer.py` | facts → `Explanation` with claim→evidence links | Yes (privileged) |
| 16 | Verify | `safety/verifier.py` | `Explanation` + `Alert` → verified `Explanation` | No (+ optional LLM judge) |
| 17 | Recommend | `remediation/recommender.py` | severity + technique → `Action`s from playbook | No |
| 18 | Render | `render/audience.py`, `render/i18n.py` | `Explanation` → analyst, manager or employee; en or hi | Optional |
| 19 | Audit | `audit/chain.py` | every decision → hash-chained record | No |

`pipeline/orchestrator.py` runs the stages in order and returns an `AnalysisResult`.

**As built:** sanitising runs before redaction, because redaction replaces identifier fields whole and would hide a payload planted in `user` or `host`. The scorer ignores LLM facts completely, and rule lookups use `rule_id`, so severity depends on no model output. Facts from the extractor are reconciled against code-derived facts, and code wins a conflict. The optional injection classifier and full STIX loading were not built.

## 3. LLM provider layer
`llm/provider.py` exposes one interface:

```python
class LLMProvider(Protocol):
    name: str
    def complete(self, system: str, user: str, *, schema: type[BaseModel] | None,
                 temperature: float = 0.0, max_tokens: int = 800) -> LLMResponse: ...
```

Implementations:
- `MockLLM` (**default**): deterministic, template-based, offline. Produces valid outputs for every schema, so the app and tests always work. Its job is to make the system demo-able with zero setup, not to be smart.
- `OllamaLLM`: local model through `http://localhost:11434` (for example a 3B–8B instruct model). Set the model name in `.env`.
- `OpenAICompatibleLLM`: any OpenAI-compatible endpoint (Groq, OpenRouter, LM Studio, vLLM).
- Gemini and Anthropic: both expose OpenAI-compatible endpoints, so they share `OpenAICompatibleLLM`. Only the wire format is tested, against a local stub.
- `NaiveBaselineLLM`: wraps any provider but sends the **raw alert** with no defences. Used only by the benchmark for comparison.

Every response records provider, model, latency, tokens (if known) and whether it fell back to a template.

## 4. Folder structure

```
alertlens/
├── CLAUDE.md
├── README.md
├── ATTRIBUTION.md
├── LICENSE                      # MIT recommended
├── CHANGELOG.md
├── Makefile
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── requirements-extra.txt       # sentence-transformers, injection classifier, etc.
├── .env.example
├── .gitignore
├── alertlens/
│   ├── __init__.py
│   ├── config.py                # settings + feature flags
│   ├── schemas.py               # all Pydantic models
│   ├── ingest/        adapters.py, normalise.py
│   ├── safety/        pii.py, injection.py, canary.py, verifier.py, state_lock.py
│   ├── llm/           provider.py, mock.py, ollama.py, openai_compat.py, quarantined.py,
│   │                  explainer.py, prompts/ (*.txt templates)
│   ├── scoring/       features.py, rules.py, model.py, scorer.py, counterfactual.py
│   ├── mitre/         attack_subset.json, mapper.py, predictor.py, transitions.json
│   ├── correlation/   correlator.py, graph.py
│   ├── memory/        store.py, retriever.py
│   ├── agents/        triage.py, investigator.py, critic.py, coordinator.py
│   ├── remediation/   playbook.yaml, recommender.py, guardrails.py
│   ├── render/        audience.py, i18n.py, report.py, templates/
│   ├── audit/         chain.py
│   ├── feedback/      loop.py
│   ├── pipeline/      orchestrator.py, router.py
│   └── api/           main.py, routes_*.py
├── ui/
│   ├── Home.py
│   └── pages/  1_Analyze_Alert.py, 2_Incidents.py, 3_Live_Feed.py, 4_Red_Team_Lab.py,
│               5_Benchmark.py, 6_Feedback.py, 7_Audit_Log.py, 8_Settings.py
├── data/
│   ├── generator/  generate.py, scenarios.py, injections.py
│   ├── samples/    (committed small demo set)
│   └── benchmark/  (generated, seeded)
├── eval/
│   ├── run_benchmark.py
│   ├── metrics.py
│   └── report.py
├── results/        benchmark_report.md, charts/*.png (generated by make eval)
├── scripts/        demo_scenarios.py, seed_db.py
├── tests/          test_*.py (one per module) + test_pipeline_e2e.py
└── docs/           (this kit)
```

## 5. Storage (SQLite: `alertlens.db`)
Tables: `alerts`, `analyses`, `incidents`, `incident_alerts`, `feedback`, `resolved_cases`, `audit_log`, `actions` (proposed, approved or rejected, dry-run output).

## 6. Configuration (`.env.example`)
```
LLM_PROVIDER=mock            # mock | ollama | openai_compat | gemini | anthropic
LLM_MODEL=                   # e.g. a local instruct model name for ollama
LLM_BASE_URL=http://localhost:11434
LLM_API_KEY=
QUARANTINE_PROVIDER=mock     # can differ from main provider
EMBEDDINGS=tfidf             # tfidf | minilm
CORRELATION_WINDOW_MIN=30
ROUTER_LLM_THRESHOLD=0.35    # ambiguity band for sending to LLM
FEATURE_MULTI_AGENT=true
FEATURE_HINDI=true
FEATURE_INJECTION_CLASSIFIER=false
DB_PATH=alertlens.db
SEED=42
```

## 7. Makefile targets
```
setup      # create venv, install requirements, generate data, train model, seed DB
data       # regenerate synthetic data (seeded)
train      # train the severity model
api        # run FastAPI on :8000
ui         # run Streamlit on :8501
demo       # api + ui together, load demo scenarios
test       # pytest with coverage
lint       # ruff
eval       # run red-team benchmark → results/
report     # regenerate results/benchmark_report.md + charts
clean
```

## 8. Design decisions to explain to judges
| Decision | Why |
|---|---|
| Severity from rules + ML, never the LLM | An injection can't argue the score down; the score is reproducible |
| Dual-LLM split | Raw attacker-controlled text never reaches the model that writes the final output |
| Fixed action playbook | No free-form commands, so no dangerous hallucinated actions |
| Graph built in code | LLMs are weak at multi-hop graph reasoning; code is exact and fast |
| Mock provider by default | Reproducible, offline and free; the demo can't fail because of an API |
| SQLite | Zero setup, one file, easy to inspect |
