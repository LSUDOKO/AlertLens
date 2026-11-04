# 07 — Build Plan (phase by phase)

Rule: **end every phase with a working, demo-able app.** Run `make test` and `make demo` before moving on. Commit and tag each phase (`phase-0`, `phase-1`, …).

Rough effort assumes one person working with Claude; split across teammates using the "Team split" table at the end.

---

## Phase 0 — Skeleton and setup (about half a day)
- [ ] Create the folder structure from `03_ARCHITECTURE.md`
- [ ] `requirements.txt` (pinned), `requirements-extra.txt`, `.env.example`, `.gitignore`, `LICENSE` (MIT), `CHANGELOG.md`, `ATTRIBUTION.md`
- [ ] `config.py` with settings and feature flags
- [ ] `schemas.py` with every model from `05_DATA_SCHEMA.md`
- [ ] `llm/provider.py` + `MockLLM` + `OllamaLLM` + `OpenAICompatibleLLM`
- [ ] `Makefile`, `Dockerfile`, `docker-compose.yml`
- [ ] FastAPI `/health`; Streamlit Home page placeholder
- [ ] GitHub Actions CI running `make lint test`
**Done when:** `make setup && make test && make demo` works and shows the Home page.

## Phase 1 — Data and core pipeline, P0 (about 2 days)
- [ ] Synthetic generator with all scenarios + injection library + hero scenario (`05_DATA_SCHEMA.md`)
- [ ] F25 adapters + normaliser (native + three formats)
- [ ] F16 PII redaction
- [ ] F1 sanitiser
- [ ] F11 quarantined extractor (mock + real)
- [ ] F2 rules + ML scorer (train script, saved model in `models/`, seeded)
- [ ] ATT&CK subset + mapper
- [ ] F3 grounded explainer
- [ ] F4 verifier
- [ ] F5 playbook + recommender
- [ ] F10 triage with confidence
- [ ] Orchestrator + `/analyze`
- [ ] UI page "Analyze Alert" (severity, explanation, actions, injection banner)
- [ ] Tests for all of the above + e2e hero test
**Done when:** The hero alert shows the injection banner, a high or critical severity, a verified explanation and safe actions, all in mock mode.

## Phase 2 — Benchmark first (about 1 day)
Do this early so every later feature can be measured.
- [ ] F26 harness: naive baseline (injection-obeying mock + real-model option), metrics, report, charts
- [ ] UI "Benchmark" page
**Done when:** `make eval` produces `results/benchmark_report.md` with real measured numbers.

> **Round 1 MVP checkpoint.** At this point you could submit. Record a backup video now.

## Phase 3 — Safety hardening (about 1.5 days)
- [ ] F12 task-state lock
- [ ] F13 canary tokens
- [ ] F14 guardrailed remediation (dry run, approval, rollback, two-step for high risk)
- [ ] F15 counterfactuals
- [ ] F17 hash-chained audit log + verify
- [ ] UI "Red-Team Lab" and "Audit Log" pages
- [ ] Ablations in the benchmark
**Done when:** The Red-Team Lab shows naive vs AlertLens live, and the audit "tamper" demo is detected.

## Phase 4 — Investigation intelligence (about 2 days)
- [ ] F6 correlation into incidents
- [ ] F7 attack graph + visual
- [ ] F8 next-step predictor
- [ ] F9 multi-agent (triage / investigator / critic / coordinator) + transcript UI
- [ ] `/analyze/batch`, `/incidents`; UI "Incidents" page
**Done when:** Loading the hero set shows one incident with a timeline, graph with pivot, predicted next steps and agent debate.

## Phase 5 — Learning and efficiency (about 1.5 days)
- [ ] F19 similar past incidents (TF-IDF; MiniLM optional)
- [ ] F18 feedback loop + retrain + before/after chart
- [ ] F20 smart routing + metrics
- [ ] UI "Feedback" page; router stats on Home
**Done when:** Retraining after feedback visibly improves a target pattern; fast-path share is reported.

## Phase 6 — User experience (about 1.5 days)
- [ ] F21 audience modes
- [ ] F22 Hindi
- [ ] F23 live feed, KPIs, heatmap, trends
- [ ] F24 report export (MD, HTML, PDF)
- [ ] UI polish and theme; empty states; error messages
**Done when:** All pages look finished; the report downloads in both languages.

## Phase 7 — Submission polish (about 1 day)
- [ ] Final README (template in `10_SUBMISSION_AND_DEMO.md`) with screenshots and GIFs
- [ ] `ATTRIBUTION.md` and known limitations complete
- [ ] Fresh-machine test (another teammate's laptop) + Docker test
- [ ] Final `make eval` with mock **and** a real local model; README numbers updated
- [ ] Record the 2-minute video; rehearse the Round 2 demo three times
- [ ] Tag `v1.0-submission`; submit
**Done when:** Everything in `10_SUBMISSION_AND_DEMO.md` is ticked.

---

## Team split (if you are 2–4 people)
| Person | Owns |
|---|---|
| A — ML and data | Generator, scorer, calibration, counterfactuals, feedback retraining, benchmark metrics |
| B — LLM and safety | Provider layer, sanitiser, dual-LLM, verifier, canary, state lock, prompts |
| C — Backend and investigation | API, orchestrator, correlation, graph, predictor, agents, audit log, RAG |
| D — UI and delivery | Streamlit pages, i18n, reports, README, video, demo rehearsal |

Everyone must understand the whole pipeline for the Q&A. Hold a 15-minute walkthrough at the end of each phase.

## Risk list
| Risk | Mitigation |
|---|---|
| Local LLM too slow on a laptop | Mock mode default; smaller model; fast-path routing |
| LLM returns broken JSON | Pydantic + one retry + template fallback |
| Demo machine or internet fails | Offline mode + pre-recorded backup video |
| Scope creep | Ship the P0 MVP first; flags for unfinished features |
| Benchmark looks "too good" | Report real numbers, include ablations and limitations, test with a real model |
