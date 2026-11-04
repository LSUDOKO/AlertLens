# Copy-Paste Prompts for Claude

Use these one at a time. Wait for each phase to finish, run it yourself, then send the next.

---

## Start (Phase 0)
```
Read CLAUDE.md and every file in docs/ carefully. Summarise the project in 5 lines so I know you understood it.
Then do Phase 0 from docs/07_BUILD_PLAN.md exactly: folder structure, config, all Pydantic schemas,
LLM provider layer with MockLLM as default, Makefile, Dockerfile, docker-compose, FastAPI /health,
Streamlit Home page, GitHub Actions CI.
At the end: run `make test`, show me the output, and give me the exact commands to run the demo. Then stop and wait.
```

## Phase 1 — Core pipeline
```
Next phase: Phase 1 from docs/07_BUILD_PLAN.md.
Build the synthetic data generator (all scenarios, injection families, and the hero scenario from docs/05_DATA_SCHEMA.md),
then features F25, F16, F1, F11, F2, ATT&CK mapper, F3, F4, F5, F10, the orchestrator, POST /analyze,
and the "Analyze Alert" UI page. Follow the acceptance criteria in docs/04_FEATURES_SPEC.md and write tests for each.
Everything must work with LLM_PROVIDER=mock. Finish with the end-to-end hero test passing.
Show me test output and how to see the hero alert in the UI. Then stop.
```

## Phase 2 — Benchmark
```
Next phase: Phase 2. Build the red-team benchmark harness (F26) exactly as in docs/08_TESTING_AND_EVALUATION.md:
naive baseline (injection-obeying mock + optional real model), all metrics, results/benchmark_report.md,
metrics.json, charts, and the Benchmark UI page. Never invent numbers; everything comes from `make eval`.
Run `make eval` and show me the headline table. Then stop.
```

## Phase 3 — Safety hardening
```
Next phase: Phase 3. Build F12, F13, F14, F15, F17, the Red-Team Lab page and the Audit Log page
(with integrity check and tamper demo), and add ablations to the benchmark.
Tests for each acceptance criterion. Re-run `make eval` and show me what changed. Then stop.
```

## Phase 4 — Investigation intelligence
```
Next phase: Phase 4. Build F6 correlation, F7 attack graph (with pivot highlight), F8 next-step predictor,
F9 multi-agent investigation with a visible debate transcript, /analyze/batch, /incidents, and the Incidents page.
Verify the hero set becomes one incident with 4 ordered steps. Then stop.
```

## Phase 5 — Learning and efficiency
```
Next phase: Phase 5. Build F19 similar past incidents (TF-IDF default, MiniLM optional via flag),
F18 feedback loop with retrain and before/after metrics, F20 smart routing with stats,
and the Feedback page. Show a demonstration that retraining improves a target pattern. Then stop.
```

## Phase 6 — User experience
```
Next phase: Phase 6. Build F21 audience modes, F22 Hindi (technical tokens untouched),
F23 live feed with KPIs, trend and ATT&CK heatmap, F24 report export (MD/HTML/PDF).
Polish the whole UI with a consistent dark security theme, good empty states and clear errors. Then stop.
```

## Phase 7 — Submission polish
```
Final phase: Phase 7. Write the final README using the template in docs/10_SUBMISSION_AND_DEMO.md,
complete ATTRIBUTION.md and known limitations, add a secret-scan target, run the full fresh-clone check,
run `make eval` and copy the real numbers into the README, and write docs/QA_ANSWERS.md with short answers
to all 15 Q&A questions. List anything still missing against docs/01_HACKATHON_REQUIREMENTS.md.
```

---

## Utility prompts

**Something broke**
```
`<command>` fails with this error: <paste error>. Find the root cause, fix it, add a test that would have caught it,
and re-run `make test`. Don't change unrelated code.
```

**Review against the spec**
```
Compare the current code against docs/04_FEATURES_SPEC.md and docs/01_HACKATHON_REQUIREMENTS.md.
Give me a table: feature, status (done / partial / missing), failing acceptance criteria, and what to fix first.
```

**Security self-audit**
```
Act as a red-teamer. Try to get a malicious alert classified as benign, leak the canary,
or produce a non-playbook action. Write each attempt as a test. Report which succeeded and fix them.
```

**Explain it to me (for Q&A prep)**
```
Explain how <module or feature> works as if I'm being asked by a judge. Use simple words, point to the files,
and list 3 likely follow-up questions with answers.
```

**Use a real local model**
```
Help me run AlertLens with Ollama on my laptop (<RAM>, <CPU/GPU>). Recommend a small instruct model that fits,
update .env, run the hero demo and `make eval` with it, and add both mock and real-model results to the README.
```
