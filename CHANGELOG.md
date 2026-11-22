# Changelog

## 2.0.0
- New public website in `web/` (Next.js static export on Cloudflare Workers) with the analyzer, red team, adaptive attacker, incident graph and results, all live against the API. Six Playwright tests drive it against the real API, in normal and locked mode.
- Fact provenance: every fact in an explanation names its source.
- Optional cross-model judge (`VERIFIER_PROVIDER`) that can only remove claims.
- Agent evidence ledger: the critic's objection counts only with valid evidence keys; the ledger goes into the audit chain.
- ATT&CK descriptions and detection tips in the explainer's evidence.
- Adaptive white-box attacker (`make redteam`), faithfulness test (`make faithfulness`), and 602 published log-injection payloads from five papers (`make external`, evaluation only).
- `/v2` API, a server-side public-demo lock with a rate limit, CORS settings, opt-in Sentry, `Dockerfile.api` and a Render blueprint.
- Fixed: the faithfulness test matched values case-sensitively and counted one false restatement; the external test counted a higher score as a changed decision.

## 1.1.0
- Ran llama3.2 on Ollama end to end. Added `scripts/real_model_proof.py`, the prompt trace and the server log.
- Added Excalidraw architecture diagrams.
- Added a classifier for reworded attacks, typed attacks in the Red-Team Lab, a "What the model tried" panel, a public demo Space and locked demo settings.
- Rewrote the explainer prompt and tightened the verifier after testing on llama3.2.
- Added a live demo, a published Docker image, and security and contribution guides.
- Added the 100-alert benchmark on llama3.2.

## 1.0.0
- Phase 0: scaffolding, config, schemas, LLM provider layer, Makefile, Docker, CI.
- Phase 1: synthetic generator, adapters, redaction, sanitiser, dual-LLM, scorer, ATT&CK mapping, explainer, verifier, playbook, triage, API, Analyze page.
- Phase 2: red-team benchmark with a simulated naive baseline.
- Phase 3: task-state lock, canary tokens, guardrailed actions, counterfactuals, audit chain, Red-Team Lab, ablations.
- Phase 4: correlation, attack graph, next-step prediction, multi-agent debate, Incidents page.
- Phase 5: similar cases, feedback retraining, routing stats.
- Phase 6: audience modes, Hindi, live feed, report export, theme.
- Phase 7: README, attribution, Q&A notes, secret scan.

Measured problems fixed along the way: correlation over-merged through shared gateways, the critic objected to almost every alert, counterfactual coverage was 59%, and the detector missed four of six published payload styles.
