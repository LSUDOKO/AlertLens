# Changelog

## 1.1.0
- Ran llama3.2 on Ollama end to end. Added `scripts/real_model_proof.py`, the prompt trace and the server log.
- Added Excalidraw architecture diagrams.
- Added a classifier for reworded attacks, typed attacks in the Red-Team Lab, a "What the model tried" panel, a public demo Space and locked demo settings.
- Rewrote the explainer prompt and tightened the verifier after testing on llama3.2.
- Added a live demo, a published Docker image, and security and contribution guides.

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
