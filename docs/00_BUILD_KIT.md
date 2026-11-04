# AlertLens — Build Kit for Aegython 2026

**Challenge:** Explain My Security Alert
**One-line pitch:** *An injection-proof, evidence-grounded AI that turns raw security alerts into clear explanations, attack stories and safe next steps — and can prove it can't be tricked.*

This folder is a complete specification. Hand it to Claude (Claude Code, or a Claude chat with file tools) and it has everything needed to build the full project, phase by phase.

---

## How to use this kit

1. Create an empty folder for the project, for example `alertlens/`.
2. Copy **everything in this zip** into it. Keep `CLAUDE.md` at the root, because Claude Code reads it automatically.
3. Open Claude Code in that folder, or upload the files to a Claude chat.
4. Start with this prompt:

   > Read `CLAUDE.md` and every file in `docs/`. Then start **Phase 0** from `docs/07_BUILD_PLAN.md`. Stop at the end of the phase, show me what you built and how to run it, and wait for me to say "next phase".

5. For each later phase, use the matching prompt in `prompts/PHASE_PROMPTS.md`.

> Build one phase at a time and run it after every phase. A working small project beats a broken big one. Working functionality and the live demo are worth 65 of your 200 points.

---

## What's inside

| File | What it covers |
|---|---|
| `CLAUDE.md` | Rules for the coding Claude: stack, conventions, build order, things it must never do |
| `docs/01_HACKATHON_REQUIREMENTS.md` | Every official rule, deliverable and scoring criterion, mapped to where we satisfy it |
| `docs/02_PROJECT_OVERVIEW.md` | The problem, the idea, why it wins, and the research behind it |
| `docs/03_ARCHITECTURE.md` | System design, pipeline, module list, folder structure, tech stack |
| `docs/04_FEATURES_SPEC.md` | All 26 features with behaviour, inputs and outputs, and acceptance criteria |
| `docs/05_DATA_SCHEMA.md` | Alert, incident and explanation schemas, plus how to generate synthetic data |
| `docs/06_SECURITY_AND_SAFETY.md` | Threat model and every defence (injection, hallucination, unsafe actions, PII) |
| `docs/07_BUILD_PLAN.md` | Phase-by-phase plan with task checklists and "done when" criteria |
| `docs/08_TESTING_AND_EVALUATION.md` | Unit tests, the red-team benchmark, metrics and the results report |
| `docs/09_API_AND_UI.md` | REST endpoints and every dashboard screen |
| `docs/10_SUBMISSION_AND_DEMO.md` | Submission checklist, README template, 2-minute video script, Round 2 demo and Q&A prep |
| `docs/11_QUALIFICATION_GUIDE.md` | How each team member completes the mandatory AeglysAI qualification |
| `docs/12_RESEARCH_REFERENCES.md` | Papers backing each feature, and how to mention them to judges |
| `prompts/PHASE_PROMPTS.md` | Copy-paste prompts for every phase, plus fix-it and review prompts |

---

## The 26 features at a glance

**Core:** 1 Sanitiser · 2 Rule and ML severity scorer · 3 Grounded explainer · 4 Claim verifier · 5 Safe recommender
**Investigation:** 6 Alert correlation · 7 Attack graph · 8 Next-step prediction · 9 Multi-agent investigation · 10 Triage with confidence
**Safety:** 11 Dual-LLM isolation · 12 Task-state lock · 13 Canary tokens · 14 Guardrailed remediation · 15 Counterfactuals · 16 PII redaction · 17 Tamper-evident audit log
**Learning:** 18 Analyst feedback loop · 19 Similar past incidents · 20 Smart cost routing
**User experience:** 21 Audience modes · 22 Hindi explanations · 23 Live dashboard · 24 Incident report export · 25 Standard alert formats
**Proof:** 26 Red-team benchmark harness

---

## Before you build: official steps

- [ ] Registered on Unstop (deadline 6 Nov 2026, 12:00 AM IST)
- [ ] Every member filled the official Google Form
- [ ] Every member finished qualification (see `docs/11_QUALIFICATION_GUIDE.md`)
- [ ] Team roster submitted and Team ID received
- [ ] Submission, finalist and event dates confirmed from the organisers (they were not published when this kit was written)

Contact: aegython@aeglysai.com
