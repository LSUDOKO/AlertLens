# 01 — Hackathon Requirements (Aegython 2026)

Source: the official Unstop listing for Aegython 2026 by AeglysAI. Re-check the official page and emails for updates, since several dates were still pending when this was written.

## Key facts
| Item | Detail |
|---|---|
| Organiser | AeglysAI |
| Fee | Free |
| Team size | 1–4 (including leader) |
| Our challenge | **Explain My Security Alert:** convert structured security alerts into clear explanations and safe recommendations |
| Registration deadline | 06 Nov 2026, 12:00 AM IST |
| Other dates | Qualification, submission, finalist and event dates were **pending**. Watch email. |
| Prizes | ₹30,000 / ₹20,000 / ₹10,000 plus pre-placement offers. The listing also mentions $300/$200/$100 and finalist goodies. Participation certificate. |
| Contact | aegython@aeglysai.com |

## Mandatory registration
- [ ] Register on Unstop
- [ ] **Every member** fills the official Google Form. Only Google Form entries are considered for shortlisting.
- [ ] Every member completes individual qualification (see `11_QUALIFICATION_GUIDE.md`)
- [ ] Leader submits the roster and gets a **Team ID**
- [ ] Nobody is in more than one active team. Roster changes need organiser approval.

## Round 1 — Technical screening (100 points)
Submit a working project, source code, a README with setup, testing evidence, and a video of 2 minutes or less.

| Criterion | Points | How AlertLens earns it | Where |
|---|---|---|---|
| Working functionality | 30 | Full pipeline runs end to end in the UI and through the API; `make demo` | Phases 1–3 |
| AI/ML or intelligent feature | 25 | Calibrated ML scorer, grounded LLM explanation, verifier, multi-agent, correlation graph, RAG, feedback learning | Features 2, 3, 4, 9, 18, 19 |
| Relevance and creativity | 20 | Directly solves the challenge; novel injection-proof angle backed by 2026 research | `02_PROJECT_OVERVIEW.md` |
| Reproducibility | 15 | Offline `MockLLM`, pinned dependencies, Docker, seeded data generator, one-command setup | `CLAUDE.md`, Phase 0 |
| Video clarity | 10 | Scripted 2-minute video with three "wow" moments | `10_SUBMISSION_AND_DEMO.md` |

## Round 2 — Finalist demo (100 points, decides the final ranking)
5-minute live demo on Google Meet, then 5 minutes of technical Q&A.

| Criterion | Points | How we earn it |
|---|---|---|
| Live demonstration | 35 | Rehearsed demo script, a backup recording, and offline mode so no API can fail mid-demo |
| Technical understanding | 25 | Every member knows the architecture (`03_ARCHITECTURE.md`) |
| Solution quality and safety | 20 | Layered defences, benchmark evidence, audit log, guardrailed actions |
| Technical Q&A | 15 | Q&A prep list in `10_SUBMISSION_AND_DEMO.md` |
| Presentation | 5 | Clean UI and a short story arc |

## Final submission deliverables
| Required item | Our file or location |
|---|---|
| Team ID and selected challenge | Top of README |
| Public GitHub repo with a fixed review commit or tag | Tag `v1.0-submission` |
| README with reproducible setup | `README.md` (template in `10_SUBMISSION_AND_DEMO.md`) |
| Demo video of 2 minutes or less | Link in README |
| Explanation of the AI/ML technique | README section "How the AI works" and `docs/03_ARCHITECTURE.md` |
| Testing or validation evidence | `make test`, `make eval` → `results/benchmark_report.md`, plus a coverage badge |
| Data and model attribution, licensing, known limitations | `ATTRIBUTION.md`, `LICENSE`, README "Known limitations" |

A slide deck alone is **not** accepted. It must be a working MVP.

## Rules we must follow
- Original work, or properly attributed third-party code, data and models
- **Only authorised systems and data.** No testing against real systems. Synthetic data only.
- **No passwords, credentials, personal info or confidential material** in the public repo
- Respectful conduct; credit collaborators and prior work
- Projects must address the selected challenge with functional, testable behaviour
- Qualification or registration does not guarantee selection or awards

## Open questions to ask the organisers
- Exact submission deadline and timezone
- Whether hosted LLM APIs are allowed in the live demo, or only local models
- Whether the repo must be public at submission time or by a set date
- Video hosting preference (YouTube unlisted or Google Drive)
- Whether a team member's existing code can be reused
