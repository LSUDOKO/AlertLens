# CLAUDE.md — Instructions for building AlertLens

You are building **AlertLens** for the Aegython 2026 hackathon, challenge **"Explain My Security Alert"**. Read every file in `docs/` before writing code. Those files are the spec; if this file and a doc disagree, this file wins.

## Mission
Turn structured security alerts into clear, grounded explanations and **safe** recommendations. Prove with a benchmark that the system resists prompt injection and does not make things up.

## Golden rules
1. **Build phase by phase** using `docs/07_BUILD_PLAN.md`. Stop at the end of each phase, show how to run it, and wait for the user to say "next phase".
2. **Everything must run offline with no API key.** A deterministic `MockLLM` provider is the default. Real LLMs (Ollama, Gemini, Groq, Anthropic, OpenAI) are optional, chosen through `.env`. Tests and the demo must pass with `MockLLM`.
3. **One-command setup.** `make setup && make demo` (and `docker compose up`) must work on a fresh machine. Reproducibility is worth 15 points.
4. **The LLM never decides severity, never runs actions, and never sees raw untrusted text in the privileged step.** See `docs/06_SECURITY_AND_SAFETY.md`.
5. **Synthetic data only.** Never use real logs, real credentials, real personal data, or connect to real systems. Use reserved test ranges: IPs `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `10.0.0.0/8`; domains `example.com`, `example.org`; users like `alice.test`.
6. **No secrets in the repo.** Use `.env` (git-ignored) and commit a `.env.example`.
7. **Every feature gets tests** before the phase is marked done.
8. **Keep it working.** Never leave `main` broken. If a feature is half-done at the end of a phase, put it behind a feature flag set to off.
9. **Attribute everything:** third-party libraries, models, datasets and MITRE ATT&CK go in `ATTRIBUTION.md`.
10. **Explain as you go.** Add short docstrings and update `docs/` if the design changes. The team must be able to answer judges' technical questions.

## Tech stack (do not change without asking)
- Python 3.11+
- **Backend:** FastAPI + Uvicorn
- **UI:** Streamlit (multi-page)
- **Schemas and validation:** Pydantic v2
- **ML:** scikit-learn (GradientBoostingClassifier, CalibratedClassifierCV, IsolationForest), numpy, pandas
- **Graph:** NetworkX; drawn with pyvis or plotly
- **Charts:** plotly
- **Storage:** SQLite through SQLModel or the stdlib `sqlite3`
- **Similarity search:** scikit-learn NearestNeighbors over TF-IDF by default; optional `sentence-transformers` (all-MiniLM-L6-v2) behind a flag
- **Reports:** Markdown → HTML (Jinja2); PDF through `fpdf2` (English); Hindi report as HTML with Noto Sans Devanagari
- **Testing:** pytest, pytest-cov; **Lint:** ruff
- **Packaging:** `requirements.txt` (pinned), `Makefile`, `Dockerfile`, `docker-compose.yml`

## Repository layout
Follow `docs/03_ARCHITECTURE.md` section "Folder structure" exactly.

## Coding conventions
- Type hints everywhere. Every data object passed between pipeline stages is a Pydantic model defined in `alertlens/schemas.py`.
- Each pipeline stage is a pure-ish function or class with one job and its own test file.
- Config lives in `alertlens/config.py` (reads `.env`). Feature flags live there too.
- Log through the `logging` module, never `print`, in library code.
- Every LLM call goes through `alertlens/llm/provider.py`. No other module imports an LLM SDK.
- Every LLM output is parsed into a Pydantic model; on a parse failure, retry once, then fall back to a template.
- Every recommended action must come from `alertlens/remediation/playbook.yaml`.

## Definition of done (for every phase)
- `make test` passes, and `make lint` is clean or nearly clean
- `make demo` starts and the new feature is visible in the UI
- README's "Features" and "How to run" sections are updated
- `CHANGELOG.md` has an entry for the phase
- You showed the user the exact commands to try it

## Never do this
- Hard-code API keys or put real-looking secrets in sample data
- Let the LLM output free-form shell commands or actions
- Send raw alert text to the privileged explainer
- Fake benchmark numbers. All results must come from `make eval`.
- Add heavy dependencies (PyTorch, transformers) to the default install; put them in `requirements-extra.txt`
