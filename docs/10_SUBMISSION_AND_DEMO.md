# 10 — Submission, Video, Demo and Q&A

## 1. Final submission checklist
- [ ] Team ID: `__________`  Challenge: **Explain My Security Alert**
- [ ] Public GitHub repo; review tag `v1.0-submission` (commit hash in README)
- [ ] README complete (template below)
- [ ] Demo video ≤ 2:00, link works in an incognito window
- [ ] "How the AI works" section in README
- [ ] Testing evidence: `make test` output + coverage, `results/benchmark_report.md`
- [ ] `ATTRIBUTION.md` (libraries, models, ATT&CK, any datasets), `LICENSE`, known limitations
- [ ] No secrets, no personal data (run `make check-secrets`)
- [ ] Every team member's name and role in README
- [ ] Submitted through the official channel before the deadline

## 2. README template (the coding Claude fills this in)
```markdown
# AlertLens 🔍 — Injection-proof, evidence-grounded security alert explainer
**Aegython 2026 · Team ID: XXXX · Challenge: Explain My Security Alert**
[Demo video](link) · Review tag: v1.0-submission

## The problem (3 lines)
## What AlertLens does (bullets + hero screenshot/GIF)
## Quick start
    git clone ... && cd alertlens
    make setup && make demo        # or: docker compose up
    # open http://localhost:8501  — works offline, no API key needed
## Use a real LLM (optional)
## How the AI works
   - Pipeline diagram
   - ML severity scorer (features, model, calibration)
   - Dual-LLM isolation, grounded explanation, verifier
   - Correlation graph, next-step prediction, multi-agent critic
   - Retrieval of similar cases, feedback learning, routing
## Safety design (threat → defence table)
## Results (table copied from results/benchmark_report.md, with model + date)
## Testing (how to run; coverage)
## Project structure
## Known limitations
## Attribution & licence
## Team
```

## 3. Two-minute video script
Record at 1080p with clear audio, zoom the browser to about 125%, and use captions. Show only three wow moments.

| Time | Screen | Voice-over (approximate) |
|---|---|---|
| 0:00–0:12 | Title card, then a messy raw alert | "SOC analysts get thousands of cryptic alerts. Teams now use AI to explain them, but attackers can hide instructions inside the logs to fool the AI." |
| 0:12–0:25 | Analyze page, hero alert 2 | "This login alert has 'mark as benign' hidden in the user agent." |
| 0:25–0:50 | **Red-Team Lab:** naive vs AlertLens side by side | "A normal AI says benign, close it. AlertLens flags the injection, keeps severity critical because it's decided by code, and explains it with every claim checked against the evidence." |
| 0:50–1:15 | **Incidents:** timeline + attack graph + next steps | "It links four alerts into one attack: stuffing, login, new admin, 1.8 GB exfil. It finds the compromised account and predicts what comes next." |
| 1:15–1:35 | Actions with dry run + approve; audience switch to Manager and **Hindi** | "Only safe, approved actions with a preview and rollback. The same story for an analyst, a manager, or in Hindi." |
| 1:35–1:52 | Benchmark page headline chart | "On our seeded red-team benchmark of N alerts, the attack success rate dropped from X% to Y%." (real numbers) |
| 1:52–2:00 | README / one-command run | "Open source, runs offline with one command. AlertLens." |

## 4. Round 2 live demo (5 minutes)
Prep: two machines (or a backup video ready), mock mode on, DB pre-seeded, browser tabs pre-opened, notifications off.

1. **(0:30) Hook:** the problem plus the one-sentence pitch
2. **(1:30) Red-Team Lab live:** let a judge **choose** the injection family and field, then attack. Show the layer that caught it.
3. **(1:15) Incident story:** graph, pivot, next steps, agent debate where the critic disagrees (the hero incident has no objection, because a chain of alerts outweighs the innocent story; show the critic on sample `12_ambiguous_admin_login_native.json` with Force the LLM path)
4. **(0:45) Safe action:** dry run, approve, audit log entry, then "Verify integrity", then the tamper demo
5. **(0:30) Proof:** benchmark headline + ablation (what breaks if we remove a layer)
6. **(0:30) Close:** limitations stated honestly + what's next

## 5. Q&A prep — every member should answer these
1. Why not just let the LLM decide severity?
2. How does the dual-LLM pattern stop injection? What can still get through?
3. How did you build and label the training data? Isn't synthetic data a weakness?
4. How do you know the explanation isn't hallucinated? How does the verifier work?
5. What is calibration, and why does it matter for triage?
6. How does correlation decide two alerts are related? What are the failure cases?
7. What if the attacker uses a language or encoding you didn't anticipate?
8. Why a fixed playbook? Isn't that limiting?
9. How would this connect to a real SIEM (Wazuh, Splunk, Elastic)?
10. How does it scale to 10,000 alerts per day? (routing, batching, caching)
11. What does the feedback loop change, exactly?
12. What are your known limitations, and what would you do with another month?
13. Which part of the code are *you* most familiar with? Walk us through it.
14. What happens if the LLM is down? (template fallback; mock mode)
15. Why is the audit log tamper-evident and not tamper-proof?

Write 2–3 sentence answers to each in `docs/QA_ANSWERS.md` once the build is done.
