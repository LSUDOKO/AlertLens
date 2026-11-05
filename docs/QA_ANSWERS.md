# Q&A answers

Draft answers. Check each against the code, and say them in your own words. Numbers are in `results/benchmark_report.md`.

**1. Why not let the LLM decide severity?** A log field can argue with a model, but it can't argue with arithmetic. In our ablation, handing severity to a model that reads the raw alert took attack success to 100% on the simulated model. Code also gives the same answer every time.

**2. How does dual-LLM stop injection, and what gets through?** Only the quarantined extractor reads free text, and its output is limited to enums and numbers. The explainer sees validated facts and placeholders, tested with a check that no 21-character substring of a payload reaches its prompt. The extractor can still lie inside the enums, so code overrides it on conflict; where code has no answer, such as `target_count`, a lie can reach the explanation.

**3. How was training data built? Is synthetic data a weakness?** Fifteen-plus seeded scenarios with overlap between benign and malicious, plus 3% label noise. Yes, it's a weakness: we wrote the data and the features, so the F1 is optimistic and says nothing about a real SOC. We use it to prove the mechanism, not field accuracy.

**4. How do you know explanations aren't hallucinated?** Each claim must cite fields. The verifier extracts IPs, names, numbers and technique IDs, checks they appear in the cited fields, and removes claims that fail. It also checks the polarity of a few booleans. It can't judge purely qualitative wording, so those claims show as partially verified.

**5. What is calibration, and why does it matter?** A calibrated 0.8 means about 80% of such alerts are malicious. Triage uses fixed probability cut-offs, so they only mean something if the probabilities do. We use sigmoid calibration and report ECE and a reliability plot.

**6. How does correlation decide alerts are related? Failure cases?** Union-find over shared users, IPs, hosts, hashes and domains within 30 minutes. Low-level alerts don't link, and a host used by two different accounts doesn't link. Precision is our weakest number: attackers reusing an address get merged, and slow attacks beyond the window split.

**7. What about languages or encodings you didn't anticipate?** The detector will often miss them. Rules alone caught 34.8% of held-out paraphrases; rules plus the classifier catch 56.5%, far below recall on our templates. That's why detection isn't the main defence. A missed payload still never reaches the explainer or changes the score.

**8. Why a fixed playbook?** A model can't recommend what isn't there, so "disable the firewall" is impossible by construction. The cost is flexibility: new responses need a person to add them. Model suggestions can only reorder valid actions.

**9. How would this connect to a real SIEM?** Add an adapter for its JSON, feed alerts to `/analyze` or `/analyze/batch`, and load the rule catalogue from SIEM metadata. We haven't connected to one, and real feeds would need retraining and threshold tuning.

**10. How does it scale to 10,000 alerts a day?** Most alerts take the fast path with no LLM call, and in-process cost is milliseconds per alert. SQLite and the single process would be the limits, so production would need Postgres and a queue. We have not load-tested this.

**11. What does the feedback loop change?** Corrections are added to training with extra weight, the model is retrained, and rule weights shift by precision, within 0.5 to 1.5. A planted mislabelled pattern shows before and after. There's no defence yet against a malicious analyst poisoning feedback, beyond the audit record.

**12. Known limitations, and another month?** Synthetic data, no real-model benchmark yet, weak recall on novel payloads, moderate correlation precision. Next: real-model runs, a real labelled data set, an injection classifier, signed audit anchors, API authentication.

**13. Which part do you know best?** Each member answers personally. Open the file and walk through one function.

**14. What if the LLM is down?** Each call retries once, then falls back to a code template with a visible badge. Severity and actions don't depend on the LLM. A test covers this with a provider that raises connection errors.

**15. Why tamper-evident and not tamper-proof?** Each record hashes the previous one, so editing or removing a middle record breaks the chain at that point. Someone with write access can still rewrite the whole chain or cut records off the end, and a test documents that. Fixing it needs an external anchor, such as publishing the head hash.

**Why not make the classifier catch more?** Our first version caught 95.7% of held-out paraphrases, but it also flagged 11 of 24 ordinary log lines. It had learned that a sentence in a log is an attack. We added clean log text to training and kept the lower score. A false alarm raises severity and blocks auto-close, so it has a real cost.

**How do you know the real model's output is safe to show?** The Analyze page and the Red-Team Lab both have a "What the model tried" panel with the raw replies and what code changed. On llama3.2 the verifier removed claims that copied numbers from elsewhere or guessed at attack stages.

