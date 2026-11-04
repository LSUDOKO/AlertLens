# 12 — Research References

Papers found on alphaXiv (arXiv preprints, 2026). Use them to justify design choices in the README and the Q&A. **Read the abstract of each one you cite** and describe it in your own words; don't overclaim what a paper says.

| Paper | Link | Supports |
|---|---|---|
| Poisoning the Watchtower: Prompt Injection Attacks Against LLM-Augmented Security Operations Through Adversarial Log Content | https://www.alphaxiv.org/abs/2605.24421 | F1, F11, F26: injection through log content is a real threat |
| Just Testing, Move Along: Evasion of LLM-based System Log Interpretation by Prompt Injection | https://www.alphaxiv.org/abs/2607.24174 | F1, injection families (benign_claim) |
| StateFence: Task-State Protection Against Evidence-Chain Contamination in Blue-Team LLM Agents | https://www.alphaxiv.org/abs/2611.02605 | F12 task-state lock |
| Architecting the Secure AI-SOC: A Neurosymbolic Framework for Pipeline Integrity and Threat Mitigation | https://www.alphaxiv.org/abs/2609.10707 | Overall hybrid (code + LLM) design |
| Constrained-Action AI Remediation for SIEM/XDR via a NeMo-Guardrails Proxy | https://www.alphaxiv.org/abs/2610.09906 | F5, F14 guardrailed actions |
| Beyond the Hype: Evaluating LLM Integration and Practical Limitations in Security Operation Centers | https://www.alphaxiv.org/abs/2608.17154 | Motivation: hallucination and trust |
| From Chasing Ghosts to Missed Attacks: Perspectives of SOC Practitioners on LLM Integration | https://www.alphaxiv.org/abs/2608.00672 | Motivation: practitioner concerns |
| AI-Driven Security Alert Screening and Alert Fatigue Mitigation in SOCs: A Survey | https://www.alphaxiv.org/abs/2605.08316 | Background, F10 triage |
| Towards Agentic Investigation of Security Alerts | https://www.alphaxiv.org/abs/2604.25846 | F9 agentic investigation |
| (EC)²: Event-Centric Explainability for Cybersecurity Through Multi-Agent LLM Investigations | https://www.alphaxiv.org/abs/2607.26201 | F9 multi-agent, F3 explanations |
| AgentSOC: A Multi-Layer Agentic AI Framework for Security Operations Automation | https://www.alphaxiv.org/abs/2604.20134 | F9 architecture |
| From Investigation Failures to Reliable SOC Agents: Understanding and Improving LLM-Based Alert Triage | https://www.alphaxiv.org/abs/2610.10608 | F9, F10 reliability |
| SENTINEL-RL: Offloading Topological Reasoning from LLM Agents in the SOC | https://www.alphaxiv.org/abs/2609.04159 | F7 graph in code, not the LLM |
| HunterAgent: Neuro-Symbolic Attack Trace Reconstruction under Anti-Forensics | https://www.alphaxiv.org/abs/2605.29269 | F6 attack-story reconstruction |
| Integrating Perception, Comprehension, and Projection for Alert Validation | https://www.alphaxiv.org/abs/2610.39849 | F8 projection / next step |
| REFINE: A Resilient Evolution Framework for Intelligent Enterprise Alert Triage | https://www.alphaxiv.org/abs/2609.32516 | F18 feedback and adaptation |
| HESP: Separating What to Probe from When to Stop in Local LLM Alert-Triage Agents | https://www.alphaxiv.org/abs/2609.33446 | Local small models, privacy |
| LanG 2.0: Energy-Efficient Agentic AI for Semi-Automated Security Operations at Scale | https://www.alphaxiv.org/abs/2610.41072 | F20 cost routing |
| Cybersecurity Detection Classification with Reasoning-enabled Language Models | https://www.alphaxiv.org/abs/2607.28460 | F10 classification |

## How to talk about it
- **Good:** "Recent work such as *Poisoning the Watchtower* shows log content can carry prompt injections against SOC assistants. Our dual-LLM split and code-decided severity are designed to blunt that, and our benchmark measures it."
- **Avoid:** "We implemented the StateFence method." Unless you actually read and reproduced it, say "inspired by".

## Standard concepts to read up on (for the Q&A)
- Dual-LLM / quarantined-LLM pattern for prompt-injection defence
- Probability calibration (Platt scaling, isotonic regression, ECE)
- MITRE ATT&CK tactics vs techniques
- Hash chains (tamper evidence)
- TF-IDF and cosine similarity; sentence embeddings
