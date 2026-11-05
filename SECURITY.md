# Security policy

AlertLens is a hackathon project. It uses synthetic data, and its remediation actions are simulated. Do not connect it to real systems or real logs without your own review.

## Report a vulnerability
Use [private vulnerability reporting](https://github.com/LSUDOKO/AlertLens/security/advisories/new). Please don't open a public issue for a security problem. Include the steps to reproduce it and what an attacker could do.

## A bypass counts
These are the reports we most want, with the alert JSON that triggers them:
- An alert that lowers its own severity or auto-closes because of text it carries
- Attacker text that reaches the privileged explainer
- A recommended action that is not in `alertlens/remediation/playbook.yaml`
- A claim shown as verified that the alert does not support

The injection detector missing a reworded attack is a known limitation, not a vulnerability, unless it also causes one of the above.

## Known limits
The API has no login, so it binds to localhost. See "Known limitations" in the [README](README.md).
