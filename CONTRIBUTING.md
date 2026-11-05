# Contributing

## Set up
```bash
make setup
make test
make lint
```
Python 3.11 or 3.12. Everything runs offline, with no API key.

## Rules for changes
- **The LLM never decides severity or runs actions**, and the privileged step never reads raw alert text.
- **Use synthetic data only.** Use reserved addresses such as `192.0.2.0/24` and domains such as `example.com`.
- **Never commit secrets.** `make check-secrets` runs in CI.
- **Add a test** with every feature or fix.
- **Never edit benchmark numbers by hand.** Run `make eval`, then `python -m scripts.fill_readme`.
- **New actions go in** `alertlens/remediation/playbook.yaml`.

## Pull requests
Keep each one to a single change. Describe how you tested it, and make sure CI passes.
