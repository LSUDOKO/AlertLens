"""Investigator agent: supporting evidence from correlated alerts and similar cases."""
from alertlens.agents.coordinator import run_agent


def run(payload, provider):
    return run_agent("investigator", "Gather evidence from the context and similar cases.", payload, provider)
