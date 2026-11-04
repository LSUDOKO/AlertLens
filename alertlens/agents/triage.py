"""Triage agent: a first verdict from the facts and calibrated score."""
from alertlens.agents.coordinator import run_agent


def run(payload, provider):
    return run_agent("triage", "Give a first verdict from the score and facts.", payload, provider)
