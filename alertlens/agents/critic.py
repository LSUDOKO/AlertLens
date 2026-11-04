"""Critic agent: tries to disprove the verdict by finding the innocent explanation."""
from alertlens.agents.coordinator import run_agent


def run(payload, provider):
    return run_agent("critic", "Try to disprove the verdict. Name benign explanations and missing evidence.",
                     payload, provider)
