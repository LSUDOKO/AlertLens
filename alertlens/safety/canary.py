"""F13: a random token in each system prompt. If it shows up in output, the prompt leaked."""
from __future__ import annotations


def leaked(output: str, canary: str) -> bool:
    return bool(canary) and canary in output
