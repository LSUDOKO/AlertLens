"""F16: replace identifiers with stable placeholders before any LLM sees them.

The vault lives for one request. Values come back only in the final rendered output.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

_RE_EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b")
_RE_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_RE_IPV6 = re.compile(r"(?<![\w:])(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{0,4}(?![\w:])")
_RE_PHONE = re.compile(r"(?<![\w.])\+?\d[\d -]{8,}\d(?![\w.])")
_RE_TEST_USER = re.compile(r"\b[\w.-]+\.test\b")
_RE_HOST = re.compile(r"\b(?:WS-\d+|APP-\d+|SRV-\d+|[A-Z]{2,}-[A-Z]{2,}-\d+)\b", re.IGNORECASE)
PLACEHOLDER = re.compile(r"<(USER|IP|EMAIL|PHONE|HOST|HASH)_(\d+)>")


@dataclass
class Vault:
    forward: dict[tuple[str, str], str] = field(default_factory=dict)
    back: dict[str, str] = field(default_factory=dict)
    _counts: dict[str, int] = field(default_factory=dict)

    def token(self, kind: str, value: str) -> str:
        key = (kind, value)
        if key not in self.forward:
            self._counts[kind] = self._counts.get(kind, 0) + 1
            tok = f"<{kind}_{self._counts[kind]}>"
            self.forward[key] = tok
            self.back[tok] = value
        return self.forward[key]

    def restore(self, text: str) -> str:
        return PLACEHOLDER.sub(lambda m: self.back.get(m.group(0), m.group(0)), text)


def redact_text(text: str, vault: Vault) -> str:
    """Regex redaction for free text, keeping values the same across fields."""
    text = _RE_EMAIL.sub(lambda m: vault.token("EMAIL", m.group(0)), text)
    text = _RE_IPV4.sub(lambda m: vault.token("IP", m.group(0)), text)
    text = _RE_IPV6.sub(lambda m: vault.token("IP", m.group(0)), text)
    text = _RE_PHONE.sub(lambda m: vault.token("PHONE", m.group(0)), text)
    text = _RE_TEST_USER.sub(lambda m: vault.token("USER", m.group(0)), text)
    return _RE_HOST.sub(lambda m: vault.token("HOST", m.group(0)), text)


def redact_identifier(kind: str, value: str | None, vault: Vault) -> str | None:
    """Field-aware redaction: the whole value is replaced, whatever it looks like."""
    return vault.token(kind, value) if value else None
