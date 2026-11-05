"""F4: check each claim against the facts payload, in placeholder space, before any value is restored."""
from __future__ import annotations

import re

from alertlens.safety.state_lock import tamper_attempt
from alertlens.schemas import Claim, ClaimDraft

_PLACEHOLDER = re.compile(r"<(?:USER|IP|EMAIL|PHONE|HOST|HASH)_\d+>")
_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b")
_TECHNIQUE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
_USERNAME = re.compile(r"\b[\w.-]+\.test\b")
_HOSTNAME = re.compile(r"\b[A-Z]{2,}(?:-[A-Z0-9]+)+\b")
_NUMBER = re.compile(r"(?<![\w.])\d+(?:\.\d+)?(?!\w)(?!\.\d)")
_SEVERITY_WORD = re.compile(r"\b(low|medium|high|critical)\b", re.IGNORECASE)
# Words that must agree with a cited boolean: (pattern, the field value that pattern asserts).
POLARITY = {
    "alert.device_known": (re.compile(r"\b(not known|unknown|unrecogni[sz]ed|new device)\b", re.IGNORECASE), False),
    "alert.geo_usual": (re.compile(r"\b(unusual|new (country|location)|unfamiliar)\b", re.IGNORECASE), False),
    "sanitise.injection_found": (re.compile(r"\b(hidden instructions|injection)\b.{0,20}\bfound\b|\bfound\b.{0,30}\b(hidden instructions|injection)\b",
                                            re.IGNORECASE), True),
}


# Attack stages and conclusions a model likes to guess. Each needs support somewhere in the evidence.
SPECULATION = {
    "lateral movement": ("lateral movement",), "privilege escalation": ("privilege escalation",),
    "exfiltration": ("exfiltration", "data_transfer"), "data theft": ("exfiltration", "data_transfer"),
    "persistence": ("persistence",), "ransomware": ("ransomware", "impact"), "malware": ("malware", "mimikatz", "execution"),
    "insider threat": ("insider",), "credential theft": ("credential access", "mimikatz"),
    "command and control": ("command and control",), "compromised": ("compromis",), "breach": ("breach",),
}
_ADMIN_WORD = re.compile(r"\b(admin|administrator|administrative|root)\b", re.IGNORECASE)
_NOT_ADMIN = re.compile(r"\b(not|non|no|without)\b[\s-]+(?:\w+\s+){0,2}(admin|administrator|administrative|root)\b", re.IGNORECASE)


def unsupported_concept(text: str, evidence: dict[str, object]) -> str | None:
    """Name a guessed conclusion that nothing in the evidence backs up."""
    lowered = text.lower()
    known = " ".join(str(v).lower() for v in evidence.values())
    for phrase, support in SPECULATION.items():
        if phrase in lowered and not any(s in known for s in support):
            return phrase
    if _ADMIN_WORD.search(_NOT_ADMIN.sub(" ", text)) and evidence.get("facts.is_admin_action") is not True and evidence.get("alert.privilege") != "admin":
        return "an admin action"
    return None


def checkable_values(text: str) -> list[str]:
    """Pull out everything a claim states as a concrete fact."""
    values: list[str] = []
    rest = text
    for pattern in (_PLACEHOLDER, _EMAIL, _IP, _TECHNIQUE, _USERNAME, _HOSTNAME):
        values += pattern.findall(rest)
        rest = pattern.sub(" ", rest)
    return values + _NUMBER.findall(rest)


def _in_values(value: str, haystack: list[str]) -> bool:
    return any(value in h for h in haystack)


def _mentions_cited_value(text: str, cited: list[object]) -> bool:
    """True when a cited word-like value (a country code, an enum, a name) appears in the claim."""
    return any(isinstance(v, str) and re.search(rf"\b{re.escape(v)}\b", text, re.IGNORECASE) for v in cited)


def _contradiction(draft: ClaimDraft, evidence: dict[str, object]) -> str | None:
    """Catch a claim that cites a field but states the opposite of its value."""
    for path, (pattern, asserted) in POLARITY.items():
        if path in draft.evidence and path in evidence and bool(pattern.search(draft.text)) != (evidence[path] == asserted):
            return f"disagrees with {path}"
    # A number stated while citing a numeric field must be that field's value, not one found elsewhere.
    numeric = [float(evidence[p]) for p in draft.evidence
               if p in evidence and isinstance(evidence[p], int | float) and not isinstance(evidence[p], bool)]
    stated = [float(n) for n in _NUMBER.findall(_TECHNIQUE.sub(" ", _PLACEHOLDER.sub(" ", draft.text)))]
    if numeric and stated and not set(numeric) & set(stated):
        return "disagrees with the cited number"
    if "severity.label" in draft.evidence and "severity.label" in evidence:
        words = {w.lower() for w in _SEVERITY_WORD.findall(draft.text)}
        if words != {str(evidence["severity.label"])}:
            return "disagrees with severity.label"
    return None


def verify_claim(draft: ClaimDraft, evidence: dict[str, object], label: str) -> Claim:
    """`verified`: every value is in the cited fields. `partially_verified`: found elsewhere, or qualitative only."""
    def result(status: str, reason: str | None = None) -> Claim:
        return Claim(text=draft.text, evidence=draft.evidence, key=draft.key, status=status, reason=reason)

    missing = [p for p in draft.evidence if p not in evidence]
    if not draft.evidence or len(missing) == len(draft.evidence):
        return result("unsupported", "no cited evidence exists")
    if phrase := tamper_attempt(draft.text, label):
        return result("unsupported", f"contradicts the code-decided outcome: {phrase!r}")
    if why := _contradiction(draft, evidence):
        return result("unsupported", why)
    if concept := unsupported_concept(draft.text, evidence):
        return result("unsupported", f"guess with no evidence: {concept}")
    cited_raw = [evidence[p] for p in draft.evidence if p in evidence]
    cited = [str(v) for v in cited_raw]
    everything = [str(v) for v in evidence.values()]
    values = checkable_values(draft.text)
    absent = [v for v in values if not _in_values(v, everything)]
    if absent:
        return result("unsupported", f"not in the alert: {absent[0]}")
    if missing:
        return result("partially_verified", "some cited fields do not exist")
    if not values and not (_mentions_cited_value(draft.text, cited_raw)
                           or any(p in POLARITY for p in draft.evidence if p in evidence)):
        return result("partially_verified", "qualitative statement, nothing concrete to check")
    if [v for v in values if not _in_values(v, cited)]:
        return result("partially_verified", "value exists but not in the cited field")
    return result("verified")


def verify_claims(drafts: list[ClaimDraft], evidence: dict[str, object], label: str) -> tuple[list[Claim], list[Claim], float]:
    """Return (kept claims, removed claims, grounding score)."""
    checked = [verify_claim(d, evidence, label) for d in drafts]
    kept = [c for c in checked if c.status != "unsupported"]
    removed = [c for c in checked if c.status == "unsupported"]
    verified = sum(c.status == "verified" for c in checked)
    return kept, removed, round(verified / len(checked), 4) if checked else 0.0


def vague_summary(summary: str, label: str) -> bool:
    """A summary must at least say how severe the alert is."""
    return label.lower() not in summary.lower()


def verify_prose(text: str, evidence: dict[str, object], label: str) -> str | None:
    """Return why free prose is unsafe to show, or None. Prose has no citations, so it gets the whole payload."""
    if phrase := tamper_attempt(text, label):
        return f"steering language: {phrase!r}"
    if concept := unsupported_concept(text, evidence):
        return f"guess with no evidence: {concept}"
    everything = [str(v) for v in evidence.values()]
    for value in checkable_values(text):
        if not _in_values(value, everything):
            return f"unknown value: {value}"
    return None
