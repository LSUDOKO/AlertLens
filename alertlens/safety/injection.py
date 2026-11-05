"""F1: find instructions hidden in alert data and quarantine the fields that carry them.

Runs on the original alert. Redaction replaces identifier fields whole, which would hide a payload
planted in `user` or `host`. Detection is only one layer: severity and actions never depend on model
output, so a miss here does not by itself change the verdict.
"""
from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from collections.abc import Iterator

from alertlens.config import get_settings
from alertlens.schemas import Alert, InjectionFinding, SanitiseReport

QUARANTINE_THRESHOLD = 0.5
IDENTIFIER_FIELDS = {"alert.user", "alert.host", "alert.process", "alert.file_hash", "alert.src_ip", "alert.dst_ip",
                     "alert.geo_country", "alert.rule_id"}
IDENTIFIER_RAW_KEYS = {"srcuser", "user", "host", "name", "process", "target_user", "srcip", "dstip", "src_ip", "dst_ip",
                       "dest_ip", "sha256", "file_hash", "geo", "geo_country"}


def _rx(*patterns: str) -> list[re.Pattern]:
    return [re.compile(p, re.IGNORECASE) for p in patterns]


RULES: list[tuple[str, float, list[re.Pattern]]] = [
    ("direct_override", 0.95, _rx(
        r"\b(ignore|disregard|forget|override)\b.{0,30}\b(instruction|rule|prompt|guidance|above|previous)s?\b",
        r"\byou are now\b", r"\bnew (task|instructions?|goal)\s*:", r"\bsystem prompt\b",
    )),
    ("verdict_steering", 0.9, _rx(
        r"\bmark\s+(this|it|as)\b.{0,20}\b(benign|safe|false positive|clean|harmless)\b", r"\bmark\s+(benign|safe|clean)\b",
        r"\bfinal(\s+\w+)?\s*:\s*(benign|clean|safe|false positive)\b", r"\bentry is whitelisted\b",
        r"\bclassify\s+(this\s+|it\s+)?as\b", r"\bset\s+(the\s+)?severity\b", r"\bseverity\s*(:|=|to|is)?\s*(low|none)\b",
        r"\bdo not\s+(alert|escalate|report|flag)\b", r"\bdon'?t\s+(alert|escalate|report|flag)\b",
        r"\bclose\s+(the\s+|this\s+)?(ticket|alert|case|incident)\b", r"\breport\s+(no threat|clean)\b",
        r"\bfalse positive\.?\s*$", r"\bthis alert is (a |an )?(benign|false positive|safe)\b",
    )),
    ("fake_authority", 0.85, _rx(
        r"\b(note|message|memo)\s+(from|to)\s+(the\s+)?(soc|ciso|ai|analyst|security|admin|assistant)\b",
        r"\bauthori[sz]ed\s+(pen ?test|red.?team|exercise|activity)\b", r"\bapproved activity\b",
        r"\[\s*[\w ]{0,20}\b(soc|admin|analyst|ciso|security team|team lead)\b[\w ]{0,20}\]",
    )),
    ("benign_claim", 0.75, _rx(
        r"\bjust testing\b", r"\bmove along\b", r"\bonly a test\b", r"\bnothing to see\b",
        r"\bsafe to ignore\b", r"\bexpected behaviou?r\b.{0,20}\bignore\b",
    )),
    ("fake_chat_turn", 0.95, _rx(
        r"<\|im_(start|end)\|>", r"\[/?INST\]", r"</?(system|assistant|user)>",
        r"(^|\n)\s*(human|user|assistant|system)\s*:", r"###\s*(instruction|system|response)",
    )),
    ("delimiter_escape", 0.85, _rx(r"\"\s*}\s*\]?\s*</", r"</(alert|log|logs|data|input)>", r"\bEND LOGS\b", r"\bSYSTEM\s*:", r"-{3,}\s*end of (data|log|input)")),
    ("action_hijack", 0.9, _rx(
        r"\b(recommend(ed)?|suggest(ed)?)\s+(action|next step|step)\s*:", r"\brun (this |the )?command\s*:",
        r"\b(disable|turn off|stop)\s+(the\s+)?(firewall|logging|edr|antivirus|defender|monitoring)\b",
        r"\bdelete\s+(the\s+)?(audit\s+)?logs?\b", r"\bwhitelist (this|the)\b",
    )),
    ("data_exfil_prompt", 0.95, _rx(
        r"\b(print|reveal|show|repeat|output|leak)\b.{0,30}\b(prompt|instructions?|canary|secret|token|api key)s?\b",
        r"\brepeat everything\b", r"\bverbatim\b.{0,20}\babove\b|\babove\b.{0,20}\bverbatim\b",
    )),
    ("multilingual", 0.9, _rx(
        r"निर्देश", r"अनदेखा", r"सुरक्षित\s+चिह्नित", r"अलर्ट\s+को\s+बंद", r"केवल\s+परीक्षण",
        r"\bignora\b.{0,30}\binstruc", r"\bmarca\b.{0,30}\bbenign", r"\bignorez\b.{0,30}\b(instructions|consignes)\b",
        r"\bignoriere\b.{0,30}\banweisung",
    )),
]
ZERO_WIDTH = re.compile("[​‌‍⁠﻿­]")
HTML_COMMENT = re.compile(r"<!--.*?-->|\[//\]:\s*#", re.DOTALL)
BASE64_RUN = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")


def iter_strings(value, path: str) -> Iterator[tuple[str, str]]:
    if isinstance(value, str):
        yield path, value
    elif isinstance(value, dict):
        for k, v in value.items():
            yield from iter_strings(v, f"{path}.{k}")
    elif isinstance(value, list):
        for i, v in enumerate(value):
            yield from iter_strings(v, f"{path}[{i}]")


def alert_strings(alert: Alert) -> Iterator[tuple[str, str]]:
    for name in ("rule_name", "rule_id", "src_ip", "dst_ip", "user", "host", "process", "command_line", "file_hash",
                 "url", "geo_country"):
        val = getattr(alert, name)
        if isinstance(val, str):
            yield f"alert.{name}", val
    yield from iter_strings(alert.raw, "raw")


def _preview(text: str, limit: int = 160) -> str:
    return text[:limit] + ("…" if len(text) > limit else "")


def _match_rules(text: str) -> list[tuple[str, float, str]]:
    hits = []
    for family, score, patterns in RULES:
        for pat in patterns:
            if m := pat.search(text):
                hits.append((family, score, m.group(0)))
                break
    return hits


def _decoded_runs(text: str) -> Iterator[str]:
    for m in BASE64_RUN.finditer(text):
        run = m.group(0)
        try:
            data = base64.b64decode(run + "=" * (-len(run) % 4), validate=True)
        except (binascii.Error, ValueError):
            continue
        for enc in ("utf-8", "utf-16-le"):
            try:
                yield data.decode(enc)
            except UnicodeDecodeError:
                continue


def _homoglyph_ratio(text: str) -> float:
    """Share of letters from Cyrillic or Greek inside words that also hold Latin letters."""
    mixed, letters = 0, 0
    for word in text.split():
        scripts = {unicodedata.name(c, "").split(" ")[0] for c in word if c.isalpha()}
        if "LATIN" in scripts and scripts & {"CYRILLIC", "GREEK"}:
            mixed += sum(c.isalpha() for c in word)
        letters += sum(c.isalpha() for c in word)
    return mixed / letters if letters else 0.0


def _is_identifier_path(path: str) -> bool:
    return path in IDENTIFIER_FIELDS or path.rsplit(".", 1)[-1] in IDENTIFIER_RAW_KEYS


def classifier_on() -> bool:
    return get_settings().feature_injection_classifier


def scan_text(path: str, text: str) -> list[InjectionFinding]:
    """Findings for one string value, trying the plain, normalised and decoded forms."""
    found: dict[str, InjectionFinding] = {}

    def add(family: str, score: float, snippet: str) -> None:
        if family not in found or found[family].score < score:
            # Show the payload around the match, so a reader sees the whole hidden message.
            at = stripped.find(snippet)
            context = stripped[max(0, at - 30):] if at >= 0 else snippet
            found[family] = InjectionFinding(field_path=path, pattern_family=family,
                                             matched_text_preview=_preview(context), score=score)

    normal = unicodedata.normalize("NFKC", text)
    stripped = ZERO_WIDTH.sub("", normal)
    for family, score, snippet in _match_rules(stripped):
        add(family, score, snippet)
    if stripped != normal and len(normal) - len(stripped) >= 3:
        # Hidden characters alone are suspicious. A payload behind them is an attack.
        add("zero_width", 0.95 if _match_rules(stripped) else 0.6, stripped)
    if HTML_COMMENT.search(normal):
        add("hidden_markup", 0.7, HTML_COMMENT.search(normal).group(0))
    for decoded in _decoded_runs(stripped):
        if hits := _match_rules(decoded):
            add("encoded", max(0.95, hits[0][1]), decoded)
    if _homoglyph_ratio(stripped) > 0.3:
        add("homoglyph", 0.7, stripped)
    if _is_identifier_path(path):
        words = len(stripped.split())
        if words > 3 or (words > 1 and re.search(r"[.!?,:;]\s", stripped)):
            add("out_of_place_text", 0.6, stripped)
    if classifier_on():
        from alertlens.safety import classifier

        if (p := classifier.score(stripped)) > 0:
            add("learned_classifier", max(p, QUARANTINE_THRESHOLD), stripped)
    return list(found.values())


def scan_alert(alert: Alert) -> SanitiseReport:
    """Scan every string in the alert and report the fields to quarantine.

    A value usually appears twice, parsed and in `raw`. Every copy is quarantined; the UI list keeps one.
    """
    findings: list[InjectionFinding] = []
    seen: set[tuple[str, str]] = set()
    quarantined: set[str] = set()
    survive_by_family: dict[str, float] = {}
    for path, text in alert_strings(alert):
        for f in scan_text(path, text):
            if f.score >= QUARANTINE_THRESHOLD:
                quarantined.add(path)
            survive_by_family[f.pattern_family] = max(survive_by_family.get(f.pattern_family, 0.0), f.score)
            if (f.pattern_family, f.matched_text_preview) not in seen:
                seen.add((f.pattern_family, f.matched_text_preview))
                findings.append(f)
    survive = 1.0
    for score in survive_by_family.values():
        survive *= 1 - score
    return SanitiseReport(findings=findings, risk=round(1 - survive, 4), quarantined_fields=sorted(quarantined))


def is_quarantined(path: str, report: SanitiseReport) -> bool:
    return path in report.quarantined_fields


def mask(path: str) -> str:
    return f"[QUARANTINED:{path}]"
