"""Cross-model check: a second, different model reviews the explainer's claims.

It can only remove claims. It cannot add claims, change severity or pick actions, so a fooled or broken
judge can make an explanation shorter but never more wrong.
"""
from __future__ import annotations

import json
import secrets

from pydantic import BaseModel, ConfigDict, Field

from alertlens.llm.provider import LLMProvider, call_structured
from alertlens.llm.quarantined import load_prompt
from alertlens.safety.canary import leaked
from alertlens.schemas import Claim


class JudgeItem(BaseModel):
    model_config = ConfigDict(extra="forbid")
    index: int = Field(ge=0)
    supported: bool
    reason: str = Field(default="", max_length=160)


class JudgeVerdict(BaseModel):
    model_config = ConfigDict(extra="forbid")
    verdicts: list[JudgeItem] = []


def judge_template(user: str) -> JudgeVerdict:
    """Offline stand-in: it supports every claim, so with the mock provider the judge never removes anything."""
    claims = json.loads(user.split("<<CLAIMS>>")[1].split("<<END-CLAIMS>>")[0]) if "<<CLAIMS>>" in user else []
    return JudgeVerdict(verdicts=[JudgeItem(index=i, supported=True, reason="offline stand-in") for i in range(len(claims))])


def judge_claims(evidence: dict[str, object], claims: list[Claim], provider: LLMProvider) -> tuple[list[Claim], list[Claim], dict]:
    """Return (kept, removed, report). A claim is removed only when the judge says it is unsupported."""
    if not claims:
        return claims, [], {}
    version, template = load_prompt("judge")
    canary = f"CANARY-{secrets.token_hex(4)}"
    system = template.format(canary=canary)
    listed = [{"index": i, "text": c.text, "evidence": c.evidence} for i, c in enumerate(claims)]
    user = (f"<<FACTS>>{json.dumps(evidence, ensure_ascii=False, default=str)}<<END-FACTS>>\n"
            f"<<CLAIMS>>{json.dumps(listed, ensure_ascii=False)}<<END-CLAIMS>>")
    call = call_structured(provider, system, user, JudgeVerdict, lambda: judge_template(user), max_tokens=400,
                           extra_check=lambda text, _: "prompt_leak" if leaked(text, canary) else None)
    unsupported = {v.index: v.reason for v in call.value.verdicts if not v.supported and v.index < len(claims)}
    kept, removed = [], []
    for i, c in enumerate(claims):
        if i in unsupported:
            removed.append(c.model_copy(update={"status": "unsupported", "reason": f"cross-model check: {unsupported[i] or 'not supported'}"}))
        else:
            kept.append(c)
    report = {"provider": call.provider, "model": call.model, "prompt_version": version, "checked": len(claims),
              "removed": len(removed), "fallback": call.fallback}
    return kept, removed, report
