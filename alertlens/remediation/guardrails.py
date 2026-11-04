"""F14: the state machine around every action. Nothing here touches a real system."""
from __future__ import annotations


class GuardrailError(ValueError):
    """The requested change is not allowed."""


def next_on_approve(status: str, two_step: bool, approver: str, confirm: bool) -> str:
    """proposed -> approved -> simulated. Two-step actions pass through pending_confirmation first."""
    if not approver or not approver.strip():
        raise GuardrailError("An approver name is required")
    if status == "proposed":
        if two_step and not confirm:
            return "pending_confirmation"
        return "simulated"
    if status == "pending_confirmation":
        if not confirm:
            raise GuardrailError("This high-risk action needs a second confirmation")
        return "simulated"
    raise GuardrailError(f"Cannot approve an action that is {status}")


def next_on_reject(status: str, approver: str) -> str:
    if not approver or not approver.strip():
        raise GuardrailError("An approver name is required")
    if status in {"proposed", "pending_confirmation"}:
        return "rejected"
    raise GuardrailError(f"Cannot reject an action that is {status}")
