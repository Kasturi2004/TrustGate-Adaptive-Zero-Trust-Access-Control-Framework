"""User-safe explanations for final access decision categories."""

from app.schemas.access import AccessDecision

_EXPLANATIONS: dict[AccessDecision, str] = {
    "ALLOW": "Access is approved.",
    "STEP_UP": "Additional verification is required to continue.",
    "BLOCK": "Access is not approved.",
}


def explain_decision(decision: AccessDecision) -> str:
    """Return a stable, user-safe explanation for a final decision category."""
    if not isinstance(decision, str) or decision not in _EXPLANATIONS:
        raise ValueError("Unsupported access decision.") from None
    return _EXPLANATIONS[decision]
