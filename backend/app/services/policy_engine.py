"""Pure policy decision evaluation using a server-side trust score."""

from decimal import Decimal

from app.schemas.access import AccessDecision
from app.schemas.policy import PolicyDecisionResult, PolicyThresholds


def evaluate_policy(trust_score: Decimal, thresholds: PolicyThresholds) -> PolicyDecisionResult:
    """Map a Phase 7 trust score to a decision using supplied policy thresholds."""
    if not isinstance(trust_score, Decimal):
        raise TypeError("Trust score must be a Decimal")
    if not trust_score.is_finite() or not Decimal("0") <= trust_score <= Decimal("100"):
        raise ValueError("Trust score must be a finite value between 0 and 100")

    allow_threshold = thresholds.allow_threshold
    stepup_threshold = thresholds.stepup_threshold
    decision: AccessDecision
    if trust_score >= allow_threshold:
        decision = "ALLOW"
        reason = f"Trust score {trust_score:f} meets the ALLOW threshold {allow_threshold:f}."
    elif trust_score >= stepup_threshold:
        decision = "STEP_UP"
        reason = (
            f"Trust score {trust_score:f} meets the STEP_UP threshold "
            f"{stepup_threshold:f} but is below the ALLOW threshold {allow_threshold:f}."
        )
    else:
        decision = "BLOCK"
        reason = f"Trust score {trust_score:f} is below the STEP_UP threshold {stepup_threshold:f}."

    return PolicyDecisionResult(
        decision=decision,
        decision_reason=reason,
        trust_score=trust_score,
        allow_threshold=allow_threshold,
        stepup_threshold=stepup_threshold,
    )
