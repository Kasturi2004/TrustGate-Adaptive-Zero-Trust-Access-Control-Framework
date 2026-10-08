"""Classify calculated trust scores for informational risk reporting."""

from decimal import Decimal
from typing import Literal

RiskClassification = Literal["LOW", "MEDIUM", "HIGH"]


def classify_risk(trust_score: Decimal) -> RiskClassification:
    """Map a validated Trust Score to its informational risk classification."""
    if not isinstance(trust_score, Decimal):
        raise TypeError("Trust score must be a Decimal")
    if not trust_score.is_finite() or not Decimal("0") <= trust_score <= Decimal("100"):
        raise ValueError("Trust score must be a finite value between 0 and 100")

    if trust_score >= Decimal("70"):
        return "LOW"
    if trust_score >= Decimal("40"):
        return "MEDIUM"
    return "HIGH"
