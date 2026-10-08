"""Unit tests for trust-score-based informational risk classification."""

from decimal import Decimal

import pytest
from app.services.risk_classifier import classify_risk


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (Decimal("0"), "HIGH"),
        (Decimal("20"), "HIGH"),
        (Decimal("39.999"), "HIGH"),
        (Decimal("40"), "MEDIUM"),
        (Decimal("55"), "MEDIUM"),
        (Decimal("69.999"), "MEDIUM"),
        (Decimal("70"), "LOW"),
        (Decimal("94"), "LOW"),
        (Decimal("100"), "LOW"),
    ],
)
def test_classifies_trust_score_boundaries(score: Decimal, expected: str) -> None:
    assert classify_risk(score) == expected


@pytest.mark.parametrize("score", [Decimal("-0.001"), Decimal("100.001"), Decimal("NaN")])
def test_rejects_scores_outside_valid_trust_score_range(score: Decimal) -> None:
    with pytest.raises(ValueError, match="finite value between 0 and 100"):
        classify_risk(score)


def test_rejects_non_decimal_score() -> None:
    with pytest.raises(TypeError, match="must be a Decimal"):
        classify_risk(70)  # type: ignore[arg-type]
