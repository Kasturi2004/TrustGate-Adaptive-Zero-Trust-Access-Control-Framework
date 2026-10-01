"""Unit tests for deterministic Phase 8A policy decisions."""

from decimal import Decimal

import pytest
from app.schemas.policy import PolicyThresholds
from app.services.policy_engine import evaluate_policy
from pydantic import ValidationError

_DEFAULT_THRESHOLDS = PolicyThresholds(
    allow_threshold=Decimal("70.00"),
    stepup_threshold=Decimal("40.00"),
)


@pytest.mark.parametrize(
    ("score", "expected_decision", "expected_reason"),
    [
        (
            Decimal("70.00"),
            "ALLOW",
            "Trust score 70.00 meets the ALLOW threshold 70.00.",
        ),
        (
            Decimal("69.99"),
            "STEP_UP",
            "Trust score 69.99 meets the STEP_UP threshold 40.00 but is below the ALLOW "
            "threshold 70.00.",
        ),
        (
            Decimal("40.00"),
            "STEP_UP",
            "Trust score 40.00 meets the STEP_UP threshold 40.00 but is below the ALLOW "
            "threshold 70.00.",
        ),
        (
            Decimal("39.99"),
            "BLOCK",
            "Trust score 39.99 is below the STEP_UP threshold 40.00.",
        ),
        (
            Decimal("55.25"),
            "STEP_UP",
            "Trust score 55.25 meets the STEP_UP threshold 40.00 but is below the ALLOW "
            "threshold 70.00.",
        ),
        (
            Decimal("0"),
            "BLOCK",
            "Trust score 0 is below the STEP_UP threshold 40.00.",
        ),
        (
            Decimal("100"),
            "ALLOW",
            "Trust score 100 meets the ALLOW threshold 70.00.",
        ),
    ],
)
def test_default_policy_threshold_boundaries_and_explanations(
    score: Decimal,
    expected_decision: str,
    expected_reason: str,
) -> None:
    result = evaluate_policy(score, _DEFAULT_THRESHOLDS)

    assert result.decision == expected_decision
    assert result.decision_reason == expected_reason
    assert result.trust_score is score
    assert result.allow_threshold == Decimal("70.00")
    assert result.stepup_threshold == Decimal("40.00")


def test_policy_evaluation_is_deterministic() -> None:
    first = evaluate_policy(Decimal("69.99"), _DEFAULT_THRESHOLDS)

    assert evaluate_policy(Decimal("69.99"), _DEFAULT_THRESHOLDS) == first


def test_changed_thresholds_change_the_result() -> None:
    thresholds = PolicyThresholds(
        allow_threshold=Decimal("80.00"),
        stepup_threshold=Decimal("50.00"),
    )

    result = evaluate_policy(Decimal("70.00"), thresholds)

    assert result.decision == "STEP_UP"
    assert result.allow_threshold == Decimal("80.00")
    assert result.stepup_threshold == Decimal("50.00")


@pytest.mark.parametrize(
    ("allow_threshold", "stepup_threshold"),
    [
        (Decimal("NaN"), Decimal("40.00")),
        (Decimal("70.00"), Decimal("Infinity")),
        (Decimal("100.01"), Decimal("40.00")),
        (Decimal("70.00"), Decimal("-0.01")),
        (Decimal("40.00"), Decimal("40.00")),
        (Decimal("39.99"), Decimal("40.00")),
        (70.0, Decimal("40.00")),
    ],
)
def test_invalid_threshold_configuration_is_rejected(
    allow_threshold: Decimal,
    stepup_threshold: Decimal,
) -> None:
    with pytest.raises(ValidationError):
        PolicyThresholds(
            allow_threshold=allow_threshold,
            stepup_threshold=stepup_threshold,
        )


@pytest.mark.parametrize("score", [Decimal("-0.01"), Decimal("100.01"), Decimal("NaN")])
def test_out_of_range_or_non_finite_trust_scores_are_rejected(score: Decimal) -> None:
    with pytest.raises(ValueError, match="finite value between 0 and 100"):
        evaluate_policy(score, _DEFAULT_THRESHOLDS)


def test_float_trust_score_is_rejected() -> None:
    with pytest.raises(TypeError, match="must be a Decimal"):
        evaluate_policy(70.0, _DEFAULT_THRESHOLDS)  # type: ignore[arg-type]
