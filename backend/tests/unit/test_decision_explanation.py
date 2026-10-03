"""Tests for the user-safe Phase 8B decision explanation mapping."""

import pytest
from app.services.decision_explanation import explain_decision


@pytest.mark.parametrize(
    ("decision", "expected"),
    [
        ("ALLOW", "Access is approved."),
        ("STEP_UP", "Additional verification is required to continue."),
        ("BLOCK", "Access is not approved."),
    ],
)
def test_explanation_is_safe_and_deterministic(decision: str, expected: str) -> None:
    first = explain_decision(decision)  # type: ignore[arg-type]

    assert first == expected
    assert explain_decision(decision) == first  # type: ignore[arg-type]
    assert not any(character.isdigit() for character in first)
    assert "trust" not in first.lower()
    assert "score" not in first.lower()
    assert "threshold" not in first.lower()
    assert "weight" not in first.lower()
    assert "device" not in first.lower()
    assert "location" not in first.lower()
    assert "time" not in first.lower()
    assert "factor" not in first.lower()
    assert "policy" not in first.lower()


@pytest.mark.parametrize("decision", ["UNKNOWN", "allow", "", None, []])
def test_unknown_decision_is_rejected(decision: object) -> None:
    with pytest.raises(ValueError, match="Unsupported access decision"):
        explain_decision(decision)  # type: ignore[arg-type]
