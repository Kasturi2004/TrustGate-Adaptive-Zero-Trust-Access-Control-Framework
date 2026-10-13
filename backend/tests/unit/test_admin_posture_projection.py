"""Tests for the safe admin projection of persisted posture evidence."""

from app.services.admin_queries import _admin_posture_assessment


def test_admin_posture_projection_keeps_coverage_and_safe_reasons_only() -> None:
    result = _admin_posture_assessment(
        {
            "version": "posture-v1",
            "classification": "PARTIAL",
            "score": None,
            "complete": False,
            "reason_codes": ["provider_unavailable", "personal@example.invalid"],
            "evidence": [
                {
                    "check": "os_patch_compliance",
                    "state": "UNKNOWN",
                    "source": "provider-secret-label",
                    "observed_at": None,
                    "validation_status": "UNVERIFIED",
                    "device_binding": "sensitive-device-binding",
                    "binding_status": "NOT_OBSERVED",
                    "reason_code": "provider_unavailable",
                }
            ],
        }
    )

    assert result is not None
    assert result.classification == "PARTIAL"
    assert result.score is None
    assert result.verified_evidence_count == 0
    assert result.total_evidence_count == 5
    assert result.reason_codes == ["provider_unavailable"]
    assert result.evidence[0].state == "UNKNOWN"
    assert result.evidence[0].validation_status == "UNVERIFIED"
    serialized = result.model_dump_json()
    assert "sensitive-device-binding" not in serialized
    assert "provider-secret-label" not in serialized
    assert "personal@example.invalid" not in serialized


def test_admin_posture_projection_rejects_inconsistent_or_legacy_assessments() -> None:
    assert _admin_posture_assessment({"version": "legacy", "classification": "HEALTHY"}) is None
    assert (
        _admin_posture_assessment({"version": "posture-v1", "classification": "verified"}) is None
    )
    assert _admin_posture_assessment({"version": "posture-v1", "classification": []}) is None
