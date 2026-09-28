import asyncio
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import cast
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

from app.db.models.access_request import AccessRequest
from app.db.models.context_signal import ContextSignal
from app.db.models.device import Device
from app.db.models.otp_challenge import OtpChallenge
from app.db.models.policy_decision import PolicyDecision
from app.db.models.policy_version import PolicyVersion
from app.db.models.profile import Profile
from app.db.models.rate_limit_state import RateLimitState
from app.db.models.security_event import SecurityEvent
from app.db.models.trust_evaluation import TrustEvaluation
from app.db.models.trust_factor import TrustFactor
from app.db.repositories import DeviceRepository, ProfileRepository
from app.db.repositories.access_request import AccessRequestRepository
from app.db.repositories.context_signal import ContextSignalRepository
from app.db.repositories.otp_challenge import OtpChallengeRepository
from app.db.repositories.policy_decision import PolicyDecisionRepository
from app.db.repositories.policy_version import PolicyVersionRepository
from app.db.repositories.rate_limit_state import RateLimitStateRepository
from app.db.repositories.security_event import SecurityEventRepository
from app.db.repositories.trust_evaluation import TrustEvaluationRepository
from app.db.repositories.trust_factor import TrustFactorRepository
from sqlalchemy.dialects import postgresql
from sqlalchemy.ext.asyncio import AsyncSession


def _mock_session() -> AsyncMock:
    return AsyncMock(spec=AsyncSession)


def test_profile_repository_get_by_id_uses_existing_session() -> None:
    session = _mock_session()
    profile = cast(Profile, object())
    user_id = uuid4()
    session.get.return_value = profile

    result = asyncio.run(ProfileRepository(session).get_by_id(user_id))

    assert result is profile
    session.get.assert_awaited_once_with(Profile, user_id)


def test_profile_repository_get_by_email_returns_first_match() -> None:
    session = _mock_session()
    result = MagicMock()
    profile = cast(Profile, object())
    result.first.return_value = profile
    session.scalars.return_value = result

    found = asyncio.run(ProfileRepository(session).get_by_email("user@example.test"))

    assert found is profile
    statement = session.scalars.await_args.args[0]
    assert "profiles.email =" in str(statement)


def test_device_repository_queries_by_owner_and_hash() -> None:
    session = _mock_session()
    scalar_result = MagicMock()
    device = cast(Device, object())
    scalar_result.first.return_value = device
    session.scalars.return_value = scalar_result
    user_id = uuid4()

    found = asyncio.run(DeviceRepository(session).get_by_user_and_hash(user_id, "device-hash"))

    assert found is device
    statement = session.scalars.await_args.args[0]
    assert "devices.user_id =" in str(statement)
    assert "devices.device_hash =" in str(statement)


def test_device_repository_lists_in_stable_order() -> None:
    session = _mock_session()
    scalar_result = MagicMock()
    devices = [cast(Device, object()), cast(Device, object())]
    scalar_result.all.return_value = devices
    session.scalars.return_value = scalar_result

    found = asyncio.run(DeviceRepository(session).list_by_user(uuid4()))

    assert found == devices
    statement = session.scalars.await_args.args[0]
    assert "ORDER BY public.devices.first_seen_at, public.devices.id" in str(statement)


def test_device_repository_add_stages_record_without_committing() -> None:
    session = _mock_session()
    device = cast(Device, object())

    DeviceRepository(session).add(device)

    session.add.assert_called_once_with(device)
    session.commit.assert_not_awaited()


def test_device_repository_updates_only_last_seen() -> None:
    session = _mock_session()
    now = datetime.now(UTC)
    device = Device(
        id=uuid4(),
        user_id=uuid4(),
        device_hash="device-hash",
        first_seen_at=now,
        last_seen_at=now,
        recognized_at=None,
        last_user_agent_family="browser",
        last_user_agent_version="1",
    )
    session.get.return_value = device

    result = asyncio.run(DeviceRepository(session).update_last_seen(device.id, now))

    assert result is device
    assert device.last_seen_at == now
    assert device.first_seen_at == now
    assert device.recognized_at is None
    assert device.last_user_agent_family == "browser"
    assert device.last_user_agent_version == "1"
    session.commit.assert_not_awaited()


def test_device_repository_update_last_seen_returns_none_when_missing() -> None:
    session = _mock_session()
    session.get.return_value = None

    result = asyncio.run(DeviceRepository(session).update_last_seen(uuid4(), datetime.now(UTC)))

    assert result is None


def test_access_request_repository_get_by_id() -> None:
    session = _mock_session()
    access_request = cast(AccessRequest, object())
    access_request_id = uuid4()
    session.get.return_value = access_request

    found = asyncio.run(AccessRequestRepository(session).get_by_id(access_request_id))

    assert found is access_request
    session.get.assert_awaited_once_with(AccessRequest, access_request_id)


def test_access_request_repository_lists_newest_first_deterministically() -> None:
    session = _mock_session()
    scalar_result = MagicMock()
    access_requests = [cast(AccessRequest, object())]
    scalar_result.all.return_value = access_requests
    session.scalars.return_value = scalar_result

    found = asyncio.run(AccessRequestRepository(session).list_by_user(uuid4()))

    assert found == access_requests
    statement = session.scalars.await_args.args[0]
    assert "ORDER BY public.access_requests.requested_at DESC, public.access_requests.id" in str(
        statement
    )


def test_access_request_repository_add_and_final_outcome_scope() -> None:
    session = _mock_session()
    access_request = cast(AccessRequest, SimpleNamespace(final_outcome=None, resolved_at=None))
    access_request_id = uuid4()
    session.get.return_value = access_request
    repository = AccessRequestRepository(session)

    repository.add(access_request)
    found = asyncio.run(repository.set_final_outcome(access_request_id, "ALLOW"))

    assert found is access_request
    assert access_request.final_outcome == "ALLOW"
    assert access_request.resolved_at is None
    session.add.assert_called_once_with(access_request)
    session.commit.assert_not_awaited()


def test_context_signal_repository_gets_by_access_request_and_adds() -> None:
    session = _mock_session()
    scalar_result = MagicMock()
    context_signal = cast(ContextSignal, object())
    scalar_result.first.return_value = context_signal
    session.scalars.return_value = scalar_result
    access_request_id = uuid4()
    repository = ContextSignalRepository(session)

    found = asyncio.run(repository.get_by_access_request(access_request_id))
    repository.add(context_signal)

    assert found is context_signal
    assert "context_signals.access_request_id =" in str(session.scalars.await_args.args[0])
    session.add.assert_called_once_with(context_signal)
    assert not hasattr(repository, "update")
    assert not hasattr(repository, "delete")
    session.commit.assert_not_awaited()


def test_trust_evaluation_repository_queries_and_adds() -> None:
    session = _mock_session()
    evaluation = cast(TrustEvaluation, object())
    session.get.return_value = evaluation
    scalar_result = MagicMock()
    scalar_result.first.return_value = evaluation
    session.scalars.return_value = scalar_result
    evaluation_id = uuid4()
    access_request_id = uuid4()
    repository = TrustEvaluationRepository(session)

    assert asyncio.run(repository.get_by_id(evaluation_id)) is evaluation
    assert asyncio.run(repository.get_by_access_request(access_request_id)) is evaluation
    repository.add(evaluation)

    session.get.assert_awaited_once_with(TrustEvaluation, evaluation_id)
    assert "trust_evaluations.access_request_id =" in str(session.scalars.await_args.args[0])
    session.add.assert_called_once_with(evaluation)
    assert not hasattr(repository, "update")
    assert not hasattr(repository, "delete")
    session.commit.assert_not_awaited()


def test_trust_factor_repository_lists_and_adds_many() -> None:
    session = _mock_session()
    scalar_result = MagicMock()
    factors = [cast(TrustFactor, object()), cast(TrustFactor, object())]
    scalar_result.all.return_value = factors
    session.scalars.return_value = scalar_result
    evaluation_id = uuid4()
    repository = TrustFactorRepository(session)

    found = asyncio.run(repository.list_by_evaluation(evaluation_id))
    repository.add_many(factors)

    assert found == factors
    statement = session.scalars.await_args.args[0]
    assert "trust_factors.trust_evaluation_id =" in str(statement)
    assert "ORDER BY public.trust_factors.factor_name, public.trust_factors.id" in str(statement)
    session.add_all.assert_called_once_with(factors)
    assert not hasattr(repository, "update")
    assert not hasattr(repository, "delete")
    session.commit.assert_not_awaited()


def test_policy_version_repository_get_active() -> None:
    session = _mock_session()
    scalar_result = MagicMock()
    policy_version = cast(PolicyVersion, object())
    scalar_result.first.return_value = policy_version
    session.scalars.return_value = scalar_result
    repository = PolicyVersionRepository(session)

    found = asyncio.run(repository.get_active())

    assert found is policy_version
    assert "policy_versions.is_active IS true" in str(session.scalars.await_args.args[0])
    assert not hasattr(repository, "update")
    assert not hasattr(repository, "delete")
    session.commit.assert_not_awaited()


def test_policy_version_repository_get_by_label() -> None:
    session = _mock_session()
    scalar_result = MagicMock()
    policy_version = cast(PolicyVersion, object())
    scalar_result.first.return_value = policy_version
    session.scalars.return_value = scalar_result
    repository = PolicyVersionRepository(session)

    found = asyncio.run(repository.get_by_label("POL-1.0"))

    assert found is policy_version
    assert "policy_versions.version_label =" in str(session.scalars.await_args.args[0])
    assert not hasattr(repository, "update")
    assert not hasattr(repository, "delete")
    session.commit.assert_not_awaited()


def test_policy_decision_repository_get_by_access_request_is_deterministic() -> None:
    session = _mock_session()
    scalar_result = MagicMock()
    policy_decision = cast(PolicyDecision, object())
    scalar_result.first.return_value = policy_decision
    session.scalars.return_value = scalar_result
    repository = PolicyDecisionRepository(session)

    found = asyncio.run(repository.get_by_access_request(uuid4()))

    assert found is policy_decision
    statement = session.scalars.await_args.args[0]
    assert "policy_decisions.access_request_id =" in str(statement)
    assert "ORDER BY public.policy_decisions.decided_at DESC, public.policy_decisions.id" in str(
        statement
    )
    assert not hasattr(repository, "update")
    assert not hasattr(repository, "delete")
    session.commit.assert_not_awaited()


def test_policy_decision_repository_add_is_append_only() -> None:
    session = _mock_session()
    policy_decision = cast(PolicyDecision, object())
    repository = PolicyDecisionRepository(session)

    repository.add(policy_decision)

    session.add.assert_called_once_with(policy_decision)
    assert not hasattr(repository, "update")
    assert not hasattr(repository, "delete")
    session.commit.assert_not_awaited()


def test_otp_challenge_repository_get_pending_for_update_locks_row() -> None:
    session = _mock_session()
    scalar_result = MagicMock()
    challenge = cast(OtpChallenge, object())
    scalar_result.first.return_value = challenge
    session.scalars.return_value = scalar_result
    repository = OtpChallengeRepository(session)

    found = asyncio.run(repository.get_pending_for_update(uuid4()))

    assert found is challenge
    statement = session.scalars.await_args.args[0]
    sql = str(statement.compile(dialect=postgresql.dialect()))  # type: ignore[no-untyped-call]
    assert "status = %(status_1)s" in sql
    assert "FOR UPDATE" in sql
    assert not hasattr(repository, "update")
    assert not hasattr(repository, "delete")
    session.commit.assert_not_awaited()


def test_otp_challenge_repository_adds_supplied_instance_only() -> None:
    session = _mock_session()
    challenge = cast(OtpChallenge, object())
    repository = OtpChallengeRepository(session)

    repository.add(challenge)

    session.add.assert_called_once_with(challenge)
    assert not hasattr(repository, "update")
    assert not hasattr(repository, "delete")
    session.commit.assert_not_awaited()


def test_otp_challenge_repository_update_status_changes_only_status() -> None:
    session = _mock_session()
    challenge = cast(
        OtpChallenge,
        SimpleNamespace(status="PENDING", attempt_count=1, verified_at=None),
    )
    challenge_id = uuid4()
    session.get.return_value = challenge
    repository = OtpChallengeRepository(session)

    found = asyncio.run(repository.update_status(challenge_id, "SUCCESS"))

    assert found is challenge
    assert challenge.status == "SUCCESS"
    assert challenge.attempt_count == 1
    assert challenge.verified_at is None
    session.get.assert_awaited_once_with(OtpChallenge, challenge_id)
    assert not hasattr(repository, "update")
    assert not hasattr(repository, "delete")
    session.commit.assert_not_awaited()


def test_rate_limit_repository_get_for_update_locks_row() -> None:
    session = _mock_session()
    scalar_result = MagicMock()
    state = cast(RateLimitState, object())
    scalar_result.first.return_value = state
    session.scalars.return_value = scalar_result
    repository = RateLimitStateRepository(session)

    found = asyncio.run(repository.get_for_update("mfa_resend:test"))

    assert found is state
    statement = session.scalars.await_args.args[0]
    sql = str(statement.compile(dialect=postgresql.dialect()))  # type: ignore[no-untyped-call]
    assert "rate_limit_state.key = %(key_1)s" in sql
    assert "FOR UPDATE" in sql
    session.commit.assert_not_awaited()


def test_rate_limit_repository_add_or_update_uses_model_fields() -> None:
    session = _mock_session()
    scalar_result = MagicMock()
    session.scalars.return_value = scalar_result
    now = datetime.now(UTC)
    state = cast(
        RateLimitState,
        SimpleNamespace(
            key="mfa_resend:test",
            counter=2,
            window_reset_at=now,
            updated_at=now,
        ),
    )
    repository = RateLimitStateRepository(session)

    asyncio.run(repository.add_or_update(state))

    session.scalars.assert_awaited_once()
    sql = str(
        session.scalars.await_args.args[0].compile(dialect=postgresql.dialect())  # type: ignore[no-untyped-call]
    )
    assert "ON CONFLICT (key) DO UPDATE" in sql
    assert "counter = excluded.counter" in sql
    assert "window_reset_at = excluded.window_reset_at" in sql
    assert "updated_at = excluded.updated_at" in sql
    assert "RETURNING public.rate_limit_state.key" in sql
    assert session.scalars.await_args.kwargs["execution_options"] == {"populate_existing": True}
    scalar_result.all.assert_called_once_with()
    session.commit.assert_not_awaited()


def test_security_event_repository_add_is_append_only() -> None:
    session = _mock_session()
    security_event = cast(SecurityEvent, object())
    repository = SecurityEventRepository(session)

    repository.add(security_event)

    session.add.assert_called_once_with(security_event)
    assert not hasattr(repository, "update")
    assert not hasattr(repository, "delete")
    session.commit.assert_not_awaited()


def test_security_event_repository_list_filters_and_orders_deterministically() -> None:
    session = _mock_session()
    scalar_result = MagicMock()
    events = [cast(SecurityEvent, object()), cast(SecurityEvent, object())]
    scalar_result.all.return_value = events
    session.scalars.return_value = scalar_result
    actor_id = uuid4()
    access_request_id = uuid4()
    created_after = datetime(2026, 9, 1, tzinfo=UTC)
    created_before = datetime(2026, 9, 28, tzinfo=UTC)
    repository = SecurityEventRepository(session)

    found = asyncio.run(
        repository.list(
            event_type="ACCESS_BLOCKED",
            actor_id=actor_id,
            access_request_id=access_request_id,
            created_after=created_after,
            created_before=created_before,
        )
    )

    assert found == events
    statement = session.scalars.await_args.args[0]
    sql = str(statement)
    assert "security_events.event_type =" in sql
    assert "security_events.actor_id =" in sql
    assert "security_events.access_request_id =" in sql
    assert "security_events.created_at >=" in sql
    assert "security_events.created_at <=" in sql
    assert "ORDER BY public.security_events.created_at DESC, public.security_events.id DESC" in sql
    assert not hasattr(repository, "update")
    assert not hasattr(repository, "delete")
    session.commit.assert_not_awaited()
