"""Access gateway orchestration and atomic persistence boundary."""

from collections.abc import Mapping
from dataclasses import dataclass, fields, is_dataclass, replace
from decimal import Decimal
from ipaddress import IPv4Address, IPv6Address, ip_address
from typing import Literal, Protocol
from uuid import UUID, uuid4

from sqlalchemy.ext.asyncio import AsyncSession
from starlette.requests import Request

from app.api.deps import AuthenticatedPrincipal
from app.core.clock import Clock
from app.core.config import Settings
from app.db.models.access_request import AccessRequest
from app.db.models.context_signal import ContextSignal
from app.db.models.device import Device
from app.db.models.policy_decision import PolicyDecision
from app.db.models.profile import Profile
from app.db.models.trust_evaluation import TrustEvaluation
from app.db.models.trust_factor import TrustFactor
from app.db.repositories.access_request import AccessRequestRepository
from app.db.repositories.context_signal import ContextSignalRepository
from app.db.repositories.device import DeviceRepository
from app.db.repositories.policy_decision import PolicyDecisionRepository
from app.db.repositories.trust_evaluation import TrustEvaluationRepository
from app.db.repositories.trust_factor import TrustFactorRepository
from app.services.context.collector import ContextSnapshot, collect_context_snapshot
from app.services.context.location import GeoResolver
from app.services.protected_resource import ProtectedResource
from app.services.security_events import record_event

Decision = Literal["ALLOW", "STEP_UP", "BLOCK"]
RiskClassification = Literal["LOW", "MEDIUM", "HIGH"]
FactorName = Literal[
    "device_familiarity",
    "device_health",
    "location_normality",
    "time_normality",
]
DeviceFamiliarity = Literal["known_device", "unknown_device"]
DeviceHealth = Literal["healthy", "partially_healthy", "unhealthy"]
LocationSignal = Literal["expected_region", "new_region", "unavailable"]
TimeSignal = Literal["within_normal_window", "outside_normal_window"]
IPAddress = IPv4Address | IPv6Address

_EXPECTED_FACTORS = {
    "device_familiarity",
    "device_health",
    "location_normality",
    "time_normality",
}
_ACCESS_EVENT_TYPES: dict[Decision, str] = {
    "ALLOW": "ACCESS_ALLOWED",
    "STEP_UP": "ACCESS_STEPUP",
    "BLOCK": "ACCESS_BLOCKED",
}


@dataclass(frozen=True, slots=True)
class DeviceResult:
    """Device identity and metadata produced by a server-side pipeline."""

    device_hash: str
    last_user_agent_family: str | None
    last_user_agent_version: str | None


@dataclass(frozen=True, slots=True)
class ContextResult:
    """Context values produced by a pipeline; this module does not collect them."""

    device_familiarity_raw: DeviceFamiliarity
    device_health_raw: DeviceHealth
    location_raw: LocationSignal
    time_raw: TimeSignal
    resolved_region: str | None
    raw_context: Mapping[str, object]


@dataclass(frozen=True, slots=True)
class TrustFactorResult:
    """One server-produced trust-factor row."""

    factor_name: FactorName
    raw_value: str
    normalized_score: Decimal
    weight: Decimal
    weighted_contribution: Decimal


@dataclass(frozen=True, slots=True)
class CompletePipelineResult:
    """Complete server-side output needed for the eight application rows."""

    device: DeviceResult
    context: ContextResult | ContextSnapshot
    policy_version_id: UUID
    trust_score: Decimal
    risk_classification: RiskClassification
    factors: tuple[TrustFactorResult, ...]
    decision: Decision
    decision_reason: str
    explanation: str


@dataclass(frozen=True, slots=True)
class FailClosedPipelineResult:
    """Fail-safe outcome before the real context and evaluation stages exist."""

    explanation: str = "Access evaluation is unavailable; the request was blocked."


PipelineResult = CompletePipelineResult | FailClosedPipelineResult


class SecurityPipeline(Protocol):
    """Server pipeline contract.

    Implementations must return a complete server-derived result or an
    explicit degraded result. They must never infer an allow/step-up decision
    from missing pipeline stages.
    """

    async def run(
        self,
        *,
        principal: AuthenticatedPrincipal,
        resource: ProtectedResource,
        device_token: str,
        client_ip: str,
        user_agent: str | None,
        context_snapshot: ContextSnapshot | None = None,
    ) -> PipelineResult:
        """Return complete server output or the decision-free fail-safe result."""


class FailClosedSecurityPipeline:
    """Default pipeline until Phases 6–8 provide real evaluation stages.

    This implementation deliberately has no trust, context, policy, or
    decision logic; its result can only be interpreted as BLOCK by the
    gateway.
    """

    async def run(
        self,
        *,
        principal: AuthenticatedPrincipal,
        resource: ProtectedResource,
        device_token: str,
        client_ip: str,
        user_agent: str | None,
        context_snapshot: ContextSnapshot | None = None,
    ) -> FailClosedPipelineResult:
        del principal, resource, device_token, client_ip, user_agent, context_snapshot
        return FailClosedPipelineResult()


_DEFAULT_PIPELINE = FailClosedSecurityPipeline()


def get_security_pipeline() -> SecurityPipeline:
    """Provide the production fail-closed pipeline; tests may override it."""
    return _DEFAULT_PIPELINE


class PipelineExecutionError(RuntimeError):
    """Safe marker for an unexpected pipeline failure, without its details."""


async def _persist_failsafe_event(
    session: AsyncSession,
    actor_id: UUID,
    *,
    rollback_first: bool = False,
) -> None:
    """Commit only the sanitized degraded-pipeline event in its own transaction."""
    if rollback_first:
        await session.rollback()
    try:
        await _begin_if_needed(session)
        record_event(
            session,
            event_type="PIPELINE_DEGRADED_FAILSAFE",
            actor_id=actor_id,
            decision="BLOCK",
            risk_category="HIGH",
        )
        await session.commit()
    except BaseException:
        await session.rollback()
        raise


@dataclass(frozen=True, slots=True)
class AccessGatewayResponse:
    """Publicly safe subset of the access gateway result."""

    evaluation_id: UUID
    decision: Decision
    explanation: str
    mfa_challenge_id: UUID | None = None


def _contains_device_token(value: object, device_token: str) -> bool:
    if isinstance(value, str):
        return value == device_token or (len(device_token) >= 16 and device_token in value)
    if isinstance(value, Mapping):
        return any(
            _contains_device_token(key, device_token) or _contains_device_token(item, device_token)
            for key, item in value.items()
        )
    if isinstance(value, (tuple, list)):
        return any(_contains_device_token(item, device_token) for item in value)
    if is_dataclass(value) and not isinstance(value, type):
        return any(
            _contains_device_token(getattr(value, field.name), device_token)
            for field in fields(value)
        )
    return False


def _validate_complete_result(result: CompletePipelineResult, device_token: str) -> None:
    names = [factor.factor_name for factor in result.factors]
    if len(names) != 4 or set(names) != _EXPECTED_FACTORS:
        raise ValueError("Pipeline must provide exactly the four schema trust factors")
    if not result.device.device_hash:
        raise ValueError("Pipeline device identity is invalid")
    if _contains_device_token(result, device_token):
        raise ValueError("Pipeline result contains the raw device token")
    if not Decimal("0") <= result.trust_score <= Decimal("100"):
        raise ValueError("Pipeline trust score is outside the schema range")


async def _begin_if_needed(session: AsyncSession) -> None:
    # Authentication loads the profile through this same request session and
    # may already have autobegun the transaction. The gateway owns its commit.
    if not session.in_transaction():
        await session.begin()


async def access_gateway(
    *,
    session: AsyncSession,
    principal: AuthenticatedPrincipal,
    resource: ProtectedResource,
    device_token: str,
    client_ip: str,
    user_agent: str | None,
    pipeline: SecurityPipeline,
    clock: Clock,
    request: Request | None = None,
    profile: Profile | None = None,
    geo_resolver: GeoResolver | None = None,
    settings: Settings | None = None,
) -> AccessGatewayResponse:
    """Run the server pipeline and persist its complete result atomically.

    The default fail-closed result persists only its standalone security event;
    no incomplete access-request/evaluation rows are written.
    """
    try:
        context_snapshot: ContextSnapshot | None = None
        if request is not None or profile is not None or geo_resolver is not None:
            if request is None or profile is None or geo_resolver is None:
                raise ValueError("Context collection dependencies are incomplete")
            if profile.id != principal.id:
                raise ValueError("Context profile does not match the authenticated principal")
            context_snapshot = await collect_context_snapshot(
                request=request,
                profile=profile,
                session=session,
                clock=clock,
                geo_resolver=geo_resolver,
                settings=settings,
            )
        evaluated = await pipeline.run(
            principal=principal,
            resource=resource,
            device_token=device_token,
            client_ip=client_ip,
            user_agent=user_agent,
            context_snapshot=context_snapshot,
        )
        if not isinstance(evaluated, (CompletePipelineResult, FailClosedPipelineResult)):
            raise TypeError("Security pipeline returned an unsupported result")
        if isinstance(evaluated, CompletePipelineResult):
            _validate_complete_result(evaluated, device_token)
            if context_snapshot is not None:
                evaluated = replace(evaluated, context=context_snapshot)
    except Exception:
        await _persist_failsafe_event(session, principal.id, rollback_first=True)
        raise PipelineExecutionError("Access evaluation is unavailable") from None

    evaluation_id = uuid4()
    if isinstance(evaluated, FailClosedPipelineResult):
        await _persist_failsafe_event(session, principal.id)
        return AccessGatewayResponse(
            evaluation_id=evaluation_id,
            decision="BLOCK",
            explanation=evaluated.explanation,
        )

    now = (
        evaluated.context.captured_at
        if isinstance(evaluated.context, ContextSnapshot)
        else clock.now()
    )
    if now.utcoffset() is None:
        raise ValueError("Gateway clock must return a timezone-aware datetime")
    try:
        await _begin_if_needed(session)

        device = Device(
            id=uuid4(),
            user_id=principal.id,
            device_hash=evaluated.device.device_hash,
            recognized_at=None,
            first_seen_at=now,
            last_seen_at=now,
            last_user_agent_family=evaluated.device.last_user_agent_family,
            last_user_agent_version=evaluated.device.last_user_agent_version,
        )
        persisted_device = await DeviceRepository(session).upsert_for_access(device)

        access_request_id = uuid4()
        access_request = AccessRequest(
            id=access_request_id,
            user_id=principal.id,
            device_id=persisted_device.id,
            resource_id=resource.resource_id,
            source_ip=ip_address(client_ip),
            resolved_region=evaluated.context.resolved_region,
            initial_decision=evaluated.decision,
            mfa_required=evaluated.decision == "STEP_UP",
            requested_at=now,
        )
        AccessRequestRepository(session).add(access_request)
        await session.flush()

        ContextSignalRepository(session).add(
            ContextSignal(
                id=uuid4(),
                access_request_id=access_request_id,
                device_familiarity_raw=evaluated.context.device_familiarity_raw,
                device_health_raw=evaluated.context.device_health_raw,
                location_raw=evaluated.context.location_raw,
                time_raw=evaluated.context.time_raw,
                raw_context=dict(evaluated.context.raw_context),
                captured_at=now,
            )
        )
        await session.flush()

        TrustEvaluationRepository(session).add(
            TrustEvaluation(
                id=evaluation_id,
                access_request_id=access_request_id,
                policy_version_id=evaluated.policy_version_id,
                trust_score=evaluated.trust_score,
                risk_classification=evaluated.risk_classification,
                status="COMPLETE",
                evaluated_at=now,
            )
        )
        await session.flush()

        TrustFactorRepository(session).add_many(
            [
                TrustFactor(
                    id=uuid4(),
                    trust_evaluation_id=evaluation_id,
                    factor_name=factor.factor_name,
                    raw_value=factor.raw_value,
                    normalized_score=factor.normalized_score,
                    weight=factor.weight,
                    weighted_contribution=factor.weighted_contribution,
                )
                for factor in evaluated.factors
            ]
        )
        await session.flush()

        PolicyDecisionRepository(session).add(
            PolicyDecision(
                id=uuid4(),
                access_request_id=access_request_id,
                trust_evaluation_id=evaluation_id,
                policy_version_id=evaluated.policy_version_id,
                decision=evaluated.decision,
                decision_reason=evaluated.decision_reason,
                decided_at=now,
            )
        )
        await session.flush()

        record_event(
            session,
            event_type=_ACCESS_EVENT_TYPES[evaluated.decision],
            actor_id=principal.id,
            access_request_id=access_request_id,
            trust_evaluation_id=evaluation_id,
            decision=evaluated.decision,
            risk_category=evaluated.risk_classification,
        )
        await session.flush()

        if evaluated.decision in {"ALLOW", "BLOCK"}:
            resolved_request = await AccessRequestRepository(session).set_final_outcome(
                access_request_id,
                evaluated.decision,
            )
            if resolved_request is None:
                raise RuntimeError("Persisted access request could not be resolved")
            resolved_request.resolved_at = now

        await session.commit()
    except BaseException:
        await session.rollback()
        raise

    return AccessGatewayResponse(
        evaluation_id=evaluation_id,
        decision=evaluated.decision,
        explanation=evaluated.explanation,
    )
