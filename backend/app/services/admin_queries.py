"""Read-only PostgreSQL queries backing the administrative dashboard."""

from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.access_request import AccessRequest
from app.db.models.context_signal import ContextSignal
from app.db.models.device import Device
from app.db.models.otp_challenge import OtpChallenge
from app.db.models.policy_decision import PolicyDecision
from app.db.models.policy_version import PolicyVersion
from app.db.models.security_event import SecurityEvent
from app.db.models.trust_evaluation import TrustEvaluation
from app.db.models.trust_factor import TrustFactor
from app.db.repositories.policy_decision import PolicyDecisionRepository
from app.db.repositories.security_event import SecurityEventRepository
from app.db.repositories.trust_evaluation import TrustEvaluationRepository
from app.db.repositories.trust_factor import TrustFactorRepository
from app.schemas.admin import (
    AdminEventInvestigation,
    AdminInvestigationContext,
    AdminInvestigationDevice,
    AdminInvestigationEvent,
    AdminInvestigationFactor,
    AdminInvestigationOtpChallenge,
    AdminInvestigationPolicyDecision,
    AdminInvestigationPolicyVersion,
    AdminInvestigationRequest,
    AdminInvestigationTrustEvaluation,
)


@dataclass(frozen=True, slots=True)
class AdminDashboardMetrics:
    """Primitive dashboard metrics, detached from database ORM models."""

    total_requests: int
    allow_count: int
    step_up_count: int
    block_count: int
    average_trust_score: float | None
    high_risk_count: int
    mfa_success_rate: float | None


@dataclass(frozen=True, slots=True)
class AdminSecurityEventRow:
    """Primitive event-list fields detached from database ORM models."""

    id: UUID
    event_type: str
    created_at: datetime
    user_id: UUID | None
    decision: str | None
    risk_category: str | None
    trust_score: Decimal | None
    device: str | None


@dataclass(frozen=True, slots=True)
class AdminSecurityEventResults:
    """One filtered event page and its total matching row count."""

    items: tuple[AdminSecurityEventRow, ...]
    total: int


async def get_dashboard_metrics(
    session: AsyncSession,
    *,
    from_utc: datetime,
    to_utc: datetime,
) -> AdminDashboardMetrics:
    """Aggregate real rows using inclusive UTC bounds for each metric's timestamp.

    Request totals and decision counts use ``access_requests.requested_at``.
    Average score is scoped by its associated request's ``requested_at``;
    high-risk evaluations use ``trust_evaluations.evaluated_at``; MFA uses
    ``otp_challenges.created_at``. Both supplied bounds are inclusive.
    """
    request_metrics = select(
        func.count(AccessRequest.id).label("total_requests"),
        func.count(AccessRequest.id)
        .filter(AccessRequest.initial_decision == "ALLOW")
        .label("allow_count"),
        func.count(AccessRequest.id)
        .filter(AccessRequest.initial_decision == "STEP_UP")
        .label("step_up_count"),
        func.count(AccessRequest.id)
        .filter(AccessRequest.initial_decision == "BLOCK")
        .label("block_count"),
        func.avg(TrustEvaluation.trust_score).label("average_trust_score"),
    ).select_from(AccessRequest)
    request_metrics = request_metrics.outerjoin(
        TrustEvaluation,
        TrustEvaluation.access_request_id == AccessRequest.id,
    ).where(AccessRequest.requested_at.between(from_utc, to_utc))
    request_row = (await session.execute(request_metrics)).one()

    high_risk_statement = select(func.count(TrustEvaluation.id)).where(
        TrustEvaluation.risk_classification == "HIGH",
        TrustEvaluation.evaluated_at.between(from_utc, to_utc),
    )
    high_risk_count = int(await session.scalar(high_risk_statement) or 0)

    challenge_metrics = select(
        func.count(OtpChallenge.id).label("total_challenges"),
        func.count(OtpChallenge.id)
        .filter(OtpChallenge.status == "SUCCESS")
        .label("successful_challenges"),
    ).where(OtpChallenge.created_at.between(from_utc, to_utc))
    challenge_row = (await session.execute(challenge_metrics)).one()
    total_challenges = int(challenge_row.total_challenges)
    successful_challenges = int(challenge_row.successful_challenges)

    average_score = request_row.average_trust_score
    return AdminDashboardMetrics(
        total_requests=int(request_row.total_requests),
        allow_count=int(request_row.allow_count),
        step_up_count=int(request_row.step_up_count),
        block_count=int(request_row.block_count),
        average_trust_score=float(average_score) if average_score is not None else None,
        high_risk_count=high_risk_count,
        mfa_success_rate=(successful_challenges / total_challenges if total_challenges else None),
    )


async def get_admin_security_events(
    session: AsyncSession,
    *,
    from_utc: datetime | None,
    to_utc: datetime | None,
    user_id: UUID | None,
    decision: str | None,
    risk_category: str | None,
    device_id: UUID | None,
    score_min: Decimal | None,
    score_max: Decimal | None,
    page: int,
    page_size: int,
) -> AdminSecurityEventResults:
    """Query persisted events with optional UTC bounds and linked request filters.

    Bounds apply inclusively to ``security_events.created_at``. Request,
    evaluation, policy-decision and device joins are one-to-one for a request;
    ordering by event timestamp and ID gives stable pagination.
    """
    statement = (
        select(
            SecurityEvent.id,
            SecurityEvent.event_type,
            SecurityEvent.created_at,
            func.coalesce(
                AccessRequest.user_id,
                SecurityEvent.target_user_id,
                SecurityEvent.actor_id,
            ).label("user_id"),
            func.coalesce(SecurityEvent.decision, PolicyDecision.decision).label("decision"),
            func.coalesce(SecurityEvent.risk_category, TrustEvaluation.risk_classification).label(
                "risk_category"
            ),
            TrustEvaluation.trust_score,
            Device.device_hash,
        )
        .select_from(SecurityEvent)
        .outerjoin(AccessRequest, AccessRequest.id == SecurityEvent.access_request_id)
        .outerjoin(
            TrustEvaluation,
            TrustEvaluation.access_request_id == AccessRequest.id,
        )
        .outerjoin(
            PolicyDecision,
            PolicyDecision.access_request_id == AccessRequest.id,
        )
        .outerjoin(Device, Device.id == AccessRequest.device_id)
    )
    if from_utc is not None:
        statement = statement.where(SecurityEvent.created_at >= from_utc)
    if to_utc is not None:
        statement = statement.where(SecurityEvent.created_at <= to_utc)
    if user_id is not None:
        statement = statement.where(
            func.coalesce(
                AccessRequest.user_id,
                SecurityEvent.target_user_id,
                SecurityEvent.actor_id,
            )
            == user_id
        )
    if decision is not None:
        statement = statement.where(
            func.coalesce(SecurityEvent.decision, PolicyDecision.decision) == decision
        )
    if risk_category is not None:
        statement = statement.where(
            func.coalesce(SecurityEvent.risk_category, TrustEvaluation.risk_classification)
            == risk_category
        )
    if device_id is not None:
        statement = statement.where(AccessRequest.device_id == device_id)
    if score_min is not None:
        statement = statement.where(TrustEvaluation.trust_score >= score_min)
    if score_max is not None:
        statement = statement.where(TrustEvaluation.trust_score <= score_max)

    count_statement = select(func.count()).select_from(statement.order_by(None).subquery())
    total = int(await session.scalar(count_statement) or 0)
    result = await session.execute(
        statement.order_by(SecurityEvent.created_at.desc(), SecurityEvent.id.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    rows = tuple(
        AdminSecurityEventRow(
            id=row.id,
            event_type=row.event_type,
            created_at=row.created_at,
            user_id=row.user_id,
            decision=row.decision,
            risk_category=row.risk_category,
            trust_score=row.trust_score,
            device=(row.device_hash[:12] + "…") if row.device_hash is not None else None,
        )
        for row in result
    )
    return AdminSecurityEventResults(items=rows, total=total)


async def get_admin_event_investigation(
    session: AsyncSession,
    *,
    event_id: UUID | None = None,
    access_request_id: UUID | None = None,
) -> AdminEventInvestigation | None:
    """Return an allow-listed persisted investigation by event or request ID.

    For the ADMIN branch of access-request detail, the newest event attached
    to the request is the root and the remaining request events are related.
    If an event has no linked access request, its investigation is event-only.
    """
    if event_id is not None:
        root_event = await session.get(SecurityEvent, event_id)
        if root_event is None:
            return None
        access_request_id = root_event.access_request_id
    elif access_request_id is not None:
        access_request = await session.get(AccessRequest, access_request_id)
        if access_request is None:
            return None
        events = await SecurityEventRepository(session).list(access_request_id=access_request_id)
        root_event = events[0] if events else None
    else:
        raise ValueError("event_id or access_request_id is required")

    event_response = _investigation_event(root_event) if root_event is not None else None
    request_response: AdminInvestigationRequest | None = None
    context_response: AdminInvestigationContext | None = None
    evaluation_response: AdminInvestigationTrustEvaluation | None = None
    policy_response: AdminInvestigationPolicyDecision | None = None
    otp_responses: list[AdminInvestigationOtpChallenge] = []
    related_responses: list[AdminInvestigationEvent] = []

    if access_request_id is not None:
        access_request = await session.get(AccessRequest, access_request_id)
        if access_request is not None:
            device = await session.get(Device, access_request.device_id)
            request_response = AdminInvestigationRequest(
                id=access_request.id,
                user_id=access_request.user_id,
                resource_id=access_request.resource_id,
                source_ip=str(access_request.source_ip),
                resolved_region=access_request.resolved_region,
                initial_decision=access_request.initial_decision,
                mfa_required=access_request.mfa_required,
                final_outcome=access_request.final_outcome,
                requested_at=access_request.requested_at,
                resolved_at=access_request.resolved_at,
                device=(
                    AdminInvestigationDevice(
                        id=device.id,
                        device_hash=device.device_hash[:12] + "…",
                    )
                    if device is not None
                    else None
                ),
            )

            context = await session.scalar(
                select(ContextSignal).where(ContextSignal.access_request_id == access_request_id)
            )
            if context is not None:
                context_response = AdminInvestigationContext(
                    captured_at=context.captured_at,
                    device_familiarity_raw=context.device_familiarity_raw,
                    device_health_raw=context.device_health_raw,
                    location_raw=context.location_raw,
                    time_raw=context.time_raw,
                )

            evaluation = await TrustEvaluationRepository(session).get_by_access_request(
                access_request_id
            )
            if evaluation is not None:
                factors = await TrustFactorRepository(session).list_by_evaluation(evaluation.id)
                evaluation_response = AdminInvestigationTrustEvaluation(
                    id=evaluation.id,
                    trust_score=evaluation.trust_score,
                    risk_classification=evaluation.risk_classification,
                    status=evaluation.status,
                    evaluated_at=evaluation.evaluated_at,
                    factors=[
                        AdminInvestigationFactor(
                            factor_name=factor.factor_name,
                            raw_value=factor.raw_value,
                            normalized_score=factor.normalized_score,
                            weight=factor.weight,
                            weighted_contribution=factor.weighted_contribution,
                            explanation=_explain_persisted_factor(factor),
                        )
                        for factor in factors
                    ],
                )

            policy_decision = await PolicyDecisionRepository(session).get_by_access_request(
                access_request_id
            )
            if policy_decision is not None:
                policy_version = await session.get(PolicyVersion, policy_decision.policy_version_id)
                policy_response = AdminInvestigationPolicyDecision(
                    id=policy_decision.id,
                    decision=policy_decision.decision,
                    decision_reason=policy_decision.decision_reason,
                    decided_at=policy_decision.decided_at,
                    policy_version=(
                        AdminInvestigationPolicyVersion(
                            id=policy_version.id,
                            version_label=policy_version.version_label,
                            created_at=policy_version.created_at,
                        )
                        if policy_version is not None
                        else None
                    ),
                )

            challenge_rows = await session.scalars(
                select(OtpChallenge)
                .where(OtpChallenge.access_request_id == access_request_id)
                .order_by(OtpChallenge.created_at, OtpChallenge.id)
            )
            otp_responses = [
                AdminInvestigationOtpChallenge(
                    id=challenge.id,
                    status=challenge.status,
                    attempt_count=challenge.attempt_count,
                    created_at=challenge.created_at,
                    expires_at=challenge.expires_at,
                    verified_at=challenge.verified_at,
                )
                for challenge in challenge_rows
            ]

            related_events = await SecurityEventRepository(session).list(
                access_request_id=access_request_id
            )
            related_responses = [
                _investigation_event(event)
                for event in reversed(related_events)
                if root_event is None or event.id != root_event.id
            ]

    return AdminEventInvestigation(
        event=event_response,
        access_request=request_response,
        context_signals=context_response,
        trust_evaluation=evaluation_response,
        policy_decision=policy_response,
        otp_challenges=otp_responses,
        related_events=related_responses,
    )


def _investigation_event(event: SecurityEvent) -> AdminInvestigationEvent:
    """Project event metadata without its unstructured details payload."""
    return AdminInvestigationEvent(
        id=event.id,
        event_type=event.event_type,
        actor_id=event.actor_id,
        target_user_id=event.target_user_id,
        decision=event.decision,
        risk_category=event.risk_category,
        created_at=event.created_at,
    )


def _explain_persisted_factor(factor: TrustFactor) -> str:
    """Build the trust-engine style explanation from persisted factor fields."""
    factor_label = factor.factor_name.replace("_", " ").title()
    return (
        f"{factor_label}: {factor.raw_value} maps to {factor.normalized_score:f} points; "
        f"at weight {factor.weight:f}, contributes {factor.weighted_contribution:f}."
    )
