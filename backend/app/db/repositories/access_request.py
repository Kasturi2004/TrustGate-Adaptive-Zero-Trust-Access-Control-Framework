"""Persistence queries and outcome updates for access requests."""

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from sqlalchemy import and_, exists, func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.access_request import AccessRequest
from app.db.models.otp_challenge import OtpChallenge

_MAX_HISTORY_PAGE_SIZE = 50


@dataclass(frozen=True, slots=True)
class AccessHistoryRecord:
    """Allow-listed access history projection for one access request."""

    id: UUID
    resource_id: str
    requested_at: datetime
    initial_decision: str
    final_outcome: str | None
    mfa_was_required: bool
    mfa_status: str | None


class AccessRequestRepository:
    """Manage access requests using a caller-owned async session."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_by_id(self, access_request_id: UUID) -> AccessRequest | None:
        """Return an access request by its ID."""
        return await self._session.get(AccessRequest, access_request_id)

    async def list_by_user(self, user_id: UUID) -> list[AccessRequest]:
        """Return a user's requests newest first with stable ID tie-breaking."""
        statement = (
            select(AccessRequest)
            .where(AccessRequest.user_id == user_id)
            .order_by(AccessRequest.requested_at.desc(), AccessRequest.id)
        )
        result = await self._session.scalars(statement)
        return list(result.all())

    async def list_history_by_user(
        self, user_id: UUID, *, page: int, page_size: int
    ) -> list[AccessHistoryRecord]:
        """Return the user's allow-listed access history page, newest first.

        A page size above the API ceiling is capped at 50. The caller supplies
        the authenticated user's ID; no user ID is read from the query itself.
        """
        if page < 1:
            raise ValueError("page must be at least 1")
        if page_size < 1:
            raise ValueError("page_size must be at least 1")

        latest_challenge = select(
            OtpChallenge.access_request_id.label("access_request_id"),
            OtpChallenge.status.label("mfa_status"),
            func.row_number()
            .over(
                partition_by=OtpChallenge.access_request_id,
                order_by=(OtpChallenge.created_at.desc(), OtpChallenge.id.desc()),
            )
            .label("challenge_rank"),
        ).subquery()
        effective_page_size = min(page_size, _MAX_HISTORY_PAGE_SIZE)
        statement = (
            select(
                AccessRequest.id,
                AccessRequest.resource_id,
                AccessRequest.requested_at,
                AccessRequest.initial_decision,
                AccessRequest.final_outcome,
                AccessRequest.mfa_required.label("mfa_was_required"),
                latest_challenge.c.mfa_status,
            )
            .outerjoin(
                latest_challenge,
                and_(
                    latest_challenge.c.access_request_id == AccessRequest.id,
                    latest_challenge.c.challenge_rank == 1,
                ),
            )
            .where(AccessRequest.user_id == user_id)
            .order_by(AccessRequest.requested_at.desc(), AccessRequest.id)
            .offset((page - 1) * effective_page_size)
            .limit(effective_page_size)
        )
        result = await self._session.execute(statement)
        return [AccessHistoryRecord(**row) for row in result.mappings()]

    async def get_history_by_id_for_user(
        self, access_request_id: UUID, user_id: UUID
    ) -> AccessHistoryRecord | None:
        """Return one owned access request using the curated history projection."""
        latest_challenge = select(
            OtpChallenge.access_request_id.label("access_request_id"),
            OtpChallenge.status.label("mfa_status"),
            func.row_number()
            .over(
                partition_by=OtpChallenge.access_request_id,
                order_by=(OtpChallenge.created_at.desc(), OtpChallenge.id.desc()),
            )
            .label("challenge_rank"),
        ).subquery()
        statement = (
            select(
                AccessRequest.id,
                AccessRequest.resource_id,
                AccessRequest.requested_at,
                AccessRequest.initial_decision,
                AccessRequest.final_outcome,
                AccessRequest.mfa_required.label("mfa_was_required"),
                latest_challenge.c.mfa_status,
            )
            .outerjoin(
                latest_challenge,
                and_(
                    latest_challenge.c.access_request_id == AccessRequest.id,
                    latest_challenge.c.challenge_rank == 1,
                ),
            )
            .where(
                AccessRequest.id == access_request_id,
                AccessRequest.user_id == user_id,
            )
        )
        result = await self._session.execute(statement)
        row = result.mappings().first()
        return AccessHistoryRecord(**row) if row is not None else None

    def add(self, access_request: AccessRequest) -> None:
        """Stage an access request without committing the transaction."""
        self._session.add(access_request)

    async def set_final_outcome(
        self, access_request_id: UUID, outcome: str
    ) -> AccessRequest | None:
        """Set only final_outcome, returning None if the request does not exist."""
        access_request = await self.get_by_id(access_request_id)
        if access_request is None:
            return None
        access_request.final_outcome = outcome
        return access_request

    async def resolve_step_up(
        self,
        access_request_id: UUID,
        user_id: UUID,
        auth_session_id: UUID,
        resolved_at: datetime,
    ) -> AccessRequest | None:
        """Atomically resolve one still-pending MFA STEP_UP request to ALLOW."""
        statement = (
            update(AccessRequest)
            .where(
                AccessRequest.id == access_request_id,
                AccessRequest.user_id == user_id,
                AccessRequest.auth_session_id == auth_session_id,
                AccessRequest.initial_decision == "STEP_UP",
                AccessRequest.mfa_required.is_(True),
                AccessRequest.final_outcome.is_(None),
                AccessRequest.resolved_at.is_(None),
            )
            .values(final_outcome="ALLOW", resolved_at=resolved_at)
            .returning(AccessRequest)
        )
        result = await self._session.scalars(
            statement,
            execution_options={"populate_existing": True},
        )
        return result.first()

    async def consume_dashboard_access(
        self, access_request_id: UUID, user_id: UUID, auth_session_id: UUID, now: datetime
    ) -> bool:
        """Atomically consume one approved dashboard request, requiring successful MFA if needed."""
        successful_mfa = exists(
            select(OtpChallenge.id).where(
                OtpChallenge.access_request_id == AccessRequest.id,
                OtpChallenge.user_id == user_id,
                OtpChallenge.status == "SUCCESS",
                OtpChallenge.verified_at.is_not(None),
            )
        )
        statement = (
            update(AccessRequest)
            .where(
                AccessRequest.id == access_request_id,
                AccessRequest.user_id == user_id,
                AccessRequest.auth_session_id == auth_session_id,
                AccessRequest.resource_id == "ops-dashboard",
                AccessRequest.final_outcome == "ALLOW",
                AccessRequest.consumed_at.is_(None),
                or_(
                    and_(
                        AccessRequest.initial_decision == "ALLOW",
                        AccessRequest.mfa_required.is_(False),
                    ),
                    and_(
                        AccessRequest.initial_decision == "STEP_UP",
                        AccessRequest.mfa_required.is_(True),
                        successful_mfa,
                    ),
                ),
            )
            .values(consumed_at=now)
            .returning(AccessRequest.id)
        )
        result = await self._session.execute(statement)
        return result.scalar_one_or_none() is not None
