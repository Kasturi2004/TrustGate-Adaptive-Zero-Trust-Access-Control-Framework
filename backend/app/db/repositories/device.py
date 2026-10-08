"""Persistence queries and narrowly scoped updates for devices."""

from datetime import datetime
from uuid import UUID

from sqlalchemy import and_, exists, or_, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.access_request import AccessRequest
from app.db.models.device import Device
from app.db.models.otp_challenge import OtpChallenge


class DeviceRepository:
    """Manage device records using a caller-owned async session."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_by_id(self, device_id: UUID) -> Device | None:
        """Return a device by its ID."""
        return await self._session.get(Device, device_id)

    async def get_by_user_and_hash(self, user_id: UUID, device_hash: str) -> Device | None:
        """Return the device identified by its owner and fingerprint hash."""
        statement = select(Device).where(
            Device.user_id == user_id,
            Device.device_hash == device_hash,
        )
        result = await self._session.scalars(statement)
        return result.first()

    async def get_recognizable_device(
        self,
        *,
        access_request_id: UUID,
        user_id: UUID,
        auth_session_id: UUID,
        device_hash: str,
    ) -> Device | None:
        """Find the request's device only after its approved request was redeemed."""
        successful_mfa = exists(
            select(OtpChallenge.id).where(
                OtpChallenge.access_request_id == AccessRequest.id,
                OtpChallenge.user_id == user_id,
                OtpChallenge.status == "SUCCESS",
                OtpChallenge.verified_at.is_not(None),
            )
        )
        eligible_request = exists(
            select(AccessRequest.id)
            .where(
                AccessRequest.id == access_request_id,
                AccessRequest.user_id == user_id,
                AccessRequest.auth_session_id == auth_session_id,
                AccessRequest.device_id == Device.id,
                AccessRequest.resource_id == "ops-dashboard",
                AccessRequest.final_outcome == "ALLOW",
                AccessRequest.consumed_at.is_not(None),
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
        )
        statement = select(Device).where(
            Device.user_id == user_id,
            Device.device_hash == device_hash,
            eligible_request,
        )
        result = await self._session.scalars(statement.with_for_update(of=Device))
        return result.first()

    async def set_recognized_at_if_unknown(
        self, device: Device, recognized_at: datetime
    ) -> Device:
        """Recognize an existing device without changing its identity or history."""
        if device.recognized_at is None:
            device.recognized_at = recognized_at
            await self._session.flush()
        return device

    async def list_by_user(self, user_id: UUID) -> list[Device]:
        """Return a user's devices in stable first-seen and ID order."""
        statement = (
            select(Device)
            .where(Device.user_id == user_id)
            .order_by(Device.first_seen_at, Device.id)
        )
        result = await self._session.scalars(statement)
        return list(result.all())

    def add(self, device: Device) -> None:
        """Stage a device for insertion without committing the transaction."""
        self._session.add(device)

    async def upsert_for_access(self, device: Device) -> Device:
        """Insert a request device or refresh only its last-seen UA fields.

        A recognized timestamp is never changed by an access request. The
        caller owns the transaction.
        """
        statement = insert(Device).values(
            id=device.id,
            user_id=device.user_id,
            device_hash=device.device_hash,
            recognized_at=device.recognized_at,
            first_seen_at=device.first_seen_at,
            last_seen_at=device.last_seen_at,
            last_user_agent_family=device.last_user_agent_family,
            last_user_agent_version=device.last_user_agent_version,
        )
        upsert = statement.on_conflict_do_update(
            constraint="user_device_hash",
            set_={
                "last_seen_at": statement.excluded.last_seen_at,
                "last_user_agent_family": statement.excluded.last_user_agent_family,
                "last_user_agent_version": statement.excluded.last_user_agent_version,
            },
        ).returning(Device)
        result = await self._session.scalars(
            upsert,
            execution_options={"populate_existing": True},
        )
        return result.one()

    async def update_last_seen(self, device_id: UUID, timestamp: datetime) -> Device | None:
        """Update only last_seen_at, returning None if the device does not exist."""
        device = await self.get_by_id(device_id)
        if device is None:
            return None
        device.last_seen_at = timestamp
        return device
