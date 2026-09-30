"""Persistence queries and narrowly scoped updates for devices."""

from datetime import datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.device import Device


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
