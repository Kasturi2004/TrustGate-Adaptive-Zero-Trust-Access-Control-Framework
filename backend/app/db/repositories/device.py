"""Persistence queries and narrowly scoped updates for devices."""

from datetime import datetime
from uuid import UUID

from sqlalchemy import select
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

    async def update_last_seen(self, device_id: UUID, timestamp: datetime) -> Device | None:
        """Update only last_seen_at, returning None if the device does not exist."""
        device = await self.get_by_id(device_id)
        if device is None:
            return None
        device.last_seen_at = timestamp
        return device
