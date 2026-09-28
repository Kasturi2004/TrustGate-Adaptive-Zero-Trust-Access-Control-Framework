"""Immutable contextual signal snapshot for an access request."""

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Text, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class ContextSignal(Base):
    __tablename__ = "context_signals"
    __table_args__ = (
        CheckConstraint(
            "device_familiarity_raw IN ('known_device', 'unknown_device')",
            name="device_familiarity_values",
        ),
        CheckConstraint(
            "device_health_raw IN ('healthy', 'partially_healthy', 'unhealthy')",
            name="device_health_values",
        ),
        CheckConstraint(
            "location_raw IN ('expected_region', 'new_region', 'unavailable')",
            name="location_values",
        ),
        CheckConstraint(
            "time_raw IN ('within_normal_window', 'outside_normal_window')", name="time_values"
        ),
    )

    id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    access_request_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("public.access_requests.id", ondelete="RESTRICT"),
        nullable=False,
        unique=True,
    )
    device_familiarity_raw: Mapped[str] = mapped_column(Text, nullable=False)
    device_health_raw: Mapped[str] = mapped_column(Text, nullable=False)
    location_raw: Mapped[str] = mapped_column(Text, nullable=False)
    time_raw: Mapped[str] = mapped_column(Text, nullable=False)
    raw_context: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, server_default=text("'{}'::jsonb")
    )
    captured_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("now()")
    )
