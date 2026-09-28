"""Append-only access request records."""

from datetime import datetime
from ipaddress import IPv4Address, IPv6Address
from uuid import UUID

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Text,
    desc,
    text,
)
from sqlalchemy.dialects.postgresql import INET
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class AccessRequest(Base):
    __tablename__ = "access_requests"
    __table_args__ = (
        CheckConstraint(
            "initial_decision IN ('ALLOW', 'STEP_UP', 'BLOCK')", name="initial_decision_values"
        ),
        CheckConstraint("final_outcome IN ('ALLOW', 'BLOCK')", name="final_outcome_values"),
        Index("idx_access_requests_user_id", "user_id"),
        Index("idx_access_requests_user_created", "user_id", desc("requested_at")),
        Index("idx_access_requests_decision", "initial_decision", desc("requested_at")),
        Index("idx_access_requests_device_id", "device_id", desc("requested_at")),
    )

    id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    user_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("public.profiles.id", ondelete="RESTRICT"), nullable=False
    )
    device_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("public.devices.id", ondelete="RESTRICT"), nullable=False
    )
    resource_id: Mapped[str] = mapped_column(
        Text, nullable=False, server_default=text("'ops-dashboard'")
    )
    source_ip: Mapped[IPv4Address | IPv6Address] = mapped_column(INET, nullable=False)
    resolved_region: Mapped[str | None] = mapped_column(Text, nullable=True)
    initial_decision: Mapped[str] = mapped_column(Text, nullable=False)
    mfa_required: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default=text("false")
    )
    final_outcome: Mapped[str | None] = mapped_column(Text, nullable=True)
    requested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("now()")
    )
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
