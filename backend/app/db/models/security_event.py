"""Append-only security event records."""

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, Text, desc, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class SecurityEvent(Base):
    __tablename__ = "security_events"
    __table_args__ = (
        CheckConstraint("decision IN ('ALLOW', 'STEP_UP', 'BLOCK')", name="decision_values"),
        CheckConstraint("risk_category IN ('LOW', 'MEDIUM', 'HIGH')", name="risk_category_values"),
        Index("idx_security_events_created_at", desc("created_at")),
        Index("idx_security_events_actor", "actor_id", desc("created_at")),
        Index("idx_security_events_event_type", "event_type", desc("created_at")),
        Index("idx_security_events_request", "access_request_id"),
    )

    id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    event_type: Mapped[str] = mapped_column(Text, nullable=False)
    actor_id: Mapped[UUID | None] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("public.profiles.id", ondelete="SET NULL"), nullable=True
    )
    target_user_id: Mapped[UUID | None] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("public.profiles.id", ondelete="SET NULL"), nullable=True
    )
    access_request_id: Mapped[UUID | None] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("public.access_requests.id", ondelete="SET NULL"),
        nullable=True,
    )
    trust_evaluation_id: Mapped[UUID | None] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("public.trust_evaluations.id", ondelete="SET NULL"),
        nullable=True,
    )
    decision: Mapped[str | None] = mapped_column(Text, nullable=True)
    risk_category: Mapped[str | None] = mapped_column(Text, nullable=True)
    details: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, server_default=text("'{}'::jsonb")
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("now()")
    )
