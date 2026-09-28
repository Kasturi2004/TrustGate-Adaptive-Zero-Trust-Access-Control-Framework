"""Immutable policy decision for an access request."""

from datetime import datetime
from uuid import UUID

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, Text, desc, text
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class PolicyDecision(Base):
    __tablename__ = "policy_decisions"
    __table_args__ = (
        CheckConstraint("decision IN ('ALLOW', 'STEP_UP', 'BLOCK')", name="decision_values"),
        Index("idx_policy_decisions_decision", "decision", desc("decided_at")),
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
    trust_evaluation_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("public.trust_evaluations.id", ondelete="RESTRICT"),
        nullable=False,
    )
    policy_version_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("public.policy_versions.id", ondelete="RESTRICT"),
        nullable=False,
    )
    decision: Mapped[str] = mapped_column(Text, nullable=False)
    decision_reason: Mapped[str] = mapped_column(Text, nullable=False)
    decided_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("now()")
    )
