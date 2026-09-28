"""Immutable trust score evaluations."""

from datetime import datetime
from decimal import Decimal
from uuid import UUID

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, Numeric, Text, text
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class TrustEvaluation(Base):
    __tablename__ = "trust_evaluations"
    __table_args__ = (
        CheckConstraint("trust_score BETWEEN 0 AND 100", name="trust_score_range"),
        CheckConstraint(
            "risk_classification IN ('LOW', 'MEDIUM', 'HIGH')", name="risk_classification_values"
        ),
        CheckConstraint("status IN ('COMPLETE', 'DEGRADED_FAILSAFE')", name="status_values"),
        Index("idx_trust_evaluations_score", "trust_score"),
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
    policy_version_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("public.policy_versions.id", ondelete="RESTRICT"),
        nullable=False,
    )
    trust_score: Mapped[Decimal] = mapped_column(Numeric(5, 2), nullable=False)
    risk_classification: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(Text, nullable=False, server_default=text("'COMPLETE'"))
    evaluated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("now()")
    )
