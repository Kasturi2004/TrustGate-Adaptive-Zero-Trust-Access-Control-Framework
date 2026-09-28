"""Immutable explainability factors for a trust evaluation."""

from decimal import Decimal
from uuid import UUID

from sqlalchemy import CheckConstraint, ForeignKey, Index, Numeric, Text, UniqueConstraint, text
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class TrustFactor(Base):
    __tablename__ = "trust_factors"
    __table_args__ = (
        CheckConstraint(
            "factor_name IN ('device_familiarity', 'device_health', "
            "'location_normality', 'time_normality')",
            name="factor_name_values",
        ),
        CheckConstraint("normalized_score BETWEEN 0 AND 100", name="normalized_score_range"),
        CheckConstraint("weight > 0 AND weight <= 1", name="weight_range"),
        UniqueConstraint("trust_evaluation_id", "factor_name", name="evaluation_factor"),
        Index("idx_trust_factors_evaluation_id", "trust_evaluation_id"),
    )

    id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    trust_evaluation_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("public.trust_evaluations.id", ondelete="RESTRICT"),
        nullable=False,
    )
    factor_name: Mapped[str] = mapped_column(Text, nullable=False)
    raw_value: Mapped[str] = mapped_column(Text, nullable=False)
    normalized_score: Mapped[Decimal] = mapped_column(Numeric(5, 2), nullable=False)
    weight: Mapped[Decimal] = mapped_column(Numeric(4, 3), nullable=False)
    weighted_contribution: Mapped[Decimal] = mapped_column(Numeric(6, 3), nullable=False)
