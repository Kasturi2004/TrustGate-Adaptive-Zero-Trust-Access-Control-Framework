"""Append-only versioned policy configuration."""

from datetime import datetime
from decimal import Decimal
from typing import Any
from uuid import UUID

from sqlalchemy import Boolean, DateTime, Index, Numeric, Text, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class PolicyVersion(Base):
    __tablename__ = "policy_versions"
    __table_args__ = (
        Index(
            "idx_policy_versions_one_active",
            "is_active",
            unique=True,
            postgresql_where=text("is_active"),
        ),
    )

    id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    version_label: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    weights_json: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    allow_threshold: Mapped[Decimal] = mapped_column(
        Numeric(5, 2), nullable=False, server_default=text("70.00")
    )
    stepup_threshold: Mapped[Decimal] = mapped_column(
        Numeric(5, 2), nullable=False, server_default=text("40.00")
    )
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("now()")
    )
