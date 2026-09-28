"""Mutable persistent rate-limit counters."""

from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, Index, Integer, Text, text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class RateLimitState(Base):
    __tablename__ = "rate_limit_state"
    __table_args__ = (
        CheckConstraint("counter >= 0", name="counter_nonnegative"),
        Index("idx_rate_limit_state_window_reset_at", "window_reset_at"),
    )

    key: Mapped[str] = mapped_column(Text, primary_key=True)
    counter: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("0"))
    window_reset_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("now()")
    )
