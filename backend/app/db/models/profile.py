"""Application profile extending a Supabase Auth identity."""

from datetime import datetime
from uuid import UUID

from sqlalchemy import Boolean, CheckConstraint, DateTime, Text, text
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.schema import FetchedValue

from app.db.base import Base


class Profile(Base):
    __tablename__ = "profiles"
    __table_args__ = (CheckConstraint("role IN ('USER', 'ADMIN')", name="role_values"),)

    id: Mapped[UUID] = mapped_column(
        # Supabase owns auth.users; its FK is created by the database migration.
        # Keeping this external FK out of ORM metadata lets flush sort this model
        # without requiring Supabase's managed table in Base.metadata.
        PG_UUID(as_uuid=True), primary_key=True
    )
    email: Mapped[str | None] = mapped_column(Text, nullable=True)
    role: Mapped[str] = mapped_column(Text, nullable=False, server_default=text("'USER'"))
    timezone: Mapped[str] = mapped_column(Text, nullable=False, server_default=text("'UTC'"))
    is_deleted: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("now()")
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("now()"),
        server_onupdate=FetchedValue(),
    )
