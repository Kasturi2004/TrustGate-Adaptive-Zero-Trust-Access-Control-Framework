"""Manually promote an existing TrustGate profile to ADMIN."""

from __future__ import annotations

import argparse
import asyncio
import re
import sys
from collections.abc import Sequence
from pathlib import Path

from sqlalchemy.ext.asyncio import AsyncSession

# The script is run from the repository root, while the backend package lives
# in backend/. Keep the CLI self-contained without requiring an installation.
_BACKEND_ROOT = Path(__file__).resolve().parents[1] / "backend"
if str(_BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(_BACKEND_ROOT))

from app.core.config import get_settings  # noqa: E402
from app.db.repositories.profile import ProfileRepository  # noqa: E402
from app.db.session import create_migration_engine, create_session_factory  # noqa: E402

_EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class ProfileNotFoundError(Exception):
    """Raised when no existing profile matches the requested email."""


def normalize_email(email: str) -> str:
    """Normalize email using the application's trim-and-casefold convention."""
    normalized = email.strip().casefold()
    if not _EMAIL_PATTERN.fullmatch(normalized):
        raise ValueError("Invalid email")
    return normalized


async def promote_profile(session: AsyncSession, email: str) -> bool:
    """Promote a matching profile, changing only its role; return whether changed."""
    repository = ProfileRepository(session)
    profile = await repository.get_by_email(email)
    if profile is None:
        raise ProfileNotFoundError
    if profile.role == "ADMIN":
        return False

    profile.role = "ADMIN"
    await session.commit()
    return True


async def _promote_with_database(email: str) -> bool:
    """Run promotion through the configured owner/migration database URL."""
    engine = create_migration_engine(get_settings())
    try:
        session_factory = create_session_factory(engine)
        async with session_factory() as session:
            return await promote_profile(session, email)
    finally:
        await engine.dispose()


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point; failures never include exception or connection details."""
    parser = argparse.ArgumentParser(description="Promote an existing TrustGate profile to ADMIN.")
    parser.add_argument("email", help="email address of the existing profile")
    args = parser.parse_args(argv)

    try:
        email = normalize_email(args.email)
    except ValueError:
        parser.error("email must be a valid address")

    try:
        changed = asyncio.run(_promote_with_database(email))
    except ProfileNotFoundError:
        print("No existing profile was found for that email.", file=sys.stderr)
        return 1
    except Exception:
        print("Admin promotion failed due to a database or configuration error.", file=sys.stderr)
        return 1

    if changed:
        print("Existing profile promoted to ADMIN.")
    else:
        print("Profile is already ADMIN; no change was necessary.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
