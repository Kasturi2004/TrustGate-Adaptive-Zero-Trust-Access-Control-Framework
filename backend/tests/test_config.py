import pytest
from app.core.config import Settings
from pydantic import ValidationError


def test_wildcard_cors_origin_is_rejected() -> None:
    with pytest.raises(ValidationError):
        Settings(app_env="test", cors_allowed_origin="*")


def test_multiple_cors_origins_are_rejected() -> None:
    with pytest.raises(ValidationError):
        Settings(
            app_env="test",
            cors_allowed_origin="http://localhost:5173,https://evil.example",
        )


def test_explicit_origin_is_accepted() -> None:
    settings = Settings(app_env="local", cors_allowed_origin="http://localhost:5173/")
    assert settings.cors_allowed_origin == "http://localhost:5173"


def test_block_indicator_limit_defaults_to_three_and_must_be_positive() -> None:
    settings = Settings(app_env="test", cors_allowed_origin="http://localhost:5173")
    assert settings.block_indicator_limit == 3

    with pytest.raises(ValidationError):
        Settings(
            app_env="test",
            cors_allowed_origin="http://localhost:5173",
            block_indicator_limit=0,
        )
