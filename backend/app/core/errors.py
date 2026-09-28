"""Consistent error envelope for every API response.

Shape: {"error": {"code": "...", "message": "...", "request_id": "..."}}
Client messages never include stack traces, SQL, or filesystem paths.
"""

import logging
import re
from collections.abc import Mapping
from uuid import uuid4

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import Response

logger = logging.getLogger("trustgate")

_REQUEST_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,64}$")

_STATUS_CODES = {
    401: "UNAUTHENTICATED",
    403: "FORBIDDEN",
    404: "NOT_FOUND",
    409: "CONFLICT",
    422: "VALIDATION_ERROR",
    429: "RATE_LIMITED",
    503: "SERVICE_UNAVAILABLE",
}


def request_id_from(request: Request) -> str:
    value = getattr(request.state, "request_id", None)
    if isinstance(value, str) and _REQUEST_ID_PATTERN.fullmatch(value):
        return value
    return "unknown"


def error_response(
    status_code: int,
    code: str,
    message: str,
    request_id: str,
    headers: Mapping[str, str] | None = None,
) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={"error": {"code": code, "message": message, "request_id": request_id}},
        headers=headers,
    )


async def handle_rate_limit_exceeded(request: Request, exc: Exception) -> JSONResponse:
    """Return a generic TrustGate 429 without exposing limiter details."""
    del exc
    return error_response(
        429,
        "RATE_LIMITED",
        "Too many requests. Please try again later.",
        request_id_from(request),
    )


class RequestIdMiddleware(BaseHTTPMiddleware):
    """Attach a request id for logs and error responses."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        incoming = request.headers.get("x-request-id", "")
        request_id = incoming if _REQUEST_ID_PATTERN.fullmatch(incoming) else str(uuid4())
        request.state.request_id = request_id
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response


def _client_message(exc: HTTPException) -> str:
    if exc.status_code >= 500:
        return "An unexpected error occurred."
    if isinstance(exc.detail, str) and exc.detail.strip():
        return exc.detail
    return "Request could not be completed."


def register_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(HTTPException)
    async def handle_http_exception(request: Request, exc: HTTPException) -> JSONResponse:
        code = _STATUS_CODES.get(exc.status_code, f"HTTP_{exc.status_code}")
        return error_response(
            exc.status_code,
            code,
            _client_message(exc),
            request_id_from(request),
            headers=exc.headers,
        )

    @app.exception_handler(RequestValidationError)
    async def handle_validation_error(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        del exc
        return error_response(
            422,
            "VALIDATION_ERROR",
            "Request validation failed.",
            request_id_from(request),
        )

    @app.exception_handler(Exception)
    async def handle_unexpected_error(request: Request, exc: Exception) -> JSONResponse:
        logger.error(
            "Unhandled error request_id=%s",
            request_id_from(request),
            exc_info=exc,
        )
        return error_response(
            500,
            "INTERNAL_ERROR",
            "An unexpected error occurred.",
            request_id_from(request),
        )
