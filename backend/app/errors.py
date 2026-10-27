"""Uniform ErrorResponse JSON for every error status."""
from __future__ import annotations

import logging

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from chainguard_contract.models import ErrorResponse

log = logging.getLogger("chainguard.errors")


class APIError(Exception):
    def __init__(self, status: int, error: str, detail: str | None = None):
        super().__init__(detail or error)
        self.status, self.error, self.detail = status, error, detail


def error_json(status: int, error: str, detail: str | None = None, headers: dict | None = None) -> JSONResponse:
    return JSONResponse(status_code=status, content=ErrorResponse(error=error, detail=detail).model_dump(), headers=headers)


_CODES = {400: "bad_request", 401: "unauthorized", 403: "forbidden", 404: "not_found", 405: "method_not_allowed",
          409: "conflict", 413: "payload_too_large", 415: "unsupported_media_type", 422: "validation_error",
          503: "service_unavailable"}


def install(app: FastAPI) -> None:
    @app.exception_handler(APIError)
    async def _api(_: Request, exc: APIError):
        return error_json(exc.status, exc.error, exc.detail)

    @app.exception_handler(StarletteHTTPException)
    async def _http(_: Request, exc: StarletteHTTPException):
        detail = exc.detail if isinstance(exc.detail, str) else str(exc.detail)
        return error_json(exc.status_code, _CODES.get(exc.status_code, "error"), detail, getattr(exc, "headers", None))

    @app.exception_handler(RequestValidationError)
    async def _val(_: Request, exc: RequestValidationError):
        parts = []
        for e in exc.errors():
            loc = ".".join(str(x) for x in e.get("loc", ()))
            parts.append(f"{loc}: {e.get('msg')}")
        return error_json(422, "validation_error", "; ".join(parts) or None)

    @app.exception_handler(Exception)
    async def _any(_: Request, exc: Exception):
        log.exception("unhandled error")
        return error_json(500, "internal_error", "An unexpected server error occurred.")
