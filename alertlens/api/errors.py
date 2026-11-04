"""Every error is {error, detail} with the right status code."""
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException

from alertlens.ingest.adapters import UnknownFormatError
from alertlens.ingest.normalise import AlertValidationError
from alertlens.remediation.guardrails import GuardrailError


def install(app: FastAPI) -> None:
    def add(exc_type, status, label):
        async def handler(_: Request, exc: Exception):
            return JSONResponse({"error": label, "detail": str(exc)[:500]}, status_code=status)

        app.add_exception_handler(exc_type, handler)

    add(UnknownFormatError, 422, "unknown_format")
    add(AlertValidationError, 422, "invalid_alert")
    add(GuardrailError, 409, "guardrail")
    add(KeyError, 404, "not_found")

    async def http_error(_: Request, exc: HTTPException):
        return JSONResponse({"error": "http_error", "detail": str(exc.detail)}, status_code=exc.status_code)

    async def validation_error(_: Request, exc: RequestValidationError):
        return JSONResponse({"error": "invalid_request", "detail": str(exc.errors())[:500]}, status_code=422)

    app.add_exception_handler(HTTPException, http_error)
    app.add_exception_handler(RequestValidationError, validation_error)
