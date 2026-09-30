"""HTTP middleware: request identity, security headers, throttling and access logging."""

from __future__ import annotations

import time
import uuid
from collections.abc import Awaitable, Callable

import structlog
from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from app.core.config import settings
from app.core.logging import get_logger
from app.core.ratelimit import auth_limiter

logger = get_logger("http")

Handler = Callable[[Request], Awaitable[Response]]

# This service returns JSON and never renders HTML of its own, so nothing needs to be
# permitted to load. Evidence previews are served as attachments with their own sandboxed
# policy (see the evidence router), never inline into this origin.
API_CSP = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'; sandbox"
# The interactive API documentation loads Swagger assets from a CDN, so it needs a policy of
# its own. It is only mounted outside production.
DOCS_CSP = (
    "default-src 'self'; script-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; "
    "style-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; img-src 'self' data: "
    "https://fastapi.tiangolo.com; font-src 'self' https://cdn.jsdelivr.net; "
    "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'"
)
DOC_PATHS = ("/docs", "/redoc", "/openapi.json")


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Assign a request id and bind it to the logging context.

    The id is echoed in the ``X-Request-ID`` response header and stored on every audit and
    custody record written during the request, which is what lets an auditor tie a cluster of
    records back to the single API call that produced them.
    """

    async def dispatch(self, request: Request, call_next: Handler) -> Response:
        incoming = request.headers.get("x-request-id")
        request_id = incoming if incoming and len(incoming) <= 64 else uuid.uuid4().hex
        request.state.request_id = request_id

        structlog.contextvars.bind_contextvars(request_id=request_id)
        started = time.perf_counter()
        try:
            response = await call_next(request)
        finally:
            duration_ms = (time.perf_counter() - started) * 1000
            structlog.contextvars.unbind_contextvars("request_id")

        response.headers["X-Request-ID"] = request_id
        if not request.url.path.startswith(DOC_PATHS):
            logger.info(
                "request",
                method=request.method,
                path=request.url.path,
                status=response.status_code,
                duration_ms=round(duration_ms, 2),
            )
        return response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: Handler) -> Response:
        response = await call_next(request)
        is_docs = request.url.path.startswith(DOC_PATHS)

        response.headers.setdefault("Content-Security-Policy", DOCS_CSP if is_docs else API_CSP)
        # Content type sniffing on evidence downloads would be actively dangerous: a file the
        # browser decides is HTML could execute in this origin.
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault(
            "Permissions-Policy", "geolocation=(), microphone=(), camera=(), usb=()"
        )
        response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        response.headers.setdefault("Cross-Origin-Resource-Policy", "same-origin")
        if settings.is_production:
            response.headers.setdefault(
                "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
            )
        return response


class AuthThrottleMiddleware(BaseHTTPMiddleware):
    """Edge throttle on authentication endpoints."""

    THROTTLED_PATHS = ("/auth/login", "/auth/refresh", "/auth/password")

    async def dispatch(self, request: Request, call_next: Handler) -> Response:
        path = request.url.path
        if request.method == "POST" and any(path.endswith(p) for p in self.THROTTLED_PATHS):
            forwarded = request.headers.get("x-forwarded-for")
            client = (
                forwarded.split(",")[0].strip()
                if forwarded
                else (request.client.host if request.client else "unknown")
            )
            decision = auth_limiter.check(f"{client}:{path}")
            if not decision.allowed:
                logger.warning("auth_throttled", path=path, client=client)
                return JSONResponse(
                    status_code=429,
                    content={
                        "error": {
                            "code": "rate_limited",
                            "message": "Too many attempts. Please wait before trying again.",
                            "details": {"retry_after_seconds": decision.retry_after_seconds},
                        }
                    },
                    headers={"Retry-After": str(decision.retry_after_seconds)},
                )
        return await call_next(request)
