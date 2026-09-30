"""Application factory.

Startup order matters and is deliberate: configuration is validated before anything else so
an unsafe deployment fails immediately rather than half-initialising; the permission catalogue
is reconciled before the first request can be authorised; and the background worker starts
last, once everything it depends on exists.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app import __version__
from app.api.v1.router import api_router
from app.core.config import settings
from app.core.errors import CybertraceError
from app.core.logging import configure_logging, get_logger
from app.core.middleware import (
    AuthThrottleMiddleware,
    RequestContextMiddleware,
    SecurityHeadersMiddleware,
)
from app.db.session import session_scope
from app.security.bootstrap import sync_permissions

logger = get_logger(__name__)

DESCRIPTION = """
CYBERTRACE manages the lifecycle of digital evidence in cybercrime investigations:
acquisition, cryptographic preservation, integrity verification, chain of custody, analysis,
correlation, timeline reconstruction and signed forensic reporting.

Authorization is enforced here, at the API. Every protected route requires an explicit
permission, and every case-scoped query is additionally narrowed in SQL to the cases the
caller is entitled to see.
"""


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    configure_logging()
    settings.assert_production_ready()

    settings.storage_root.mkdir(parents=True, exist_ok=True)

    with session_scope() as session:
        sync_permissions(session)

    from app.jobs.scheduler import register_default_schedule
    from app.jobs.worker import WorkerPool

    with session_scope() as session:
        register_default_schedule(session)

    pool: WorkerPool | None = None
    if settings.worker_enabled:
        pool = WorkerPool(concurrency=settings.worker_concurrency)
        pool.start()
        logger.info("worker_started", concurrency=settings.worker_concurrency)

    logger.info("cybertrace_started", version=__version__, environment=settings.env.value)
    try:
        yield
    finally:
        if pool is not None:
            pool.stop()
            logger.info("worker_stopped")


def create_app() -> FastAPI:
    app = FastAPI(
        title="CYBERTRACE API",
        description=DESCRIPTION,
        version=__version__,
        lifespan=lifespan,
        # Interactive documentation is a development affordance, not a production surface.
        docs_url="/docs" if not settings.is_production else None,
        redoc_url="/redoc" if not settings.is_production else None,
        openapi_url="/openapi.json" if not settings.is_production else None,
    )

    # Middleware executes in reverse registration order, so the request id is established
    # first and security headers are applied to every response including error responses.
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(AuthThrottleMiddleware)
    app.add_middleware(
        CORSMiddleware,
        # An explicit allowlist, never a wildcard: credentials are involved.
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-CSRF-Token", "X-Request-ID"],
        expose_headers=["X-Request-ID", "Content-Disposition"],
        max_age=600,
    )
    app.add_middleware(RequestContextMiddleware)

    _register_exception_handlers(app)

    app.include_router(api_router, prefix=settings.api_prefix)

    @app.get("/health", tags=["System"], summary="Liveness probe")
    def health() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    return app


def _register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(CybertraceError)
    async def handle_domain_error(request: Request, exc: CybertraceError) -> JSONResponse:
        request_id = getattr(request.state, "request_id", None)
        # Authorization failures are logged at warning level because they are security
        # signals, not routine validation noise.
        log = logger.warning if exc.status_code in (401, 403, 409, 429) else logger.info
        log(
            "domain_error",
            code=exc.code,
            status=exc.status_code,
            path=request.url.path,
            message=exc.message,
        )
        headers = {}
        if exc.status_code == 401:
            headers["WWW-Authenticate"] = "Bearer"
        retry_after = exc.details.get("retry_after_seconds")
        if retry_after:
            headers["Retry-After"] = str(retry_after)
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": {
                    "code": exc.code,
                    "message": exc.message,
                    "details": exc.details,
                    "request_id": request_id,
                }
            },
            headers=headers or None,
        )

    @app.exception_handler(RequestValidationError)
    async def handle_validation_error(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        fields = [
            {
                "field": ".".join(str(part) for part in error["loc"][1:]) or "body",
                "message": error["msg"],
            }
            for error in exc.errors()
        ]
        return JSONResponse(
            status_code=422,
            content={
                "error": {
                    "code": "validation_failed",
                    "message": "The submitted data is not valid.",
                    "details": {"fields": fields},
                    "request_id": getattr(request.state, "request_id", None),
                }
            },
        )

    @app.exception_handler(Exception)
    async def handle_unexpected(request: Request, exc: Exception) -> JSONResponse:
        # Log the detail, return none of it: an unexpected failure must not become an
        # information disclosure about schema, paths or evidence.
        logger.exception("unhandled_error", path=request.url.path, error=str(exc))
        return JSONResponse(
            status_code=500,
            content={
                "error": {
                    "code": "internal_error",
                    "message": "An unexpected error occurred. The incident has been logged.",
                    "details": {},
                    "request_id": getattr(request.state, "request_id", None),
                }
            },
        )


app = create_app()
