"""Structured logging.

Logs from a forensic platform are themselves sensitive: they must never leak evidence
content, credentials or tokens. :func:`_redact` strips known-sensitive keys from every
event before it is rendered.
"""

from __future__ import annotations

import logging
import sys
from typing import Any

import structlog

from app.core.config import settings

SENSITIVE_KEYS = frozenset(
    {
        "password",
        "new_password",
        "current_password",
        "token",
        "access_token",
        "refresh_token",
        "authorization",
        "cookie",
        "set-cookie",
        "secret",
        "secret_key",
        "master_key",
        "data_key",
        "wrapped_key",
        "api_key",
        "csrf",
        "excerpt",  # analyzer excerpts can contain evidence content
        "plaintext",
    }
)
REDACTED = "[redacted]"


def _redact(
    _logger: Any, _name: str, event_dict: structlog.types.EventDict
) -> structlog.types.EventDict:
    for key in list(event_dict):
        if key.lower() in SENSITIVE_KEYS:
            event_dict[key] = REDACTED
    return event_dict


def configure_logging() -> None:
    level = logging.DEBUG if settings.debug else logging.INFO

    renderer: structlog.types.Processor = (
        structlog.dev.ConsoleRenderer(colors=True)
        if not settings.is_production
        else structlog.processors.JSONRenderer()
    )

    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            _redact,
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            renderer,
        ],
        wrapper_class=structlog.make_filtering_bound_logger(level),
        logger_factory=structlog.PrintLoggerFactory(file=sys.stderr),
        cache_logger_on_first_use=True,
    )

    logging.basicConfig(level=level, format="%(message)s", stream=sys.stderr, force=True)
    for noisy in ("uvicorn.access", "sqlalchemy.engine.Engine", "multipart"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    return structlog.get_logger(name)
