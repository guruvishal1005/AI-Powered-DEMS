"""Application error taxonomy.

Every error carries a stable machine-readable ``code`` so the frontend can react
without string-matching human prose.
"""

from __future__ import annotations

from typing import Any


class CybertraceError(Exception):
    """Base class for expected, client-visible failures."""

    status_code: int = 400
    code: str = "error"

    def __init__(self, message: str, *, details: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details or {}


class ValidationFailed(CybertraceError):
    status_code = 422
    code = "validation_failed"


class NotFound(CybertraceError):
    status_code = 404
    code = "not_found"

    def __init__(self, resource: str, identifier: str | int | None = None) -> None:
        label = (
            f"{resource} '{identifier}' was not found" if identifier else f"{resource} not found"
        )
        super().__init__(label, details={"resource": resource})


class Conflict(CybertraceError):
    status_code = 409
    code = "conflict"


class AuthenticationRequired(CybertraceError):
    status_code = 401
    code = "authentication_required"


class InvalidCredentials(AuthenticationRequired):
    code = "invalid_credentials"


class AccountLocked(AuthenticationRequired):
    code = "account_locked"


class PermissionDenied(CybertraceError):
    """Raised when the actor lacks a permission or is outside the object's access scope."""

    status_code = 403
    code = "permission_denied"


class RateLimited(CybertraceError):
    status_code = 429
    code = "rate_limited"


class IntegrityViolation(CybertraceError):
    """Raised when evidence or an append-only chain fails verification."""

    status_code = 409
    code = "integrity_violation"


class StorageError(CybertraceError):
    status_code = 500
    code = "storage_error"


class UnsupportedEvidence(CybertraceError):
    status_code = 415
    code = "unsupported_evidence"
