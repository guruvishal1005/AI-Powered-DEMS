"""Report artifact signing and verification.

The signature is over the snapshot SHA-256, not the rendered PDF. A PDF can be regenerated
from the snapshot; the snapshot is what the signer actually attested to. Verifying a report
therefore answers "is this the document that was signed?", independently of whether the
bytes of a particular PDF render still exist.
"""

from __future__ import annotations

from app.security.crypto import (
    sign_record,
    signing_key_id,
    verify_record_signature,
)


def sign_snapshot(snapshot_sha256: str) -> tuple[bytes, str]:
    return sign_record(snapshot_sha256), signing_key_id()


def verify_snapshot_signature(snapshot_sha256: str, signature: bytes) -> bool:
    return verify_record_signature(snapshot_sha256, signature)
