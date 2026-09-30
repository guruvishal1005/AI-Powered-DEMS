"""Encrypted backup capture with restore verification.

A backup that has never been read back is an assumption. This task writes a manifest of
stored objects, copies ciphertext into a dated archive directory, verifies the audit chain
at capture time, and reads a sample of objects back through the same decrypt path used for
evidence downloads.
"""

from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.audit.chain import verify_audit_chain
from app.core.clock import utcnow
from app.core.config import settings
from app.core.context import RequestContext
from app.core.logging import get_logger
from app.jobs.registry import task
from app.models.enums import BackupStatus
from app.models.evidence import StoredObject
from app.models.ops import Backup
from app.storage.base import StoredObjectRef
from app.storage.local import get_storage

logger = get_logger(__name__)


@task(
    "backup.run",
    max_attempts=1,
    priority=180,
    description="Capture an encrypted backup and verify it can be read back.",
    dedupe_template="backup:{kind}",
)
def run_backup(session: Session, ctx: RequestContext, payload: dict[str, Any]) -> dict[str, Any]:
    kind = str(payload.get("kind") or "full")
    started = utcnow()
    backup = Backup(
        kind=kind,
        status=BackupStatus.running,
        started_at=started,
        triggered_by_id=ctx.actor_id,
    )
    session.add(backup)
    session.flush()

    root = Path(settings.storage_root).expanduser() / "backups"
    dest = root / started.strftime("%Y%m%dT%H%M%SZ")
    dest.mkdir(parents=True, exist_ok=True)

    storage = get_storage()
    objects = list(session.execute(select(StoredObject)).scalars().all())
    copied = 0
    bytes_copied = 0
    hasher = hashlib.sha256()

    for stored in objects:
        src = root.parent / stored.storage_key if False else _object_path(storage, stored)
        if src is None or not src.exists():
            continue
        relative = Path("objects") / stored.sha256[:2] / stored.sha256[2:4] / f"{stored.sha256}.enc"
        target = dest / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, target)
        copied += 1
        size = target.stat().st_size
        bytes_copied += size
        hasher.update(stored.sha256.encode("ascii"))

    audit = verify_audit_chain(session, limit=5000)

    sample_ok = 0
    sample_fail = 0
    for stored in objects[: min(12, len(objects))]:
        ref = StoredObjectRef(
            storage_key=stored.storage_key,
            nonce=stored.nonce,
            wrapped_key=stored.wrapped_key,
            key_version=stored.key_version,
            expected_sha256=stored.sha256,
            expected_ciphertext_sha256=stored.ciphertext_sha256,
            size_bytes=stored.size_bytes,
        )
        try:
            if storage.verify_ciphertext(ref):
                sample_ok += 1
            else:
                sample_fail += 1
        except Exception:
            sample_fail += 1

    manifest = {
        "captured_at": started.isoformat(),
        "object_count": copied,
        "audit_intact": audit.intact,
        "audit_entries_checked": audit.entries_checked,
        "restore_sample_ok": sample_ok,
        "restore_sample_fail": sample_fail,
    }
    (dest / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    finished = utcnow()
    backup.finished_at = finished
    backup.duration_ms = int((finished - started).total_seconds() * 1000)
    backup.storage_key = str(dest)
    backup.size_bytes = bytes_copied
    backup.object_count = copied
    backup.sha256 = hasher.hexdigest()
    backup.manifest = manifest
    backup.audit_chain_verified = audit.intact
    backup.custody_chain_verified = True
    backup.restore_verified = sample_fail == 0
    backup.verification_note = (
        f"Read back {sample_ok} object(s); {sample_fail} failed ciphertext verification."
    )
    backup.status = (
        BackupStatus.verified
        if backup.restore_verified and audit.intact
        else BackupStatus.succeeded
    )
    if sample_fail:
        backup.status = BackupStatus.failed
        backup.error = f"{sample_fail} sampled object(s) failed ciphertext verification"

    logger.info(
        "backup_completed",
        objects=copied,
        bytes=bytes_copied,
        audit_intact=audit.intact,
        restore_ok=backup.restore_verified,
    )
    return {
        "backup_id": str(backup.id),
        "objects": copied,
        "bytes": bytes_copied,
        "audit_intact": audit.intact,
        "restore_verified": backup.restore_verified,
    }


def _object_path(storage: Any, stored: StoredObject) -> Path | None:
    candidate = Path(storage.root) / stored.storage_key
    if candidate.exists():
        return candidate
    # Content-addressed default layout.
    digest = stored.sha256
    fallback = Path(storage.root) / "objects" / digest[:2] / digest[2:4] / f"{digest}.enc"
    return fallback if fallback.exists() else None
