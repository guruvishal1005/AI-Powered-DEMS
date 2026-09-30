"""Cryptographic primitives.

Three separate concerns live here, each with a different threat model:

*Password verification* uses Argon2id, a memory-hard function, so a stolen database does not
yield a fast offline cracking target.

*Opaque tokens* (refresh tokens, API tokens) are random secrets stored only as SHA-256
digests. A plain digest is correct here rather than Argon2: the token already has full
entropy, so there is nothing to brute-force, and verification happens on every request.

*Record signing* uses Ed25519 over chain entry hashes, binding records to this deployment.
The signing key is derived deterministically from the master key with HKDF instead of being
a separate managed key, which keeps the operational surface to exactly one secret while
still rotating signatures when that secret is rotated.
"""

from __future__ import annotations

import functools
import hashlib
import hmac
import secrets

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from app.core.config import settings

# Argon2id parameters: ~64 MiB and 3 passes is a deliberate balance for an interactive login
# on commodity hardware, comfortably above the RFC 9106 low-memory baseline.
_password_hasher = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=4,
    hash_len=32,
    salt_len=16,
)

SIGNING_KEY_INFO = b"cybertrace-record-signing-v1"


def hash_password(password: str) -> str:
    return _password_hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    """Constant-time-ish verification that never raises for a wrong password."""
    try:
        return _password_hasher.verify(password_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def password_needs_rehash(password_hash: str) -> bool:
    """True when the stored hash used weaker parameters than currently configured."""
    try:
        return _password_hasher.check_needs_rehash(password_hash)
    except InvalidHashError:
        return True


def generate_token(num_bytes: int = 32) -> str:
    """A URL-safe opaque secret with `num_bytes` of entropy."""
    return secrets.token_urlsafe(num_bytes)


def hash_token(token: str) -> str:
    """Digest under which an opaque token is stored."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def constant_time_equal(left: str, right: str) -> bool:
    return hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@functools.lru_cache(maxsize=1)
def _signing_key() -> Ed25519PrivateKey:
    seed = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=SIGNING_KEY_INFO,
    ).derive(settings.master_key_bytes)
    return Ed25519PrivateKey.from_private_bytes(seed)


@functools.lru_cache(maxsize=1)
def signing_key_id() -> str:
    """Short public-key fingerprint, recorded on every signed row.

    Stored alongside signatures so that after a key rotation it is still possible to tell
    which key was expected to have signed a given historical record.
    """
    public_bytes = _signing_key().public_key().public_bytes_raw()
    return hashlib.sha256(public_bytes).hexdigest()[:16]


def signing_public_key() -> Ed25519PublicKey:
    return _signing_key().public_key()


def sign_record(entry_hash: str) -> bytes:
    """Sign a chain entry hash, binding the record to this deployment's key."""
    return _signing_key().sign(entry_hash.encode("utf-8"))


def verify_record_signature(entry_hash: str, signature: bytes) -> bool:
    try:
        signing_public_key().verify(signature, entry_hash.encode("utf-8"))
    except Exception:
        return False
    return True
