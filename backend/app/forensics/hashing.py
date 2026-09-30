"""Streaming multi-algorithm hashing.

Digests are computed incrementally during the single pass that reads an artifact, so ingestion
never holds a file in memory and never re-reads it to hash it. That is both a performance
property and a forensic one: the fingerprint is taken from exactly the byte sequence that was
written, not from a later re-read that could differ.

Three algorithms are recorded per artifact. SHA-256 is the working identity used for addressing,
deduplication and integrity checks. SHA-1 and MD5 are legacy digests, kept because forensic
tooling, NSRL reference sets and threat intelligence feeds are still keyed on them - they exist
for cross-referencing external data, never as an integrity control.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterator
from dataclasses import dataclass
from typing import BinaryIO

from app.core.config import settings


@dataclass(frozen=True, slots=True)
class HashSet:
    """Digests and length of one byte sequence."""

    sha256: str
    sha1: str
    md5: str
    size_bytes: int


class MultiHasher:
    """Feeds chunks into several digest algorithms at once."""

    __slots__ = ("_md5", "_sha1", "_sha256", "_size")

    def __init__(self) -> None:
        self._sha256 = hashlib.sha256()
        # SHA-1 and MD5 are not used as integrity controls - SHA-256 is. They are computed so
        # that hashes recorded here can be matched against external reference sets and threat
        # intelligence feeds, which are still overwhelmingly keyed on these digests.
        self._sha1 = hashlib.sha1(usedforsecurity=False)
        self._md5 = hashlib.md5(usedforsecurity=False)
        self._size = 0

    def update(self, chunk: bytes) -> None:
        self._sha256.update(chunk)
        self._sha1.update(chunk)
        self._md5.update(chunk)
        self._size += len(chunk)

    @property
    def size_bytes(self) -> int:
        """Bytes consumed so far, so callers can enforce limits mid-stream."""
        return self._size

    def result(self) -> HashSet:
        return HashSet(
            sha256=self._sha256.hexdigest(),
            sha1=self._sha1.hexdigest(),
            md5=self._md5.hexdigest(),
            size_bytes=self._size,
        )


def iter_chunks(stream: BinaryIO, chunk_size: int | None = None) -> Iterator[bytes]:
    """Yield fixed-size chunks from a binary stream until exhausted."""
    size = chunk_size or settings.hash_chunk_bytes
    while True:
        chunk = stream.read(size)
        if not chunk:
            return
        yield chunk


def hash_stream(stream: BinaryIO) -> HashSet:
    hasher = MultiHasher()
    for chunk in iter_chunks(stream):
        hasher.update(chunk)
    return hasher.result()


def hash_bytes(data: bytes) -> HashSet:
    hasher = MultiHasher()
    hasher.update(data)
    return hasher.result()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
