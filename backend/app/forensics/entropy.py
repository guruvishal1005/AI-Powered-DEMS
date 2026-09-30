"""Shannon entropy measurement over artifact bytes.

Entropy is a cheap, well-understood signal for whether data is compressed or encrypted. Random
and encrypted data approaches the 8.0 bits-per-byte ceiling, natural language sits near 4.5, and
structured text lower still. On its own it proves nothing - a ZIP archive is legitimately
high-entropy - which is why the interpretation returned here is always paired with the detected
file type before anything is presented as noteworthy.

The windowed profile matters more than the overall figure. A document whose average entropy is
unremarkable but which contains one maximal-entropy region is far more interesting than a
uniformly high-entropy archive, because that shape is what appended encrypted payloads and
embedded packed executables look like.
"""

from __future__ import annotations

import math
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass

# Above this, a byte sequence is statistically indistinguishable from random data.
HIGH_ENTROPY_THRESHOLD = 7.5
MODERATE_ENTROPY_THRESHOLD = 6.0
WINDOW_BYTES = 8192

# Types whose content is expected to be near-random, so high entropy carries no signal.
_COMPRESSED_FAMILIES = (
    "application/zip",
    "application/gzip",
    "application/x-7z",
    "application/vnd.rar",
    "application/x-bzip",
    "application/x-xz",
    "image/jpeg",
    "image/png",
    "image/webp",
    "video/",
    "audio/",
    "application/pdf",
    "application/vnd.openxmlformats",
)


@dataclass(frozen=True, slots=True)
class EntropyProfile:
    """Overall and windowed entropy for one artifact."""

    overall: float
    window_count: int
    max_window: float
    min_window: float
    mean_window: float
    high_entropy_window_ratio: float
    # Byte offsets of the windows with the highest entropy, for analyst follow-up.
    peak_offsets: tuple[int, ...]

    def as_metadata(self) -> dict[str, object]:
        return {
            "overall_bits_per_byte": round(self.overall, 4),
            "window_bytes": WINDOW_BYTES,
            "window_count": self.window_count,
            "max_window": round(self.max_window, 4),
            "min_window": round(self.min_window, 4),
            "mean_window": round(self.mean_window, 4),
            "high_entropy_window_ratio": round(self.high_entropy_window_ratio, 4),
            "peak_offsets": list(self.peak_offsets),
        }


def shannon_entropy(data: bytes) -> float:
    """Bits of entropy per byte, in the range 0.0 to 8.0."""
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


class EntropyScanner:
    """Accumulates entropy statistics over a stream without buffering it.

    Byte frequencies are kept for the whole artifact to give an exact overall figure, while
    windows are summarised as they complete. Memory use is therefore bounded at 256 counters
    plus one window, whatever the artifact's size.
    """

    __slots__ = ("_buffer", "_global", "_offset", "_windows")

    def __init__(self) -> None:
        self._global: Counter[int] = Counter()
        self._buffer = bytearray()
        self._windows: list[tuple[int, float]] = []
        self._offset = 0

    def update(self, chunk: bytes) -> None:
        self._global.update(chunk)
        self._buffer.extend(chunk)
        while len(self._buffer) >= WINDOW_BYTES:
            window = bytes(self._buffer[:WINDOW_BYTES])
            del self._buffer[:WINDOW_BYTES]
            self._windows.append((self._offset, shannon_entropy(window)))
            self._offset += WINDOW_BYTES

    def result(self) -> EntropyProfile:
        windows = list(self._windows)
        # A trailing partial window still counts, provided it is large enough to be meaningful.
        if len(self._buffer) >= 512:
            windows.append((self._offset, shannon_entropy(bytes(self._buffer))))

        total = sum(self._global.values())
        if total == 0:
            return EntropyProfile(0.0, 0, 0.0, 0.0, 0.0, 0.0, ())

        overall = -sum(
            (count / total) * math.log2(count / total) for count in self._global.values()
        )

        if not windows:
            # Artifact smaller than the minimum window: the overall figure is all there is.
            return EntropyProfile(overall, 0, overall, overall, overall, 0.0, ())

        values = [value for _, value in windows]
        high = [value for value in values if value >= HIGH_ENTROPY_THRESHOLD]
        peaks = sorted(windows, key=lambda item: item[1], reverse=True)[:5]

        return EntropyProfile(
            overall=overall,
            window_count=len(windows),
            max_window=max(values),
            min_window=min(values),
            mean_window=sum(values) / len(values),
            high_entropy_window_ratio=len(high) / len(values),
            peak_offsets=tuple(offset for offset, _ in peaks),
        )


def scan_stream(chunks: Iterable[bytes]) -> EntropyProfile:
    scanner = EntropyScanner()
    for chunk in chunks:
        scanner.update(chunk)
    return scanner.result()


def is_expected_high_entropy(mime: str) -> bool:
    return any(mime.startswith(family) for family in _COMPRESSED_FAMILIES)


def interpret(profile: EntropyProfile, mime: str) -> str | None:
    """Describe what the entropy shape suggests, or ``None`` when unremarkable.

    Returns prose for an analyst rather than a verdict. Where high entropy is normal for the
    file type, only the *localised* case is reported, because that is the one the type does not
    already explain.
    """
    expected_high = is_expected_high_entropy(mime)

    localised_peak = (
        profile.window_count >= 4
        and profile.max_window >= HIGH_ENTROPY_THRESHOLD
        and profile.mean_window < MODERATE_ENTROPY_THRESHOLD
    )
    if localised_peak:
        return (
            f"Entropy is uneven: it averages {profile.mean_window:.2f} bits/byte but peaks at "
            f"{profile.max_window:.2f} near offset {profile.peak_offsets[0]}. A localised "
            "high-entropy region in otherwise low-entropy data can indicate appended "
            "compressed or encrypted content."
        )

    if expected_high:
        return None

    if profile.overall >= HIGH_ENTROPY_THRESHOLD:
        return (
            f"Entropy of {profile.overall:.2f} bits/byte is near the theoretical maximum of "
            f"8.0, which is characteristic of encrypted or compressed data. The detected type "
            f"({mime}) does not normally exhibit this."
        )

    if profile.overall <= 1.5:
        return (
            f"Entropy of {profile.overall:.2f} bits/byte is unusually low, indicating highly "
            "repetitive content such as padding, sparse regions or a wiped area."
        )

    return None
