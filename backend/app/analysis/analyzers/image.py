"""Image analyzer: EXIF metadata, GPS coordinates and camera provenance.

Photographs carry an unusual amount of investigative value in their metadata: where the picture was
taken, on what device, when, and whether it has been through editing software. This analyzer
recovers that and converts GPS coordinates into a form the platform can correlate on.

GPS is stored in EXIF as degrees/minutes/seconds rationals plus a separate hemisphere reference,
and getting the reference wrong puts a location in the wrong hemisphere - so the conversion applies
the N/S and E/W references explicitly and records the precision it actually has rather than
implying more.

EXIF is also *writable*, which matters more than it might appear. Metadata absence is not evidence
of tampering (every social platform strips it on upload) and metadata presence is not proof of
origin (all of it can be edited). Both are reported as observations with that caveat attached.
"""

from __future__ import annotations

from datetime import UTC, datetime
from fractions import Fraction
from typing import Any

from app.analysis.base import (
    AnalyzerOutput,
    ArtifactHandle,
    BaseAnalyzer,
    ExtractedEntity,
    ExtractedFinding,
    ExtractedObservation,
)
from app.analysis.registry import register
from app.models.enums import (
    Confidence,
    EntityType,
    EvidenceType,
    ObservationKind,
    Severity,
)

MAX_IMAGE_BYTES = 256 * 1024 * 1024

# Software strings that indicate the image passed through an editor rather than coming straight
# off a camera. Not incriminating on its own; a resized photo is still a photo.
_EDITOR_HINTS = (
    "photoshop", "gimp", "lightroom", "paint.net", "pixelmator", "affinity",
    "snapseed", "picasa", "imagemagick", "ffmpeg", "canva", "figma",
)

_TIMESTAMP_TAGS = (
    ("DateTimeOriginal", "when the shutter fired"),
    ("DateTimeDigitized", "when the image was digitised"),
    ("DateTime", "when the file was last modified by the device or software"),
)


def _to_float(value: Any) -> float | None:
    """Coerce an EXIF rational into a float without raising on the malformed cases."""
    try:
        if isinstance(value, tuple) and len(value) == 2:
            return float(value[0]) / float(value[1]) if value[1] else None
        if isinstance(value, Fraction):
            return float(value)
        return float(value)
    except (TypeError, ValueError, ZeroDivisionError):
        return None


def _dms_to_degrees(parts: Any, reference: str | None) -> float | None:
    """Convert EXIF degrees/minutes/seconds plus hemisphere into signed decimal degrees."""
    if not isinstance(parts, (tuple, list)) or len(parts) != 3:
        return None
    degrees, minutes, seconds = (_to_float(part) for part in parts)
    if degrees is None or minutes is None or seconds is None:
        return None
    decimal = degrees + minutes / 60.0 + seconds / 3600.0
    # Southern and western hemispheres are negative; missing this inverts the location.
    if reference and reference.upper() in ("S", "W"):
        decimal = -decimal
    return decimal if -180.0 <= decimal <= 180.0 else None


class ImageAnalyzer(BaseAnalyzer):
    name = "image_exif"
    version = "1"
    description = "EXIF metadata, GPS location, camera identification and editing history"
    mime_prefixes = ("image/",)
    evidence_types = (EvidenceType.image,)
    max_size_bytes = MAX_IMAGE_BYTES

    def analyze(self, artifact: ArtifactHandle) -> AnalyzerOutput:
        output = AnalyzerOutput()

        try:
            from PIL import ExifTags, Image, UnidentifiedImageError
        except ImportError:  # pragma: no cover - Pillow is a declared dependency
            output.skip_reason = "Pillow is not installed, so image metadata cannot be read"
            return output

        with artifact.open_temp_file() as handle:
            output.bytes_examined = artifact.size_bytes
            try:
                # Decompression-bomb protection stays at Pillow's default: a crafted image that
                # expands to gigabytes is a real risk when processing untrusted evidence.
                with Image.open(handle) as image:
                    basics = {
                        "format": image.format,
                        "mode": image.mode,
                        "width": image.width,
                        "height": image.height,
                        "megapixels": round(image.width * image.height / 1_000_000, 2),
                        "animated": getattr(image, "is_animated", False),
                        "frame_count": getattr(image, "n_frames", 1),
                    }
                    raw_exif = image.getexif()
                    icc = bool(image.info.get("icc_profile"))
            except UnidentifiedImageError:
                output.skip_reason = (
                    "Content could not be decoded as an image despite an image content type, "
                    "which may indicate a corrupt or deliberately malformed file"
                )
                return output
            except (OSError, ValueError) as exc:
                output.skip_reason = f"Image could not be read: {type(exc).__name__}: {exc}"
                return output

        exif = self._flatten_exif(raw_exif, ExifTags)
        gps = self._gps(exif)
        timestamps = self._timestamps(exif)

        output.metadata = {
            **basics,
            "has_icc_profile": icc,
            "exif_present": bool(exif),
            "exif_tag_count": len(exif),
            "exif": exif,
            "gps": gps,
            "timestamps": {name: value.isoformat() for name, value in timestamps.items()},
            "camera": {
                "make": exif.get("Make"),
                "model": exif.get("Model"),
                "lens": exif.get("LensModel"),
                "serial": exif.get("BodySerialNumber") or exif.get("SerialNumber"),
                "software": exif.get("Software"),
            },
        }

        self._record_device_entities(output, exif)
        self._record_gps(output, gps, timestamps)
        self._record_timestamps(output, timestamps, exif)
        self._check_editing(output, exif)
        self._check_metadata_absence(output, exif, artifact)
        self._check_timestamp_consistency(output, timestamps)

        return output

    def _flatten_exif(self, raw: Any, exif_tags: Any) -> dict[str, Any]:
        """Turn Pillow's numeric EXIF tags into named, JSON-safe values."""
        if not raw:
            return {}

        flat: dict[str, Any] = {}

        def store(tag_id: Any, value: Any, table: dict[int, str]) -> None:
            name = table.get(tag_id, f"Tag{tag_id}")
            if isinstance(value, bytes):
                # Binary blobs such as MakerNote are recorded by size only; embedding kilobytes of
                # opaque bytes into metadata helps nobody and bloats every response.
                flat[name] = f"<{len(value)} bytes of binary data>"
            elif isinstance(value, tuple):
                converted = [_to_float(item) for item in value]
                flat[name] = (
                    converted if all(item is not None for item in converted) else str(value)
                )
            elif isinstance(value, (int, float, str)):
                flat[name] = value.strip() if isinstance(value, str) else value
            elif isinstance(value, Fraction):
                flat[name] = float(value)
            else:
                flat[name] = str(value)

        for tag_id, value in raw.items():
            store(tag_id, value, exif_tags.TAGS)

        for ifd_name, ifd_tag in (("Exif", 0x8769), ("GPS", 0x8825)):
            try:
                nested = raw.get_ifd(ifd_tag)
            except (KeyError, AttributeError, OSError):
                continue
            if not nested:
                continue
            table = exif_tags.GPSTAGS if ifd_name == "GPS" else exif_tags.TAGS
            for tag_id, value in nested.items():
                store(tag_id, value, table)

        return flat

    def _gps(self, exif: dict[str, Any]) -> dict[str, Any] | None:
        latitude = _dms_to_degrees(exif.get("GPSLatitude"), exif.get("GPSLatitudeRef"))
        longitude = _dms_to_degrees(exif.get("GPSLongitude"), exif.get("GPSLongitudeRef"))
        if latitude is None or longitude is None:
            return None

        altitude = _to_float(exif.get("GPSAltitude"))
        if altitude is not None and str(exif.get("GPSAltitudeRef", "0")).startswith("1"):
            altitude = -altitude

        return {
            "latitude": round(latitude, 6),
            "longitude": round(longitude, 6),
            "altitude_m": round(altitude, 2) if altitude is not None else None,
            "map_datum": exif.get("GPSMapDatum") or "WGS-84 (assumed)",
            "timestamp_utc": self._gps_time(exif),
            # Roughly 0.1 m at the equator - the limit of what six decimal places can express,
            # not a claim about the receiver's actual accuracy.
            "coordinate_precision_note": (
                "Coordinates are as recorded by the device. Consumer GPS is typically accurate to "
                "within 5-10 m outdoors and considerably worse indoors or among tall buildings."
            ),
        }

    def _gps_time(self, exif: dict[str, Any]) -> str | None:
        """Combine GPSDateStamp and GPSTimeStamp, which are genuinely UTC from the satellites."""
        date_stamp = exif.get("GPSDateStamp")
        time_stamp = exif.get("GPSTimeStamp")
        if not date_stamp or not isinstance(time_stamp, list) or len(time_stamp) != 3:
            return None
        try:
            hour, minute, second = (int(value) for value in time_stamp)
            parsed = datetime.strptime(str(date_stamp).strip(), "%Y:%m:%d")
        except (TypeError, ValueError):
            return None
        return parsed.replace(
            hour=min(hour, 23), minute=min(minute, 59), second=min(second, 59),
            tzinfo=UTC,
        ).isoformat()

    def _timestamps(self, exif: dict[str, Any]) -> dict[str, datetime]:
        found: dict[str, datetime] = {}
        for tag, _meaning in _TIMESTAMP_TAGS:
            raw = exif.get(tag)
            if not raw:
                continue
            try:
                # EXIF's own format, which carries no timezone at all.
                parsed = datetime.strptime(str(raw).strip(), "%Y:%m:%d %H:%M:%S")
            except (TypeError, ValueError):
                continue
            found[tag] = parsed.replace(tzinfo=UTC)
        return found

    def _record_device_entities(self, output: AnalyzerOutput, exif: dict[str, Any]) -> None:
        make = exif.get("Make")
        model = exif.get("Model")
        if make or model:
            label = " ".join(str(part) for part in (make, model) if part).strip()
            output.add_entity(
                ExtractedEntity(
                    type=EntityType.device,
                    value=label,
                    locator={"exif_tag": "Make/Model"},
                    context="capture_device",
                    excerpt=f"Make: {make} | Model: {model}",
                )
            )

        serial = exif.get("BodySerialNumber") or exif.get("SerialNumber")
        if serial:
            # A camera body serial is close to a unique device identifier, which makes it one of
            # the strongest links available between separate images.
            output.add_entity(
                ExtractedEntity(
                    type=EntityType.device_identifier,
                    value=str(serial),
                    locator={"exif_tag": "BodySerialNumber"},
                    context="camera_serial",
                )
            )

        for tag, context in (("Artist", "exif_artist"), ("Copyright", "exif_copyright")):
            value = exif.get(tag)
            if value and isinstance(value, str) and len(value) < 200:
                output.add_entity(
                    ExtractedEntity(
                        type=EntityType.person,
                        value=value,
                        locator={"exif_tag": tag},
                        context=context,
                        # Self-declared and freely editable, so recorded with reduced confidence.
                        confidence=0.5,
                    )
                )

        software = exif.get("Software")
        if software and isinstance(software, str):
            output.add_entity(
                ExtractedEntity(
                    type=EntityType.software,
                    value=software,
                    locator={"exif_tag": "Software"},
                    context="processing_software",
                )
            )

    def _record_gps(
        self,
        output: AnalyzerOutput,
        gps: dict[str, Any] | None,
        timestamps: dict[str, datetime],
    ) -> None:
        if gps is None:
            return

        coordinate = f"{gps['latitude']},{gps['longitude']}"
        output.add_entity(
            ExtractedEntity(
                type=EntityType.location,
                value=coordinate,
                locator={"exif_tag": "GPSLatitude/GPSLongitude"},
                context="capture_location",
                excerpt=(
                    f"{gps['latitude']}, {gps['longitude']}"
                    + (f" at {gps['altitude_m']} m" if gps.get("altitude_m") is not None else "")
                ),
            )
        )

        when = None
        if gps.get("timestamp_utc"):
            when = datetime.fromisoformat(str(gps["timestamp_utc"]))
            confidence = Confidence.high
            assumed = False
        elif "DateTimeOriginal" in timestamps:
            when = timestamps["DateTimeOriginal"]
            confidence = Confidence.moderate
            assumed = True

        if when is not None:
            output.add_observation(
                ExtractedObservation(
                    kind=ObservationKind.geolocation,
                    occurred_at=when,
                    summary=(
                        f"Image captured at {gps['latitude']}, {gps['longitude']}"
                    ),
                    locator={"exif_tag": "GPS"},
                    excerpt=coordinate,
                    target_value=coordinate,
                    time_confidence=confidence,
                    timezone_assumed=assumed,
                    attributes={
                        "latitude": gps["latitude"],
                        "longitude": gps["longitude"],
                        "altitude_m": gps.get("altitude_m"),
                        "time_source": (
                            "GPS satellite clock (UTC)"
                            if gps.get("timestamp_utc")
                            else "EXIF DateTimeOriginal, treated as UTC"
                        ),
                    },
                    entity_values=(coordinate,),
                )
            )

        output.add_finding(
            ExtractedFinding(
                code="image.gps_present",
                title="Image contains GPS coordinates",
                description=(
                    f"EXIF records a capture location of {gps['latitude']}, "
                    f"{gps['longitude']}"
                    + (
                        f" at an altitude of {gps['altitude_m']} m"
                        if gps.get("altitude_m") is not None
                        else ""
                    )
                    + ". Coordinates are written by the capturing device and can be edited "
                    "afterwards, so they place the *file's metadata* at this location rather than "
                    "proving the photograph was taken there."
                ),
                severity=Severity.informational,
                confidence=1.0,
                locator={"exif_tag": "GPS"},
                excerpt=coordinate,
                attributes={
                    "latitude": gps["latitude"],
                    "longitude": gps["longitude"],
                    "map_datum": gps["map_datum"],
                },
            )
        )

    def _record_timestamps(
        self, output: AnalyzerOutput, timestamps: dict[str, datetime], exif: dict[str, Any]
    ) -> None:
        original = timestamps.get("DateTimeOriginal") or timestamps.get("DateTimeDigitized")
        if original is None:
            return

        offset = exif.get("OffsetTimeOriginal") or exif.get("OffsetTime")
        device = " ".join(
            str(part) for part in (exif.get("Make"), exif.get("Model")) if part
        ).strip()

        output.add_observation(
            ExtractedObservation(
                kind=ObservationKind.file_created,
                occurred_at=original,
                summary=(
                    "Image captured"
                    + (f" on {device}" if device else "")
                    + (f" (device offset {offset})" if offset else "")
                ),
                locator={"exif_tag": "DateTimeOriginal"},
                excerpt=str(exif.get("DateTimeOriginal") or exif.get("DateTimeDigitized")),
                actor_value=device or None,
                # EXIF timestamps have no timezone field. Where the device recorded an offset it
                # is reported, but the value itself is still stored as local-time-as-UTC.
                time_confidence=Confidence.moderate,
                timezone_assumed=offset is None,
                attributes={
                    "device": device or None,
                    "device_utc_offset": offset,
                    "note": (
                        "EXIF timestamps carry no timezone. This value is the device's local "
                        "clock, interpreted as UTC."
                    ),
                },
            )
        )

    def _check_editing(self, output: AnalyzerOutput, exif: dict[str, Any]) -> None:
        software = str(exif.get("Software") or "").lower()
        matched = next((hint for hint in _EDITOR_HINTS if hint in software), None)
        if matched is None:
            return

        output.add_finding(
            ExtractedFinding(
                code="image.edited_by_software",
                title="Image was processed by editing software",
                description=(
                    f"The Software tag records {exif.get('Software')!r}, indicating the file was "
                    "written by an image editor rather than saved directly by a camera. Editing "
                    "is entirely routine - cropping, resizing and colour correction all leave "
                    "this trace - but it does mean the pixel data is not an unmodified original, "
                    "and any embedded metadata may have been rewritten in the process."
                ),
                severity=Severity.low,
                confidence=0.8,
                locator={"exif_tag": "Software"},
                excerpt=str(exif.get("Software")),
                attributes={"software": exif.get("Software"), "matched_editor": matched},
            )
        )

    def _check_metadata_absence(
        self, output: AnalyzerOutput, exif: dict[str, Any], artifact: ArtifactHandle
    ) -> None:
        if exif:
            return
        output.add_finding(
            ExtractedFinding(
                code="image.no_exif",
                title="Image carries no EXIF metadata",
                description=(
                    "No EXIF metadata is present, so no capture device, timestamp or location "
                    "can be recovered. This is the normal result for images downloaded from "
                    "messaging apps and social platforms, which strip metadata on upload, as well "
                    "as for screenshots and images produced by editors that discard it. Absence "
                    "of metadata is not by itself an indication of deliberate removal."
                ),
                severity=Severity.informational,
                confidence=1.0,
                locator={"scope": "metadata"},
                attributes={"format": artifact.mime_type},
            )
        )

    def _check_timestamp_consistency(
        self, output: AnalyzerOutput, timestamps: dict[str, datetime]
    ) -> None:
        original = timestamps.get("DateTimeOriginal")
        modified = timestamps.get("DateTime")
        if original is None or modified is None:
            return

        drift = (modified - original).total_seconds()
        # Modification before capture is impossible for an untouched file, so the metadata has
        # been rewritten or a device clock was reset between the two writes.
        if drift < -60:
            output.add_finding(
                ExtractedFinding(
                    code="image.timestamp_inconsistency",
                    title="Image modification time precedes its capture time",
                    description=(
                        f"DateTime ({modified.isoformat()}) is {abs(drift) / 60:.1f} minutes "
                        f"earlier than DateTimeOriginal ({original.isoformat()}). A file cannot "
                        "be modified before it was created, so at least one of these values has "
                        "been altered or written by a device with an incorrect clock."
                    ),
                    severity=Severity.medium,
                    confidence=0.8,
                    locator={"exif_tag": "DateTime"},
                    attributes={
                        "date_time_original": original.isoformat(),
                        "date_time": modified.isoformat(),
                        "drift_seconds": int(drift),
                        "method": "DateTime versus DateTimeOriginal ordering",
                    },
                )
            )


register(ImageAnalyzer())
