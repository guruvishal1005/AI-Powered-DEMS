"""Generate real demo artifacts: email, logs, JPEG+EXIF, PDF, CSV, archive."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from email.message import EmailMessage
from email.utils import format_datetime, make_msgid
from io import BytesIO
from zipfile import ZIP_DEFLATED, ZipFile

from PIL import Image
from PIL.TiffImagePlugin import IFDRational
from pypdf import PdfWriter

from app.seed.indicators import (
    ATTACKER_IP,
    C2_DOMAIN,
    C2_URL,
    GPS_LAT,
    GPS_LON,
    INSIDER_USER,
    SPOOFED_FROM,
    VICTIM_EMAIL,
    WALLET,
)


@dataclass(frozen=True, slots=True)
class GeneratedFile:
    filename: str
    content: bytes
    mime: str


def generate_all() -> dict[str, GeneratedFile]:
    return {
        "ransom_note": _pdf_ransom_note(),
        "auth_log": _auth_log(),
        "netflow": _netflow_csv(),
        "bec_email": _bec_email(),
        "nginx_log": _nginx_log(),
        "exfil_archive": _exfil_archive(),
        "camera_jpeg": _jpeg_with_gps(),
        "insider_syslog": _insider_syslog(),
    }


def _pdf_ransom_note() -> GeneratedFile:
    writer = PdfWriter()
    writer.add_blank_page(width=595, height=842)
    writer.add_metadata(
        {
            "/Author": "InvoiceLock",
            "/Title": "YOUR FILES ARE ENCRYPTED",
            "/Subject": f"Payment to {WALLET}",
            "/Creator": "InvoiceLock builder",
            "/Producer": "InvoiceLock",
        }
    )
    buffer = BytesIO()
    writer.write(buffer)
    return GeneratedFile("INVOICELOCK-README.pdf", buffer.getvalue(), "application/pdf")


def _auth_log() -> GeneratedFile:
    base = datetime(2026, 8, 12, 2, 14, tzinfo=UTC)
    lines = []
    for i in range(18):
        ts = (base + timedelta(seconds=i * 7)).strftime("%b %d %H:%M:%S")
        lines.append(
            f"{ts} fileserver sshd[4412]: Failed password for {INSIDER_USER} "
            f"from {ATTACKER_IP} port {51000 + i} ssh2"
        )
    ts_ok = (base + timedelta(minutes=3)).strftime("%b %d %H:%M:%S")
    lines.append(
        f"{ts_ok} fileserver sshd[4412]: Accepted password for {INSIDER_USER} "
        f"from {ATTACKER_IP} port 51220 ssh2"
    )
    lines.append(
        f"{ts_ok} fileserver sudo: {INSIDER_USER} : TTY=pts/0 ; PWD=/home/{INSIDER_USER} ; "
        "USER=root ; COMMAND=/usr/bin/systemctl stop backup.timer"
    )
    body = "\n".join(lines) + "\n"
    return GeneratedFile("fileserver.auth.log", body.encode("utf-8"), "text/plain")


def _netflow_csv() -> GeneratedFile:
    header = "timestamp,src_ip,src_port,dst_ip,dst_port,protocol,bytes,packets\n"
    rows = [
        f"2026-08-12T02:18:11Z,10.4.12.21,49152,{ATTACKER_IP},443,tcp,184320,88",
        f"2026-08-12T02:18:40Z,10.4.12.21,49153,{ATTACKER_IP},443,tcp,2048000,640",
        "2026-08-12T02:19:02Z,10.4.12.21,53,10.4.0.2,53,udp,128,2",
        f"2026-08-12T02:19:03Z,10.4.12.21,49154,{C2_DOMAIN},443,tcp,4096,12",
    ]
    body = header + "\n".join(rows) + "\n"
    return GeneratedFile("edge-firewall-netflow.csv", body.encode("utf-8"), "text/csv")


def _bec_email() -> GeneratedFile:
    sent = datetime(2026, 8, 11, 16, 42, tzinfo=UTC)
    msg = EmailMessage()
    msg["From"] = f"Globex AP <{SPOOFED_FROM}>"
    msg["To"] = f"Chief Financial Officer <{VICTIM_EMAIL}>"
    msg["Return-Path"] = f"bounce@{C2_DOMAIN}"
    msg["Reply-To"] = f"payments@{C2_DOMAIN}"
    msg["Subject"] = "Urgent: updated supplier payment details"
    msg["Date"] = format_datetime(sent)
    msg["Message-ID"] = make_msgid(domain=C2_DOMAIN)
    msg["Received"] = (
        f"from mail.{C2_DOMAIN} ({ATTACKER_IP}) by mx.globex-holding.example "
        f"with ESMTPS id 4k2s; {format_datetime(sent)}"
    )
    msg["Received"] = (
        f"from [{ATTACKER_IP}] by mail.{C2_DOMAIN} with ESMTP id a91; "
        f"{format_datetime(sent - timedelta(seconds=12))}"
    )
    msg["Authentication-Results"] = (
        "mx.globex-holding.example; spf=fail smtp.mailfrom="
        f"{C2_DOMAIN}; dkim=fail header.d={C2_DOMAIN}; dmarc=fail"
    )
    msg.set_content(
        "Please process the attached invoice against the new account today.\n"
        f"Payment confirmation should be sent to {SPOOFED_FROM}.\n"
        f"Staging copy: {C2_URL}\n"
    )
    return GeneratedFile("bec-supplier-payment.eml", msg.as_bytes(), "message/rfc822")


def _nginx_log() -> GeneratedFile:
    lines = [
        f'10.4.12.88 - {INSIDER_USER} [11/Aug/2026:09:14:02 +0000] '
        '"GET /share/board-minutes.pdf HTTP/1.1" 200 482110 "-" "Mozilla/5.0"',
        f'{ATTACKER_IP} - - [11/Aug/2026:16:48:11 +0000] '
        f'"GET /login HTTP/1.1" 200 8120 "https://{C2_DOMAIN}/" "Mozilla/5.0"',
        f'{ATTACKER_IP} - - [11/Aug/2026:16:48:19 +0000] '
        f'"POST /owa/auth.owa HTTP/1.1" 302 0 "https://mail.globex-holding.example/" "Mozilla/5.0"',
        f'10.4.12.88 - {INSIDER_USER} [12/Aug/2026:01:02:44 +0000] '
        '"GET /export/customer-db.csv HTTP/1.1" 200 12582912 "-" "curl/8.5.0"',
    ]
    body = "\n".join(lines) + "\n"
    return GeneratedFile("webmail.access.log", body.encode("utf-8"), "text/plain")


def _insider_syslog() -> GeneratedFile:
    lines = [
        f"Aug 12 01:02:40 workstation-14 usb-storage: device attached by {INSIDER_USER}",
        "Aug 12 01:03:11 workstation-14 kernel: copy /srv/finance/q2.xlsx -> /media/usb",
        f"Aug 12 01:04:02 workstation-14 systemd: session opened for user {INSIDER_USER}",
        f"Aug 12 01:11:18 workstation-14 sshd: Connection from {ATTACKER_IP} port 443",
    ]
    return GeneratedFile(
        "workstation-14.syslog", "\n".join(lines).encode("utf-8") + b"\n", "text/plain"
    )


def _exfil_archive() -> GeneratedFile:
    buffer = BytesIO()
    with ZipFile(buffer, "w", compression=ZIP_DEFLATED) as archive:
        archive.writestr(
            "customer-db-excerpt.csv",
            "name,email,account\n"
            f"Globex CFO,{VICTIM_EMAIL},8821-44\n"
            f"AP mailbox,{SPOOFED_FROM},8821-12\n",
        )
        archive.writestr("note.txt", f"Drop to {ATTACKER_IP} / {C2_DOMAIN}\nwallet {WALLET}\n")
    return GeneratedFile("usb-export-2026-08-12.zip", buffer.getvalue(), "application/zip")


def _dms(decimal: float) -> tuple[IFDRational, IFDRational, IFDRational]:
    """Encode a decimal degree as EXIF GPS rationals (degrees, minutes, seconds)."""
    absolute = abs(decimal)
    degrees = int(absolute)
    minutes_full = (absolute - degrees) * 60
    minutes = int(minutes_full)
    seconds = (minutes_full - minutes) * 60
    return (
        IFDRational(degrees, 1),
        IFDRational(minutes, 1),
        IFDRational(round(seconds * 100), 100),
    )


def _jpeg_with_gps() -> GeneratedFile:
    image = Image.new("RGB", (640, 480), color=(32, 48, 64))
    exif = image.getexif()
    exif[271] = "Canon"
    exif[272] = "EOS R6"
    exif[306] = "2026:08:11 09:14:02"
    gps = exif.get_ifd(0x8825)
    gps[1] = "N" if GPS_LAT >= 0 else "S"
    gps[2] = _dms(GPS_LAT)
    gps[3] = "E" if GPS_LON >= 0 else "W"
    gps[4] = _dms(GPS_LON)
    buffer = BytesIO()
    image.save(buffer, format="JPEG", exif=exif)
    return GeneratedFile("boardroom-camera.jpg", buffer.getvalue(), "image/jpeg")
