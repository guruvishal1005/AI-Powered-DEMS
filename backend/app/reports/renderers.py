"""Report renderers: HTML/PDF via WeasyPrint, plus JSON and CSV inventory exports."""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from app.core.clock import utcnow
from app.models.enums import ReportFormat

TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"

_env = Environment(
    loader=FileSystemLoader(str(TEMPLATE_DIR)),
    autoescape=select_autoescape(["html"]),
)


def render_html(snapshot: dict[str, Any], *, title: str, classification: str) -> str:
    template = _env.get_template("report.html")
    return template.render(
        snapshot=snapshot,
        title=title,
        classification=classification,
        generated_at=utcnow().isoformat(),
    )


def render_pdf(html: str) -> bytes:
    from weasyprint import HTML

    return HTML(string=html, base_url=str(TEMPLATE_DIR)).write_pdf()


def render_json(snapshot: dict[str, Any]) -> bytes:
    return json.dumps(snapshot, indent=2, ensure_ascii=False, sort_keys=True).encode("utf-8")


def render_csv_inventory(snapshot: dict[str, Any]) -> bytes:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(
        [
            "reference",
            "title",
            "filename",
            "type",
            "sha256",
            "size_bytes",
            "mime_type",
            "integrity_status",
            "custody_intact",
            "acquired_at",
            "acquired_by",
        ]
    )
    for item in snapshot.get("evidence_inventory", []):
        custody = item.get("custody") or {}
        writer.writerow(
            [
                item.get("reference"),
                item.get("title"),
                item.get("original_filename"),
                item.get("evidence_type"),
                item.get("sha256"),
                item.get("size_bytes"),
                item.get("mime_type"),
                item.get("integrity_status"),
                custody.get("trustworthy"),
                item.get("acquired_at"),
                item.get("acquired_by"),
            ]
        )
    return buffer.getvalue().encode("utf-8")


def render(
    snapshot: dict[str, Any], fmt: ReportFormat, *, title: str, classification: str
) -> bytes:
    if fmt is ReportFormat.json:
        return render_json(snapshot)
    if fmt is ReportFormat.csv:
        return render_csv_inventory(snapshot)
    html = render_html(snapshot, title=title, classification=classification)
    if fmt is ReportFormat.html:
        return html.encode("utf-8")
    return render_pdf(html)
