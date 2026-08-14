"""
AuditForge PDF reporting module.

Generates professional client-ready security assessment reports
from AuditForge JSONReport data.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    HRFlowable,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from src.auditforge.reports.json_report import (
    JSONReport,
    report_to_dict,
)


# ---------------------------------------------------------------------------
# PDF Constants
# ---------------------------------------------------------------------------

PAGE_WIDTH, PAGE_HEIGHT = A4

DARK_BACKGROUND = colors.HexColor("#080808")
SURFACE = colors.HexColor("#111111")
PRIMARY_RED = colors.HexColor("#D90429")
DARK_RED = colors.HexColor("#8B0000")
WHITE = colors.HexColor("#F5F5F5")
SECONDARY_TEXT = colors.HexColor("#A0A0A0")
BORDER = colors.HexColor("#292929")

SUCCESS = colors.HexColor("#22C55E")
WARNING = colors.HexColor("#F59E0B")
CRITICAL = colors.HexColor("#EF4444")


# ---------------------------------------------------------------------------
# Styles
# ---------------------------------------------------------------------------


def _build_styles() -> dict[str, ParagraphStyle]:
    """Build PDF paragraph styles."""

    base = getSampleStyleSheet()

    return {
        "title": ParagraphStyle(
            "AuditForgeTitle",
            parent=base["Title"],
            fontName="Helvetica-Bold",
            fontSize=24,
            leading=28,
            alignment=TA_CENTER,
            textColor=PRIMARY_RED,
            spaceAfter=8 * mm,
        ),
        "subtitle": ParagraphStyle(
            "AuditForgeSubtitle",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=10,
            leading=14,
            alignment=TA_CENTER,
            textColor=SECONDARY_TEXT,
            spaceAfter=10 * mm,
        ),
        "heading": ParagraphStyle(
            "AuditForgeHeading",
            parent=base["Heading1"],
            fontName="Helvetica-Bold",
            fontSize=15,
            leading=19,
            textColor=PRIMARY_RED,
            spaceBefore=7 * mm,
            spaceAfter=4 * mm,
        ),
        "subheading": ParagraphStyle(
            "AuditForgeSubheading",
            parent=base["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=11,
            leading=14,
            textColor=WHITE,
            spaceBefore=4 * mm,
            spaceAfter=2 * mm,
        ),
        "body": ParagraphStyle(
            "AuditForgeBody",
            parent=base["BodyText"],
            fontName="Helvetica",
            fontSize=9,
            leading=13,
            textColor=colors.HexColor("#222222"),
            spaceAfter=3 * mm,
        ),
        "small": ParagraphStyle(
            "AuditForgeSmall",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=7.5,
            leading=10,
            textColor=SECONDARY_TEXT,
        ),
        "finding": ParagraphStyle(
            "AuditForgeFinding",
            parent=base["BodyText"],
            fontName="Helvetica",
            fontSize=9,
            leading=13,
            textColor=colors.HexColor("#222222"),
            spaceAfter=2 * mm,
        ),
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _safe_text(value: Any) -> str:
    """Convert a value safely to display text."""
    if value is None:
        return "N/A"

    return str(value)


def _severity_color(severity: str) -> colors.Color:
    """Return display color for a severity."""
    normalized = severity.strip().lower()

    if normalized == "critical":
        return CRITICAL

    if normalized == "high":
        return colors.HexColor("#C2410C")

    if normalized == "medium":
        return WARNING

    if normalized == "low":
        return PRIMARY_RED

    if normalized == "info":
        return SECONDARY_TEXT

    return SECONDARY_TEXT


def _footer(
    canvas,
    doc,
) -> None:
    """Draw footer on every page."""
    canvas.saveState()

    canvas.setStrokeColor(BORDER)
    canvas.line(
        18 * mm,
        13 * mm,
        PAGE_WIDTH - 18 * mm,
        13 * mm,
    )

    canvas.setFont(
        "Helvetica",
        7,
    )

    canvas.setFillColor(
        colors.HexColor("#666666")
    )

    canvas.drawString(
        18 * mm,
        8 * mm,
        "AuditForge — Assess. Analyze. Report.",
    )

    canvas.drawRightString(
        PAGE_WIDTH - 18 * mm,
        8 * mm,
        f"Page {doc.page}",
    )

    canvas.restoreState()


def _section_heading(
    text: str,
    styles: dict[str, ParagraphStyle],
) -> list[Any]:
    """Create a report section heading."""
    return [
        Paragraph(
            text,
            styles["heading"],
        ),
        HRFlowable(
            width="100%",
            thickness=0.7,
            color=PRIMARY_RED,
            spaceAfter=4 * mm,
        ),
    ]


# ---------------------------------------------------------------------------
# Cover
# ---------------------------------------------------------------------------


def _build_cover(
    report: JSONReport,
    styles: dict[str, ParagraphStyle],
) -> list[Any]:
    """Build report cover content."""

    metadata = report.metadata

    story: list[Any] = []

    story.append(
        Spacer(
            1,
            35 * mm,
        )
    )

    story.append(
        Paragraph(
            "AUDITFORGE",
            styles["title"],
        )
    )

    story.append(
        Paragraph(
            "Automated Security Assessment & Reporting Platform",
            styles["subtitle"],
        )
    )

    story.append(
        Paragraph(
            _safe_text(
                metadata.assessment_name
            ),
            ParagraphStyle(
                "AssessmentCover",
                parent=styles["heading"],
                alignment=TA_CENTER,
                fontSize=17,
                textColor=colors.HexColor(
                    "#222222"
                ),
            ),
        )
    )

    story.append(
        Spacer(
            1,
            8 * mm,
        )
    )

    metadata_rows = [
        ["Target", _safe_text(metadata.target)],
        [
            "Client",
            _safe_text(metadata.client_name),
        ],
        [
            "Tester",
            _safe_text(metadata.tester_name),
        ],
        [
            "Assessment ID",
            _safe_text(metadata.assessment_id),
        ],
        [
            "Created",
            _safe_text(metadata.created_at),
        ],
    ]

    table = Table(
        metadata_rows,
        colWidths=[
            40 * mm,
            120 * mm,
        ],
    )

    table.setStyle(
        TableStyle(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (0, -1),
                    SURFACE,
                ),
                (
                    "TEXTCOLOR",
                    (0, 0),
                    (0, -1),
                    WHITE,
                ),
                (
                    "TEXTCOLOR",
                    (1, 0),
                    (1, -1),
                    colors.HexColor("#222222"),
                ),
                (
                    "FONTNAME",
                    (0, 0),
                    (0, -1),
                    "Helvetica-Bold",
                ),
                (
                    "FONTNAME",
                    (1, 0),
                    (1, -1),
                    "Helvetica",
                ),
                (
                    "FONTSIZE",
                    (0, 0),
                    (-1, -1),
                    9,
                ),
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.5,
                    BORDER,
                ),
                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "MIDDLE",
                ),
                (
                    "LEFTPADDING",
                    (0, 0),
                    (-1, -1),
                    6,
                ),
                (
                    "RIGHTPADDING",
                    (0, 0),
                    (-1, -1),
                    6,
                ),
                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, -1),
                    7,
                ),
                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    7,
                ),
            ]
        )
    )

    story.append(table)

    story.append(
        Spacer(
            1,
            35 * mm,
        )
    )

    story.append(
        Paragraph(
            "CONFIDENTIAL SECURITY ASSESSMENT",
            ParagraphStyle(
                "Confidential",
                parent=styles["small"],
                alignment=TA_CENTER,
                textColor=DARK_RED,
            ),
        )
    )

    story.append(
        Spacer(
            1,
            10 * mm,
        )
    )

    return story


# ---------------------------------------------------------------------------
# Executive Summary
# ---------------------------------------------------------------------------


def _build_summary(
    report: JSONReport,
    styles: dict[str, ParagraphStyle],
) -> list[Any]:
    """Build executive summary section."""

    story = _section_heading(
        "1. Executive Summary",
        styles,
    )

    summary = report.summary

    if not summary:
        story.append(
            Paragraph(
                "No executive summary data was provided.",
                styles["body"],
            )
        )
        return story

    rows = [
        [
            Paragraph(
                "<b>Metric</b>",
                styles["body"],
            ),
            Paragraph(
                "<b>Value</b>",
                styles["body"],
            ),
        ]
    ]

    for key, value in summary.items():
        rows.append(
            [
                Paragraph(
                    _safe_text(key),
                    styles["body"],
                ),
                Paragraph(
                    _safe_text(value),
                    styles["body"],
                ),
            ]
        )

    table = Table(
        rows,
        colWidths=[
            65 * mm,
            95 * mm,
        ],
    )

    table.setStyle(
        TableStyle(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    SURFACE,
                ),
                (
                    "TEXTCOLOR",
                    (0, 0),
                    (-1, 0),
                    WHITE,
                ),
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.4,
                    BORDER,
                ),
                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "TOP",
                ),
            ]
        )
    )

    story.append(table)

    return story


# ---------------------------------------------------------------------------
# Assets
# ---------------------------------------------------------------------------


def _build_assets(
    report: JSONReport,
    styles: dict[str, ParagraphStyle],
) -> list[Any]:
    """Build asset inventory section."""

    story = _section_heading(
        "2. Asset Inventory",
        styles,
    )

    if not report.assets:
        story.append(
            Paragraph(
                "No assets were recorded.",
                styles["body"],
            )
        )
        return story

    headers = list(
        report.assets[0].keys()
    )

    rows = [
        [
            Paragraph(
                f"<b>{_safe_text(header)}</b>",
                styles["body"],
            )
            for header in headers
        ]
    ]

    for asset in report.assets:
        rows.append(
            [
                Paragraph(
                    _safe_text(
                        asset.get(header)
                    ),
                    styles["body"],
                )
                for header in headers
            ]
        )

    column_width = (
        160 * mm / max(len(headers), 1)
    )

    table = Table(
        rows,
        colWidths=[
            column_width
            for _ in headers
        ],
        repeatRows=1,
    )

    table.setStyle(
        TableStyle(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    SURFACE,
                ),
                (
                    "TEXTCOLOR",
                    (0, 0),
                    (-1, 0),
                    WHITE,
                ),
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.4,
                    BORDER,
                ),
                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "TOP",
                ),
            ]
        )
    )

    story.append(table)

    return story


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------


def _build_findings(
    report: JSONReport,
    styles: dict[str, ParagraphStyle],
) -> list[Any]:
    """Build technical findings section."""

    story = _section_heading(
        "3. Security Findings",
        styles,
    )

    if not report.findings:
        story.append(
            Paragraph(
                "No security findings were recorded.",
                styles["body"],
            )
        )
        return story

    for index, finding in enumerate(
        report.findings,
        start=1,
    ):
        title = (
            finding.get("title")
            or finding.get("name")
            or finding.get("finding_id")
            or f"Finding {index}"
        )

        severity = _safe_text(
            finding.get(
                "severity",
                "info",
            )
        )

        story.append(
            Paragraph(
                f"{index}. {_safe_text(title)}",
                styles["subheading"],
            )
        )

        details = [
            [
                "Finding ID",
                _safe_text(
                    finding.get(
                        "finding_id"
                    )
                ),
            ],
            [
                "Severity",
                severity.upper(),
            ],
            [
                "Target",
                _safe_text(
                    finding.get(
                        "target"
                    )
                ),
            ],
            [
                "Score",
                _safe_text(
                    finding.get(
                        "score"
                    )
                ),
            ],
        ]

        table = Table(
            details,
            colWidths=[
                35 * mm,
                125 * mm,
            ],
        )

        table.setStyle(
            TableStyle(
                [
                    (
                        "BACKGROUND",
                        (0, 0),
                        (0, -1),
                        SURFACE,
                    ),
                    (
                        "TEXTCOLOR",
                        (0, 0),
                        (0, -1),
                        WHITE,
                    ),
                    (
                        "TEXTCOLOR",
                        (1, 0),
                        (1, -1),
                        _severity_color(
                            severity
                        ),
                    ),
                    (
                        "FONTNAME",
                        (0, 0),
                        (0, -1),
                        "Helvetica-Bold",
                    ),
                    (
                        "GRID",
                        (0, 0),
                        (-1, -1),
                        0.4,
                        BORDER,
                    ),
                    (
                        "FONTSIZE",
                        (0, 0),
                        (-1, -1),
                        8,
                    ),
                ]
            )
        )

        story.append(table)
        story.append(
            Spacer(
                1,
                3 * mm,
            )
        )

        description = finding.get(
            "description"
        )

        if description:
            story.append(
                Paragraph(
                    f"<b>Description:</b> "
                    f"{_safe_text(description)}",
                    styles["finding"],
                )
            )

        evidence = finding.get(
            "evidence"
        )

        if evidence:
            story.append(
                Paragraph(
                    f"<b>Evidence:</b> "
                    f"{_safe_text(evidence)}",
                    styles["finding"],
                )
            )

        recommendation = finding.get(
            "recommendation"
        )

        if recommendation:
            story.append(
                Paragraph(
                    f"<b>Recommendation:</b> "
                    f"{_safe_text(recommendation)}",
                    styles["finding"],
                )
            )

        story.append(
            Spacer(
                1,
                5 * mm,
            )
        )

    return story


# ---------------------------------------------------------------------------
# Recommendations
# ---------------------------------------------------------------------------


def _build_recommendations(
    report: JSONReport,
    styles: dict[str, ParagraphStyle],
) -> list[Any]:
    """Build remediation recommendations section."""

    story = _section_heading(
        "4. Remediation Recommendations",
        styles,
    )

    if not report.recommendations:
        story.append(
            Paragraph(
                "No remediation recommendations were recorded.",
                styles["body"],
            )
        )
        return story

    for index, recommendation in enumerate(
        report.recommendations,
        start=1,
    ):
        if isinstance(
            recommendation,
            dict,
        ):
            title = recommendation.get(
                "title",
                f"Recommendation {index}",
            )

            description = recommendation.get(
                "description",
                "",
            )

            priority = recommendation.get(
                "priority",
                "N/A",
            )

            text = (
                f"<b>{index}. "
                f"{_safe_text(title)}</b><br/>"
                f"Priority: {_safe_text(priority)}<br/>"
                f"{_safe_text(description)}"
            )
        else:
            text = (
                f"<b>{index}.</b> "
                f"{_safe_text(recommendation)}"
            )

        story.append(
            Paragraph(
                text,
                styles["body"],
            )
        )

    return story


# ---------------------------------------------------------------------------
# PDF Generation
# ---------------------------------------------------------------------------


def generate_pdf_report(
    report: JSONReport,
    output_path: str | Path,
) -> Path:
    """
    Generate a professional PDF report.

    Returns the created PDF path.
    """
    if not isinstance(
        report,
        JSONReport,
    ):
        raise TypeError(
            "report must be a JSONReport instance."
        )

    output = Path(output_path)

    if output.suffix.lower() != ".pdf":
        output = output.with_suffix(".pdf")

    output.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    styles = _build_styles()

    document = SimpleDocTemplate(
        str(output),
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm,
        title=report.metadata.assessment_name,
        author=(
            report.metadata.tester_name
            or "AuditForge"
        ),
        subject="Security Assessment Report",
    )

    story: list[Any] = []

    story.extend(
        _build_cover(
            report,
            styles,
        )
    )

    story.extend(
        _build_summary(
            report,
            styles,
        )
    )

    story.extend(
        _build_assets(
            report,
            styles,
        )
    )

    story.extend(
        _build_findings(
            report,
            styles,
        )
    )

    story.extend(
        _build_recommendations(
            report,
            styles,
        )
    )

    story.extend(
        [
            Spacer(
                1,
                10 * mm,
            ),
            Paragraph(
                "End of Report",
                ParagraphStyle(
                    "EndReport",
                    parent=styles["subtitle"],
                    alignment=TA_CENTER,
                ),
            ),
        ]
    )

    document.build(
        story,
        onFirstPage=_footer,
        onLaterPages=_footer,
    )

    return output


# ---------------------------------------------------------------------------
# Convenience Function
# ---------------------------------------------------------------------------


def generate_pdf_from_report(
    report: JSONReport,
    output_directory: str | Path = "reports",
    *,
    filename: str | None = None,
) -> Path:
    """
    Generate a PDF using the report's user-defined filename when available.
    """
    if not isinstance(
        report,
        JSONReport,
    ):
        raise TypeError(
            "report must be a JSONReport instance."
        )

    directory = Path(
        output_directory
    )

    directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    selected_filename = filename

    if selected_filename is None:
        selected_filename = (
            report.metadata.report_filename
        )

    if selected_filename is None:
        selected_filename = (
            "AuditForge_"
            f"{_filename_part(report.metadata.assessment_name)}"
            ".pdf"
        )

    if not selected_filename.lower().endswith(
        ".pdf"
    ):
        selected_filename += ".pdf"

    return generate_pdf_report(
        report,
        directory / selected_filename,
    )


def _filename_part(
    value: str,
) -> str:
    """Create a safe filename component."""
    result = []

    for character in value.strip():
        if character.isalnum():
            result.append(character)
        elif character in {" ", "-", "_"}:
            result.append("_")

    cleaned = "".join(result)

    while "__" in cleaned:
        cleaned = cleaned.replace(
            "__",
            "_",
        )

    return (
        cleaned.strip("_")
        or "Security_Assessment"
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

__all__ = [
    "generate_pdf_report",
    "generate_pdf_from_report",
]