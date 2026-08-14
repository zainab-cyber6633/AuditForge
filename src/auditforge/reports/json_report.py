"""
AuditForge JSON reporting module.

Creates structured, machine-readable security assessment reports.

The report metadata supports user-defined assessment names, client names,
tester names, and report filenames.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping


# ---------------------------------------------------------------------------
# Report Metadata
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class ReportMetadata:
    """Metadata describing one security assessment report."""

    assessment_id: str
    assessment_name: str
    target: str

    client_name: str | None = None
    tester_name: str | None = None
    report_filename: str | None = None

    created_at: str = field(
        default_factory=lambda: datetime.now(
            timezone.utc
        ).isoformat()
    )


# ---------------------------------------------------------------------------
# JSON Report
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class JSONReport:
    """Complete structured AuditForge JSON report."""

    metadata: ReportMetadata

    summary: dict[str, Any] = field(
        default_factory=dict
    )

    assets: list[dict[str, Any]] = field(
        default_factory=list
    )

    risk_map: list[dict[str, Any]] = field(
        default_factory=list
    )

    exposure_correlation: list[dict[str, Any]] = field(
        default_factory=list
    )

    findings: list[dict[str, Any]] = field(
        default_factory=list
    )

    recommendations: list[dict[str, Any]] = field(
        default_factory=list
    )


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def _required_string(
    value: str,
    name: str,
) -> str:
    """Validate a required string."""
    if not isinstance(value, str):
        raise TypeError(
            f"{name} must be a string."
        )

    normalized = value.strip()

    if not normalized:
        raise ValueError(
            f"{name} cannot be empty."
        )

    return normalized


def _optional_string(
    value: str | None,
) -> str | None:
    """Normalize an optional string."""
    if value is None:
        return None

    if not isinstance(value, str):
        raise TypeError(
            "Optional value must be a string or None."
        )

    normalized = value.strip()

    return normalized or None


def _safe_filename(
    filename: str,
) -> str:
    """
    Validate a report filename.

    Only the filename itself is accepted. Directory traversal and path
    separators are rejected.
    """
    normalized = _required_string(
        filename,
        "report_filename",
    )

    if (
        "/" in normalized
        or "\\" in normalized
        or normalized in {".", ".."}
    ):
        raise ValueError(
            "report_filename must contain only a filename."
        )

    if not normalized.lower().endswith(".json"):
        normalized += ".json"

    return normalized


# ---------------------------------------------------------------------------
# Report Creation
# ---------------------------------------------------------------------------


def create_report_metadata(
    assessment_id: str,
    assessment_name: str,
    target: str,
    *,
    client_name: str | None = None,
    tester_name: str | None = None,
    report_filename: str | None = None,
) -> ReportMetadata:
    """
    Create validated report metadata.

    Assessment name and report filename are user-defined.
    """
    normalized_filename = None

    if report_filename is not None:
        normalized_filename = _safe_filename(
            report_filename
        )

    return ReportMetadata(
        assessment_id=_required_string(
            assessment_id,
            "assessment_id",
        ),
        assessment_name=_required_string(
            assessment_name,
            "assessment_name",
        ),
        target=_required_string(
            target,
            "target",
        ),
        client_name=_optional_string(
            client_name
        ),
        tester_name=_optional_string(
            tester_name
        ),
        report_filename=normalized_filename,
    )


def create_json_report(
    metadata: ReportMetadata,
    *,
    summary: Mapping[str, Any] | None = None,
    assets: list[Mapping[str, Any]] | None = None,
    risk_map: list[Mapping[str, Any]] | None = None,
    exposure_correlation: list[
        Mapping[str, Any]
    ] | None = None,
    findings: list[Mapping[str, Any]] | None = None,
    recommendations: list[
        Mapping[str, Any]
    ] | None = None,
) -> JSONReport:
    """Create a structured JSON report."""
    if not isinstance(
        metadata,
        ReportMetadata,
    ):
        raise TypeError(
            "metadata must be a ReportMetadata instance."
        )

    return JSONReport(
        metadata=metadata,
        summary=dict(summary or {}),
        assets=[
            dict(item)
            for item in (assets or [])
        ],
        risk_map=[
            dict(item)
            for item in (risk_map or [])
        ],
        exposure_correlation=[
            dict(item)
            for item in (exposure_correlation or [])
        ],
        findings=[
            dict(item)
            for item in (findings or [])
        ],
        recommendations=[
            dict(item)
            for item in (recommendations or [])
        ],
    )


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------


def report_to_dict(
    report: JSONReport,
) -> dict[str, Any]:
    """Convert a JSONReport into a dictionary."""
    if not isinstance(
        report,
        JSONReport,
    ):
        raise TypeError(
            "report must be a JSONReport instance."
        )

    return asdict(report)


def report_to_json(
    report: JSONReport,
    *,
    indent: int = 2,
) -> str:
    """Serialize a JSONReport to JSON text."""
    if not isinstance(
        report,
        JSONReport,
    ):
        raise TypeError(
            "report must be a JSONReport instance."
        )

    if indent < 0:
        raise ValueError(
            "indent cannot be negative."
        )

    return json.dumps(
        report_to_dict(report),
        indent=indent,
        ensure_ascii=False,
    )


# ---------------------------------------------------------------------------
# File Output
# ---------------------------------------------------------------------------


def save_json_report(
    report: JSONReport,
    output_directory: str | Path = "reports",
    *,
    filename: str | None = None,
) -> Path:
    """
    Save a JSON report to disk.

    Filename priority:

    1. Explicit filename argument
    2. User-defined metadata filename
    3. Automatically generated filename
    """
    if not isinstance(
        report,
        JSONReport,
    ):
        raise TypeError(
            "report must be a JSONReport instance."
        )

    directory = Path(output_directory)
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
            f"AuditForge_"
            f"{_filename_part(report.metadata.assessment_name)}"
            f".json"
        )

    selected_filename = _safe_filename(
        selected_filename
    )

    output_path = directory / selected_filename

    output_path.write_text(
        report_to_json(report),
        encoding="utf-8",
    )

    return output_path


def _filename_part(
    value: str,
) -> str:
    """
    Convert assessment name into a filesystem-friendly filename component.
    """
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

    return cleaned.strip("_") or "Security_Assessment"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

__all__ = [
    "ReportMetadata",
    "JSONReport",
    "create_report_metadata",
    "create_json_report",
    "report_to_dict",
    "report_to_json",
    "save_json_report",
]