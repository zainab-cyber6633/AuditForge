"""
AuditForge security headers analysis module.

Analyzes HTTP response headers for the presence of commonly recommended
security-related headers.

This module observes and interprets supplied headers only. It does not
perform network requests or assign final vulnerability severity.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Mapping


# ---------------------------------------------------------------------------
# Security Header Definitions
# ---------------------------------------------------------------------------


SECURITY_HEADERS: tuple[tuple[str, str], ...] = (
    (
        "Strict-Transport-Security",
        "Controls browser HTTPS enforcement.",
    ),
    (
        "Content-Security-Policy",
        "Helps restrict executable content sources.",
    ),
    (
        "X-Content-Type-Options",
        "Helps prevent MIME-type sniffing.",
    ),
    (
        "X-Frame-Options",
        "Controls whether the page may be framed.",
    ),
    (
        "Referrer-Policy",
        "Controls referrer information sent by browsers.",
    ),
    (
        "Permissions-Policy",
        "Controls access to selected browser features.",
    ),
)


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class HeaderCheck:
    """Represents the analysis of one security-related HTTP header."""

    name: str
    present: bool
    value: str | None
    description: str


@dataclass(slots=True)
class HeaderAnalysisResult:
    """Structured security-header analysis result."""

    target: str
    checks: list[HeaderCheck]

    @property
    def present_count(self) -> int:
        """Return the number of detected security headers."""
        return sum(
            1
            for check in self.checks
            if check.present
        )

    @property
    def missing_count(self) -> int:
        """Return the number of missing security headers."""
        return sum(
            1
            for check in self.checks
            if not check.present
        )


# ---------------------------------------------------------------------------
# Header Normalization
# ---------------------------------------------------------------------------


def _normalize_headers(
    headers: Mapping[str, str] | None,
) -> dict[str, str]:
    """
    Normalize header names for case-insensitive comparison.
    """
    if headers is None:
        return {}

    return {
        str(name).strip().lower(): str(value).strip()
        for name, value in headers.items()
    }


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------


def analyze_security_headers(
    target: str,
    headers: Mapping[str, str] | None,
) -> HeaderAnalysisResult:
    """
    Analyze supplied HTTP response headers.

    Args:
        target:
            Target associated with the HTTP response.

        headers:
            HTTP response headers.

    Returns:
        Structured HeaderAnalysisResult.
    """
    if not isinstance(target, str) or not target.strip():
        raise ValueError("target cannot be empty.")

    normalized_headers = _normalize_headers(headers)

    checks: list[HeaderCheck] = []

    for header_name, description in SECURITY_HEADERS:
        value = normalized_headers.get(
            header_name.lower()
        )

        checks.append(
            HeaderCheck(
                name=header_name,
                present=value is not None,
                value=value,
                description=description,
            )
        )

    return HeaderAnalysisResult(
        target=target.strip(),
        checks=checks,
    )


# ---------------------------------------------------------------------------
# Convenience Helpers
# ---------------------------------------------------------------------------


def missing_security_headers(
    result: HeaderAnalysisResult,
) -> list[str]:
    """
    Return names of missing security headers.
    """
    if not isinstance(result, HeaderAnalysisResult):
        raise TypeError(
            "result must be a HeaderAnalysisResult instance."
        )

    return [
        check.name
        for check in result.checks
        if not check.present
    ]


def present_security_headers(
    result: HeaderAnalysisResult,
) -> list[str]:
    """
    Return names of present security headers.
    """
    if not isinstance(result, HeaderAnalysisResult):
        raise TypeError(
            "result must be a HeaderAnalysisResult instance."
        )

    return [
        check.name
        for check in result.checks
        if check.present
    ]


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------


def header_analysis_to_dict(
    result: HeaderAnalysisResult,
) -> dict[str, object]:
    """
    Convert HeaderAnalysisResult into JSON-compatible data.
    """
    if not isinstance(result, HeaderAnalysisResult):
        raise TypeError(
            "result must be a HeaderAnalysisResult instance."
        )

    return {
        "target": result.target,
        "present_count": result.present_count,
        "missing_count": result.missing_count,
        "checks": [
            asdict(check)
            for check in result.checks
        ],
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

__all__ = [
    "SECURITY_HEADERS",
    "HeaderCheck",
    "HeaderAnalysisResult",
    "analyze_security_headers",
    "missing_security_headers",
    "present_security_headers",
    "header_analysis_to_dict",
]