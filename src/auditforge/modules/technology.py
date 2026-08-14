"""
AuditForge technology detection module.

Performs passive technology fingerprinting using HTTP response headers
and supplied response content.

This module does not perform additional network requests, exploitation,
brute-force discovery, or active probing.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Iterable, Mapping


# ---------------------------------------------------------------------------
# Technology Signatures
# ---------------------------------------------------------------------------

HEADER_SIGNATURES: tuple[tuple[str, str, str], ...] = (
    ("server", "nginx", "Nginx"),
    ("server", "apache", "Apache HTTP Server"),
    ("server", "cloudflare", "Cloudflare"),
    ("server", "microsoft-iis", "Microsoft IIS"),
    ("x-powered-by", "php", "PHP"),
    ("x-powered-by", "asp.net", "ASP.NET"),
    ("x-powered-by", "express", "Express"),
    ("x-generator", "wordpress", "WordPress"),
)

CONTENT_SIGNATURES: tuple[tuple[str, str], ...] = (
    ('wp-content/', "WordPress"),
    ('wp-includes/', "WordPress"),
    ("__next_data__", "Next.js"),
    ("_next/static/", "Next.js"),
    ("react", "React"),
    ("jquery", "jQuery"),
    ("django", "Django"),
    ("laravel", "Laravel"),
    ("bootstrap", "Bootstrap"),
)


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Technology:
    """Represents one detected technology."""

    name: str
    category: str
    evidence: str


@dataclass(slots=True)
class TechnologyResult:
    """Structured technology detection result."""

    target: str
    technologies: list[Technology] = field(default_factory=list)

    @property
    def count(self) -> int:
        """Return the number of detected technologies."""
        return len(self.technologies)


# ---------------------------------------------------------------------------
# Detection Helpers
# ---------------------------------------------------------------------------


def _normalize_headers(
    headers: Mapping[str, str] | None,
) -> dict[str, str]:
    """Normalize HTTP headers for case-insensitive matching."""
    if headers is None:
        return {}

    return {
        str(key).lower().strip(): str(value).strip()
        for key, value in headers.items()
    }


def _add_detection(
    detections: list[Technology],
    seen: set[tuple[str, str]],
    *,
    name: str,
    category: str,
    evidence: str,
) -> None:
    """Add a unique technology detection."""
    key = (
        name.lower(),
        category.lower(),
    )

    if key in seen:
        return

    seen.add(key)

    detections.append(
        Technology(
            name=name,
            category=category,
            evidence=evidence,
        )
    )


# ---------------------------------------------------------------------------
# Header Detection
# ---------------------------------------------------------------------------


def detect_from_headers(
    headers: Mapping[str, str] | None,
) -> list[Technology]:
    """
    Detect technologies from HTTP response headers.
    """
    normalized_headers = _normalize_headers(headers)

    detections: list[Technology] = []
    seen: set[tuple[str, str]] = set()

    for (
        header_name,
        indicator,
        technology_name,
    ) in HEADER_SIGNATURES:
        value = normalized_headers.get(header_name)

        if not value:
            continue

        if indicator in value.lower():
            category = (
                "Web Server"
                if header_name == "server"
                else "Application"
            )

            _add_detection(
                detections,
                seen,
                name=technology_name,
                category=category,
                evidence=(
                    f"{header_name}: {value}"
                ),
            )

    return detections


# ---------------------------------------------------------------------------
# Content Detection
# ---------------------------------------------------------------------------


def detect_from_content(
    content: str,
) -> list[Technology]:
    """
    Detect technologies from supplied HTML/content.
    """
    if not isinstance(content, str):
        raise TypeError("content must be a string.")

    normalized_content = content.lower()

    detections: list[Technology] = []
    seen: set[tuple[str, str]] = set()

    for indicator, technology_name in CONTENT_SIGNATURES:
        if indicator not in normalized_content:
            continue

        category = "Framework"

        if technology_name in {
            "jQuery",
            "Bootstrap",
        }:
            category = "JavaScript / UI"

        _add_detection(
            detections,
            seen,
            name=technology_name,
            category=category,
            evidence=(
                f"Content indicator: {indicator}"
            ),
        )

    return detections


# ---------------------------------------------------------------------------
# Combined Detection
# ---------------------------------------------------------------------------


def detect_technologies(
    target: str,
    *,
    headers: Mapping[str, str] | None = None,
    content: str = "",
) -> TechnologyResult:
    """
    Perform passive technology detection.

    Args:
        target:
            Target associated with the HTTP response.

        headers:
            HTTP response headers.

        content:
            HTML or response body supplied by the caller.

    Returns:
        Structured TechnologyResult.
    """
    if not isinstance(target, str) or not target.strip():
        raise ValueError("target cannot be empty.")

    result = TechnologyResult(
        target=target.strip(),
    )

    detections: list[Technology] = []
    seen: set[tuple[str, str]] = set()

    for technology in detect_from_headers(headers):
        _add_detection(
            detections,
            seen,
            name=technology.name,
            category=technology.category,
            evidence=technology.evidence,
        )

    for technology in detect_from_content(content):
        _add_detection(
            detections,
            seen,
            name=technology.name,
            category=technology.category,
            evidence=technology.evidence,
        )

    result.technologies = detections

    return result


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------


def technology_result_to_dict(
    result: TechnologyResult,
) -> dict[str, object]:
    """
    Convert TechnologyResult into JSON-compatible data.
    """
    if not isinstance(result, TechnologyResult):
        raise TypeError(
            "result must be a TechnologyResult instance."
        )

    return {
        "target": result.target,
        "count": result.count,
        "technologies": [
            asdict(technology)
            for technology in result.technologies
        ],
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

__all__ = [
    "HEADER_SIGNATURES",
    "CONTENT_SIGNATURES",
    "Technology",
    "TechnologyResult",
    "detect_from_headers",
    "detect_from_content",
    "detect_technologies",
    "technology_result_to_dict",
]