"""
AuditForge HTTP/HTTPS assessment module.

Collects basic HTTP response information from an explicitly supplied URL.

This module performs observation only. It does not crawl, brute-force,
exploit, or discover additional endpoints.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

import requests


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_TIMEOUT = 10.0

SUPPORTED_SCHEMES = frozenset(
    {
        "http",
        "https",
    }
)


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class HTTPResult:
    """Structured HTTP assessment result."""

    requested_url: str
    final_url: str | None = None
    status_code: int | None = None
    reason: str | None = None
    content_type: str | None = None
    server: str | None = None
    response_time_ms: float | None = None
    headers: dict[str, str] = field(default_factory=dict)
    redirect_count: int = 0
    error: str | None = None

    @property
    def success(self) -> bool:
        """Return True when a valid HTTP response was received."""
        return self.error is None and self.status_code is not None


# ---------------------------------------------------------------------------
# URL Validation
# ---------------------------------------------------------------------------


def validate_http_url(url: str) -> str:
    """
    Validate an HTTP/HTTPS URL.

    This is intentionally local validation only; it does not make a request.
    """
    if not isinstance(url, str) or not url.strip():
        raise ValueError("url cannot be empty.")

    normalized = url.strip()

    scheme = normalized.split("://", 1)[0].lower()

    if scheme not in SUPPORTED_SCHEMES:
        raise ValueError(
            f"Unsupported URL scheme: {scheme!r}"
        )

    if "://" not in normalized:
        raise ValueError(
            "URL must include a scheme."
        )

    return normalized


# ---------------------------------------------------------------------------
# HTTP Collection
# ---------------------------------------------------------------------------


def request_url(
    url: str,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    verify_tls: bool = True,
    follow_redirects: bool = True,
    user_agent: str = "AuditForge/1.0",
) -> HTTPResult:
    """
    Perform an HTTP/HTTPS observation request.

    Args:
        url:
            Explicit URL to assess.

        timeout:
            Request timeout in seconds.

        verify_tls:
            Whether HTTPS certificates should be verified.

        follow_redirects:
            Whether HTTP redirects should be followed.

        user_agent:
            User-Agent sent with the request.

    Returns:
        Structured HTTPResult.

    Raises:
        ValueError:
            If URL or timeout is invalid.
    """
    normalized_url = validate_http_url(url)

    if timeout <= 0:
        raise ValueError(
            "timeout must be greater than zero."
        )

    if not isinstance(user_agent, str) or not user_agent.strip():
        raise ValueError(
            "user_agent cannot be empty."
        )

    result = HTTPResult(
        requested_url=normalized_url,
    )

    headers = {
        "User-Agent": user_agent.strip(),
        "Accept": "*/*",
    }

    try:
        response = requests.get(
            normalized_url,
            headers=headers,
            timeout=timeout,
            verify=verify_tls,
            allow_redirects=follow_redirects,
        )

        result.final_url = response.url
        result.status_code = response.status_code
        result.reason = response.reason
        result.content_type = response.headers.get(
            "Content-Type"
        )
        result.server = response.headers.get(
            "Server"
        )

        result.response_time_ms = round(
            response.elapsed.total_seconds() * 1000,
            2,
        )

        result.headers = {
            str(key): str(value)
            for key, value in response.headers.items()
        }

        result.redirect_count = len(
            response.history
        )

    except requests.RequestException as exc:
        result.error = str(exc)

    return result


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------


def http_result_to_dict(
    result: HTTPResult,
) -> dict[str, Any]:
    """
    Convert HTTPResult into JSON-compatible data.
    """
    if not isinstance(result, HTTPResult):
        raise TypeError(
            "result must be an HTTPResult instance."
        )

    return asdict(result) | {
        "success": result.success,
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

__all__ = [
    "DEFAULT_TIMEOUT",
    "SUPPORTED_SCHEMES",
    "HTTPResult",
    "validate_http_url",
    "request_url",
    "http_result_to_dict",
]