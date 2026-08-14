"""
AuditForge WHOIS assessment module.

Collects publicly available WHOIS registration information for an
authorized domain.

This module performs information gathering only. It does not modify
domain registrations or interact with registrar management functions.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any

import whois


# ---------------------------------------------------------------------------
# Data Model
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class WHOISResult:
    """
    Structured WHOIS assessment result.
    """

    domain: str
    registrar: str | None = None
    creation_date: str | None = None
    expiration_date: str | None = None
    updated_date: str | None = None
    name_servers: list[str] = field(default_factory=list)
    statuses: list[str] = field(default_factory=list)
    registrant_country: str | None = None
    raw_available: bool = False
    error: str | None = None

    @property
    def success(self) -> bool:
        """Return True when WHOIS information was successfully collected."""
        return self.error is None and self.raw_available


# ---------------------------------------------------------------------------
# Normalization Helpers
# ---------------------------------------------------------------------------


def _normalize_string(value: Any) -> str | None:
    """
    Convert a WHOIS value into a clean string.
    """
    if value is None:
        return None

    if isinstance(value, (list, tuple, set)):
        if not value:
            return None

        value = next(iter(value))

    value = str(value).strip()

    return value or None


def _normalize_list(value: Any) -> list[str]:
    """
    Normalize WHOIS list-like values into unique strings.
    """
    if value is None:
        return []

    if isinstance(value, str):
        values = [value]
    elif isinstance(value, (list, tuple, set)):
        values = list(value)
    else:
        values = [value]

    normalized: list[str] = []

    for item in values:
        cleaned = _normalize_string(item)

        if cleaned and cleaned not in normalized:
            normalized.append(cleaned)

    return normalized


def _normalize_date(value: Any) -> str | None:
    """
    Convert WHOIS date values into ISO-compatible strings.

    WHOIS providers may return either a datetime or a list of datetimes.
    """
    if value is None:
        return None

    if isinstance(value, (list, tuple, set)):
        if not value:
            return None

        value = next(iter(value))

    if isinstance(value, datetime):
        return value.isoformat()

    return str(value).strip() or None


# ---------------------------------------------------------------------------
# WHOIS Collection
# ---------------------------------------------------------------------------


def collect_whois(domain: str) -> WHOISResult:
    """
    Collect WHOIS information for a domain.

    Args:
        domain:
            Domain name to query.

    Returns:
        Structured WHOISResult.

    Raises:
        ValueError:
            If domain is empty.
    """
    if not isinstance(domain, str) or not domain.strip():
        raise ValueError("domain cannot be empty.")

    normalized_domain = domain.strip().lower().rstrip(".")

    result = WHOISResult(
        domain=normalized_domain,
    )

    try:
        data = whois.whois(normalized_domain)

        if not data:
            result.error = "WHOIS returned no data."
            return result

        result.registrar = _normalize_string(
            getattr(data, "registrar", None)
        )

        result.creation_date = _normalize_date(
            getattr(data, "creation_date", None)
        )

        result.expiration_date = _normalize_date(
            getattr(data, "expiration_date", None)
        )

        result.updated_date = _normalize_date(
            getattr(data, "updated_date", None)
        )

        result.name_servers = _normalize_list(
            getattr(data, "name_servers", None)
        )

        result.statuses = _normalize_list(
            getattr(data, "status", None)
        )

        result.registrant_country = _normalize_string(
            getattr(data, "registrant_country", None)
        )

        result.raw_available = True

    except Exception as exc:
        result.error = str(exc)

    return result


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------


def whois_result_to_dict(
    result: WHOISResult,
) -> dict[str, Any]:
    """
    Convert WHOISResult into JSON-compatible data.
    """
    if not isinstance(result, WHOISResult):
        raise TypeError(
            "result must be a WHOISResult instance."
        )

    return asdict(result) | {
        "success": result.success,
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

__all__ = [
    "WHOISResult",
    "collect_whois",
    "whois_result_to_dict",
]