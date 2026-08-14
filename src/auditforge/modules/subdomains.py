"""
AuditForge subdomain discovery module.

Provides structured, normalized, and deduplicated handling of discovered
subdomains for an authorized domain.

This module does not perform brute-force enumeration or unauthorized
network discovery. Discovery data is supplied explicitly to the module.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

from ..utils.validators import is_valid_hostname, validate_domain


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Subdomain:
    """Represents one normalized discovered subdomain."""

    hostname: str


@dataclass(slots=True)
class SubdomainResult:
    """Structured subdomain discovery result."""

    domain: str
    subdomains: list[Subdomain] = field(default_factory=list)
    rejected: list[str] = field(default_factory=list)

    @property
    def count(self) -> int:
        """Return the number of accepted unique subdomains."""
        return len(self.subdomains)


# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------


def normalize_subdomain(
    hostname: str,
    domain: str,
) -> str:
    """
    Normalize and validate a discovered subdomain.

    The hostname must belong to the supplied parent domain.
    """
    normalized_domain = validate_domain(domain)

    if not isinstance(hostname, str) or not hostname.strip():
        raise ValueError("hostname cannot be empty.")

    normalized_hostname = hostname.strip().lower().rstrip(".")

    if not is_valid_hostname(normalized_hostname):
        raise ValueError(
            f"Invalid hostname: {hostname!r}"
        )

    if normalized_hostname == normalized_domain:
        raise ValueError(
            f"Hostname is the root domain, not a subdomain: "
            f"{hostname!r}"
        )

    suffix = f".{normalized_domain}"

    if not normalized_hostname.endswith(suffix):
        raise ValueError(
            f"Hostname is outside the supplied domain: "
            f"{hostname!r}"
        )

    return normalized_hostname


# ---------------------------------------------------------------------------
# Discovery Processing
# ---------------------------------------------------------------------------


def process_subdomains(
    domain: str,
    hostnames: Iterable[str],
) -> SubdomainResult:
    """
    Normalize, validate, and deduplicate discovered subdomains.

    Invalid or out-of-domain values are recorded in ``rejected`` instead
    of causing the entire discovery process to fail.
    """
    normalized_domain = validate_domain(domain)

    result = SubdomainResult(
        domain=normalized_domain,
    )

    accepted: set[str] = set()

    for hostname in hostnames:
        try:
            normalized_hostname = normalize_subdomain(
                hostname,
                normalized_domain,
            )
        except (TypeError, ValueError):
            if isinstance(hostname, str):
                value = hostname.strip()
            else:
                value = str(hostname)

            if value and value not in result.rejected:
                result.rejected.append(value)

            continue

        if normalized_hostname in accepted:
            continue

        accepted.add(normalized_hostname)

        result.subdomains.append(
            Subdomain(
                hostname=normalized_hostname,
            )
        )

    result.subdomains.sort(
        key=lambda item: item.hostname
    )

    result.rejected.sort()

    return result


# ---------------------------------------------------------------------------
# Result Helpers
# ---------------------------------------------------------------------------


def subdomains_to_list(
    result: SubdomainResult,
) -> list[str]:
    """
    Return accepted subdomains as a simple list of hostnames.
    """
    if not isinstance(result, SubdomainResult):
        raise TypeError(
            "result must be a SubdomainResult instance."
        )

    return [
        item.hostname
        for item in result.subdomains
    ]


def subdomain_result_to_dict(
    result: SubdomainResult,
) -> dict[str, object]:
    """
    Convert SubdomainResult into JSON-compatible data.
    """
    if not isinstance(result, SubdomainResult):
        raise TypeError(
            "result must be a SubdomainResult instance."
        )

    return {
        "domain": result.domain,
        "count": result.count,
        "subdomains": subdomains_to_list(result),
        "rejected": list(result.rejected),
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

__all__ = [
    "Subdomain",
    "SubdomainResult",
    "normalize_subdomain",
    "process_subdomains",
    "subdomains_to_list",
    "subdomain_result_to_dict",
]