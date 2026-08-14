"""
AuditForge input validation utilities.

This module validates user-supplied assessment inputs such as domains,
hostnames, IP addresses, URLs, and target types.

Validation is deliberately limited to syntax and structure. This module
does not perform network requests, DNS resolution, scanning, or scope
authorization checks.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SUPPORTED_TARGET_TYPES = frozenset(
    {
        "domain",
        "hostname",
        "ip",
        "url",
    }
)

SUPPORTED_URL_SCHEMES = frozenset(
    {
        "http",
        "https",
    }
)

_MAX_DOMAIN_LENGTH = 253
_MAX_HOSTNAME_LENGTH = 253
_MAX_LABEL_LENGTH = 63

_DOMAIN_LABEL_PATTERN = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$"
)

_HOSTNAME_LABEL_PATTERN = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$"
)


# ---------------------------------------------------------------------------
# Generic Validation
# ---------------------------------------------------------------------------


def is_non_empty(value: str) -> bool:
    """
    Return True when value is a non-empty string after stripping whitespace.
    """
    return isinstance(value, str) and bool(value.strip())


def validate_non_empty(value: str, field_name: str = "value") -> str:
    """
    Validate and return a normalized non-empty string.

    Raises:
        ValueError: If value is not a string or is empty.
    """
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a string.")

    normalized = value.strip()

    if not normalized:
        raise ValueError(f"{field_name} cannot be empty.")

    return normalized


# ---------------------------------------------------------------------------
# Domain Validation
# ---------------------------------------------------------------------------


def is_valid_domain(domain: str) -> bool:
    """
    Return True when domain has a valid ASCII domain structure.

    Examples of accepted values:

        example.com
        sub.example.com
        api.example.co.uk
    """
    if not isinstance(domain, str):
        return False

    domain = domain.strip().rstrip(".")

    if not domain or len(domain) > _MAX_DOMAIN_LENGTH:
        return False

    if "." not in domain:
        return False

    labels = domain.split(".")

    for label in labels:
        if not label or len(label) > _MAX_LABEL_LENGTH:
            return False

        if not _DOMAIN_LABEL_PATTERN.fullmatch(label):
            return False

    return True


def validate_domain(domain: str) -> str:
    """
    Validate and return a normalized domain.

    Raises:
        ValueError: If the domain is invalid.
    """
    normalized = validate_non_empty(domain, "domain").rstrip(".")

    if not is_valid_domain(normalized):
        raise ValueError(f"Invalid domain: {domain!r}")

    return normalized.lower()


# ---------------------------------------------------------------------------
# Hostname Validation
# ---------------------------------------------------------------------------


def is_valid_hostname(hostname: str) -> bool:
    """
    Return True when hostname has a valid ASCII hostname structure.

    Hostnames may be single-label names such as:

        localhost
        server01

    or multi-label names such as:

        api.example.com
    """
    if not isinstance(hostname, str):
        return False

    hostname = hostname.strip().rstrip(".")

    if not hostname or len(hostname) > _MAX_HOSTNAME_LENGTH:
        return False

    labels = hostname.split(".")

    for label in labels:
        if not label or len(label) > _MAX_LABEL_LENGTH:
            return False

        if not _HOSTNAME_LABEL_PATTERN.fullmatch(label):
            return False

    return True


def validate_hostname(hostname: str) -> str:
    """
    Validate and return a normalized hostname.

    Raises:
        ValueError: If the hostname is invalid.
    """
    normalized = validate_non_empty(hostname, "hostname").rstrip(".")

    if not is_valid_hostname(normalized):
        raise ValueError(f"Invalid hostname: {hostname!r}")

    return normalized.lower()


# ---------------------------------------------------------------------------
# IP Address Validation
# ---------------------------------------------------------------------------


def is_valid_ipv4(value: str) -> bool:
    """Return True when value is a valid IPv4 address."""
    if not isinstance(value, str):
        return False

    try:
        return isinstance(
            ipaddress.ip_address(value.strip()),
            ipaddress.IPv4Address,
        )
    except ValueError:
        return False


def is_valid_ipv6(value: str) -> bool:
    """Return True when value is a valid IPv6 address."""
    if not isinstance(value, str):
        return False

    try:
        return isinstance(
            ipaddress.ip_address(value.strip()),
            ipaddress.IPv6Address,
        )
    except ValueError:
        return False


def is_valid_ip(value: str) -> bool:
    """Return True when value is either a valid IPv4 or IPv6 address."""
    if not isinstance(value, str):
        return False

    try:
        ipaddress.ip_address(value.strip())
        return True
    except ValueError:
        return False


def validate_ip(value: str) -> str:
    """
    Validate and return a normalized IP address.

    Raises:
        ValueError: If the IP address is invalid.
    """
    normalized = validate_non_empty(value, "IP address")

    try:
        return str(ipaddress.ip_address(normalized))
    except ValueError as exc:
        raise ValueError(f"Invalid IP address: {value!r}") from exc


# ---------------------------------------------------------------------------
# URL Validation
# ---------------------------------------------------------------------------


def is_valid_url(url: str) -> bool:
    """
    Return True when URL has a supported HTTP/HTTPS scheme and valid host.
    """
    if not isinstance(url, str):
        return False

    normalized = url.strip()

    if not normalized:
        return False

    try:
        parsed = urlparse(normalized)
    except ValueError:
        return False

    if parsed.scheme.lower() not in SUPPORTED_URL_SCHEMES:
        return False

    if not parsed.netloc:
        return False

    try:
        hostname = parsed.hostname
    except ValueError:
        return False

    if not hostname:
        return False

    return is_valid_hostname(hostname) or is_valid_ip(hostname)


def validate_url(url: str) -> str:
    """
    Validate and return a normalized HTTP/HTTPS URL.

    Raises:
        ValueError: If the URL is invalid.
    """
    normalized = validate_non_empty(url, "URL")

    if not is_valid_url(normalized):
        raise ValueError(f"Invalid URL: {url!r}")

    parsed = urlparse(normalized)

    scheme = parsed.scheme.lower()

    return parsed._replace(scheme=scheme).geturl()


# ---------------------------------------------------------------------------
# Target Validation
# ---------------------------------------------------------------------------


def validate_target_type(target_type: str) -> str:
    """
    Validate a supported AuditForge target type.

    Supported types:

        domain
        hostname
        ip
        url
    """
    normalized = validate_non_empty(target_type, "target type").lower()

    if normalized not in SUPPORTED_TARGET_TYPES:
        supported = ", ".join(sorted(SUPPORTED_TARGET_TYPES))
        raise ValueError(
            f"Unsupported target type: {target_type!r}. "
            f"Supported types: {supported}."
        )

    return normalized


def validate_target(value: str, target_type: str) -> str:
    """
    Validate a target according to its declared target type.

    Raises:
        ValueError: If target type or target value is invalid.
    """
    normalized_type = validate_target_type(target_type)

    if normalized_type == "domain":
        return validate_domain(value)

    if normalized_type == "hostname":
        return validate_hostname(value)

    if normalized_type == "ip":
        return validate_ip(value)

    if normalized_type == "url":
        return validate_url(value)

    # This is unreachable because validate_target_type() already validates
    # the target type.
    raise ValueError(f"Unsupported target type: {target_type!r}")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

__all__ = [
    "SUPPORTED_TARGET_TYPES",
    "SUPPORTED_URL_SCHEMES",
    "is_non_empty",
    "validate_non_empty",
    "is_valid_domain",
    "validate_domain",
    "is_valid_hostname",
    "validate_hostname",
    "is_valid_ipv4",
    "is_valid_ipv6",
    "is_valid_ip",
    "validate_ip",
    "is_valid_url",
    "validate_url",
    "validate_target_type",
    "validate_target",
]