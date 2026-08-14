"""
AuditForge TLS/SSL assessment module.

Collects basic TLS certificate and connection metadata from an HTTPS
target.

This module performs observation only. It does not perform TLS attacks,
certificate manipulation, or exploitation.
"""

from __future__ import annotations

import socket
import ssl
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_TIMEOUT = 10.0
DEFAULT_PORT = 443


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class TLSResult:
    """Structured TLS assessment result."""

    target: str
    hostname: str
    port: int = DEFAULT_PORT

    protocol: str | None = None
    cipher: str | None = None
    cipher_bits: int | None = None

    subject: str | None = None
    issuer: str | None = None
    serial_number: str | None = None

    valid_from: str | None = None
    valid_until: str | None = None

    subject_alternative_names: list[str] = field(
        default_factory=list
    )

    certificate_verified: bool = False
    error: str | None = None

    @property
    def success(self) -> bool:
        """Return True when TLS connection metadata was collected."""
        return self.error is None and self.protocol is not None


# ---------------------------------------------------------------------------
# Target Parsing
# ---------------------------------------------------------------------------


def parse_https_target(
    target: str,
) -> tuple[str, int]:
    """
    Parse an HTTPS target into hostname and port.

    Accepted examples:

        https://example.com
        https://example.com:443
        example.com
    """
    if not isinstance(target, str) or not target.strip():
        raise ValueError("target cannot be empty.")

    normalized = target.strip()

    if "://" not in normalized:
        normalized = f"https://{normalized}"

    parsed = urlparse(normalized)

    if parsed.scheme.lower() != "https":
        raise ValueError(
            "TLS assessment requires an HTTPS target."
        )

    if not parsed.hostname:
        raise ValueError(
            "HTTPS target must contain a hostname."
        )

    port = parsed.port or DEFAULT_PORT

    if not 1 <= port <= 65535:
        raise ValueError(
            f"Invalid port: {port}"
        )

    return parsed.hostname, port


# ---------------------------------------------------------------------------
# Certificate Helpers
# ---------------------------------------------------------------------------


def _name_to_string(
    name: Any,
) -> str | None:
    """
    Convert a certificate distinguished-name structure into a readable
    string.
    """
    if not name:
        return None

    parts: list[str] = []

    for attribute_group in name:
        for attribute, value in attribute_group:
            parts.append(
                f"{attribute}={value}"
            )

    return ", ".join(parts) or None


def _format_certificate_time(
    value: str | None,
) -> str | None:
    """
    Convert OpenSSL certificate timestamps into ISO format.
    """
    if not value:
        return None

    try:
        parsed = datetime.strptime(
            value,
            "%b %d %H:%M:%S %Y %Z",
        )

        return parsed.isoformat()

    except ValueError:
        return value


def _extract_sans(
    certificate: dict[str, Any],
) -> list[str]:
    """
    Extract DNS/IP subject alternative names.
    """
    result: list[str] = []

    for name_type, value in certificate.get(
        "subjectAltName",
        (),
    ):
        if name_type not in {
            "DNS",
            "IP Address",
        }:
            continue

        value = str(value).strip()

        if value and value not in result:
            result.append(value)

    return result


# ---------------------------------------------------------------------------
# TLS Collection
# ---------------------------------------------------------------------------


def collect_tls(
    target: str,
    *,
    timeout: float = DEFAULT_TIMEOUT,
) -> TLSResult:
    """
    Collect TLS metadata from an HTTPS target.

    Args:
        target:
            HTTPS URL or hostname.

        timeout:
            Socket timeout in seconds.

    Returns:
        Structured TLSResult.
    """
    hostname, port = parse_https_target(target)

    result = TLSResult(
        target=target.strip(),
        hostname=hostname,
        port=port,
    )

    if timeout <= 0:
        raise ValueError(
            "timeout must be greater than zero."
        )

    context = ssl.create_default_context()

    try:
        with socket.create_connection(
            (hostname, port),
            timeout=timeout,
        ) as raw_socket:

            with context.wrap_socket(
                raw_socket,
                server_hostname=hostname,
            ) as tls_socket:

                result.certificate_verified = True

                result.protocol = (
                    tls_socket.version()
                )

                cipher = tls_socket.cipher()

                if cipher:
                    result.cipher = cipher[0]
                    result.cipher_bits = cipher[2]

                certificate = (
                    tls_socket.getpeercert()
                )

                result.subject = _name_to_string(
                    certificate.get("subject")
                )

                result.issuer = _name_to_string(
                    certificate.get("issuer")
                )

                result.serial_number = (
                    certificate.get("serialNumber")
                )

                result.valid_from = (
                    _format_certificate_time(
                        certificate.get("notBefore")
                    )
                )

                result.valid_until = (
                    _format_certificate_time(
                        certificate.get("notAfter")
                    )
                )

                result.subject_alternative_names = (
                    _extract_sans(certificate)
                )

    except (
        OSError,
        ssl.SSLError,
        socket.timeout,
    ) as exc:
        result.error = str(exc)

    return result


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------


def tls_result_to_dict(
    result: TLSResult,
) -> dict[str, Any]:
    """
    Convert TLSResult into JSON-compatible data.
    """
    if not isinstance(result, TLSResult):
        raise TypeError(
            "result must be a TLSResult instance."
        )

    return asdict(result) | {
        "success": result.success,
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

__all__ = [
    "DEFAULT_TIMEOUT",
    "DEFAULT_PORT",
    "TLSResult",
    "parse_https_target",
    "collect_tls",
    "tls_result_to_dict",
]