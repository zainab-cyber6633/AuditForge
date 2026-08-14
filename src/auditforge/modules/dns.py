"""
AuditForge DNS assessment module.

Performs structured DNS record collection for an authorized target.

This module performs observation only. It does not exploit DNS services,
modify DNS records, or perform unauthorized enumeration.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import dns.exception
import dns.resolver


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SUPPORTED_RECORD_TYPES = (
    "A",
    "AAAA",
    "CNAME",
    "MX",
    "NS",
    "TXT",
)


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class DNSRecord:
    """
    Represents one observed DNS record.
    """

    record_type: str
    value: str


@dataclass(slots=True)
class DNSResult:
    """
    Structured DNS assessment result.
    """

    target: str
    records: list[DNSRecord] = field(default_factory=list)
    errors: dict[str, str] = field(default_factory=dict)

    @property
    def success(self) -> bool:
        """Return True when at least one DNS record was collected."""
        return bool(self.records)

    def records_by_type(
        self,
        record_type: str,
    ) -> list[str]:
        """
        Return values for a specific DNS record type.
        """
        normalized_type = record_type.upper()

        return [
            record.value
            for record in self.records
            if record.record_type == normalized_type
        ]


# ---------------------------------------------------------------------------
# Resolver Helpers
# ---------------------------------------------------------------------------


def create_resolver(
    *,
    timeout: float = 5.0,
    lifetime: float = 5.0,
) -> dns.resolver.Resolver:
    """
    Create a configured DNS resolver.

    Args:
        timeout: Per-query timeout in seconds.
        lifetime: Maximum lifetime of a DNS query.

    Returns:
        Configured dnspython resolver.
    """
    if timeout <= 0:
        raise ValueError("timeout must be greater than zero.")

    if lifetime <= 0:
        raise ValueError("lifetime must be greater than zero.")

    resolver = dns.resolver.Resolver()

    resolver.timeout = timeout
    resolver.lifetime = lifetime

    return resolver


# ---------------------------------------------------------------------------
# Record Collection
# ---------------------------------------------------------------------------


def query_record(
    target: str,
    record_type: str,
    *,
    resolver: dns.resolver.Resolver | None = None,
) -> list[DNSRecord]:
    """
    Query one DNS record type.

    DNS lookup failures are converted into an empty result. The caller
    can decide how to represent or report the failure.
    """
    if not isinstance(target, str) or not target.strip():
        raise ValueError("target cannot be empty.")

    normalized_type = record_type.upper()

    if normalized_type not in SUPPORTED_RECORD_TYPES:
        raise ValueError(
            f"Unsupported DNS record type: {record_type!r}"
        )

    active_resolver = resolver or create_resolver()

    try:
        answers = active_resolver.resolve(
            target.strip(),
            normalized_type,
        )
    except (
        dns.resolver.NoAnswer,
        dns.resolver.NXDOMAIN,
        dns.resolver.NoNameservers,
        dns.exception.Timeout,
    ):
        return []

    records: list[DNSRecord] = []

    for answer in answers:
        value = str(answer).strip()

        if value:
            records.append(
                DNSRecord(
                    record_type=normalized_type,
                    value=value,
                )
            )

    return records


def collect_dns_records(
    target: str,
    *,
    record_types: tuple[str, ...] = SUPPORTED_RECORD_TYPES,
    resolver: dns.resolver.Resolver | None = None,
) -> DNSResult:
    """
    Collect supported DNS records for a target.

    Args:
        target:
            Domain or hostname to query.

        record_types:
            DNS record types to collect.

        resolver:
            Optional preconfigured resolver.

    Returns:
        Structured DNSResult.
    """
    if not isinstance(target, str) or not target.strip():
        raise ValueError("target cannot be empty.")

    normalized_target = target.strip().rstrip(".")

    result = DNSResult(
        target=normalized_target,
    )

    active_resolver = resolver or create_resolver()

    for record_type in record_types:
        normalized_type = record_type.upper()

        if normalized_type not in SUPPORTED_RECORD_TYPES:
            result.errors[normalized_type] = (
                f"Unsupported DNS record type: {record_type!r}"
            )
            continue

        try:
            records = query_record(
                normalized_target,
                normalized_type,
                resolver=active_resolver,
            )

            result.records.extend(records)

        except Exception as exc:
            result.errors[normalized_type] = str(exc)

    return result


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------


def dns_result_to_dict(
    result: DNSResult,
) -> dict[str, Any]:
    """
    Convert DNSResult into JSON-compatible data.
    """
    if not isinstance(result, DNSResult):
        raise TypeError(
            "result must be a DNSResult instance."
        )

    return {
        "target": result.target,
        "success": result.success,
        "records": [
            {
                "type": record.record_type,
                "value": record.value,
            }
            for record in result.records
        ],
        "errors": dict(result.errors),
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

__all__ = [
    "SUPPORTED_RECORD_TYPES",
    "DNSRecord",
    "DNSResult",
    "create_resolver",
    "query_record",
    "collect_dns_records",
    "dns_result_to_dict",
]