"""
AuditForge domain models.

This module defines the core data structures used throughout AuditForge.
Models intentionally contain data representation only. Assessment logic,
scoring, severity calculation, scanning, reporting, and UI logic belong
to their respective modules.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
from uuid import uuid4


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _generate_id() -> str:
    """Generate a unique identifier for a domain object."""
    return str(uuid4())


def _utc_now() -> datetime:
    """Return the current UTC time as a timezone-aware datetime."""
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Type Definitions
# ---------------------------------------------------------------------------

AssessmentStatus = str
TargetType = str
ScopeStatus = str
ScanStatus = str
FindingStatus = str
Severity = str
Confidence = str


# ---------------------------------------------------------------------------
# Assessment
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Assessment:
    """
    Represents a complete security assessment.

    An assessment acts as the top-level container for targets, scans,
    and findings associated with one authorized security engagement.
    """

    name: str
    target: str

    id: str = field(default_factory=_generate_id)
    status: AssessmentStatus = "pending"

    created_at: datetime = field(default_factory=_utc_now)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None


# ---------------------------------------------------------------------------
# Target
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Target:
    """
    Represents an authorized assessment target.

    A target may be a domain, hostname, IP address, or URL.
    """

    assessment_id: str
    value: str
    target_type: TargetType

    id: str = field(default_factory=_generate_id)
    scope_status: ScopeStatus = "authorized"


# ---------------------------------------------------------------------------
# Scan
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Scan:
    """
    Represents one module execution within an assessment.

    Examples include DNS enumeration, HTTP analysis, TLS analysis,
    and subdomain discovery.
    """

    assessment_id: str
    module: str

    id: str = field(default_factory=_generate_id)
    status: ScanStatus = "pending"

    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Service:
    """
    Represents a discovered network or application service.
    """

    target_id: str
    host: str
    port: int
    protocol: str

    id: str = field(default_factory=_generate_id)
    service_name: Optional[str] = None
    version: Optional[str] = None


# ---------------------------------------------------------------------------
# Endpoint
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Endpoint:
    """
    Represents a discovered HTTP or API endpoint.
    """

    target_id: str
    url: str

    id: str = field(default_factory=_generate_id)
    method: str = "GET"
    status_code: Optional[int] = None
    content_type: Optional[str] = None
    technology: Optional[str] = None


# ---------------------------------------------------------------------------
# Finding
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Finding:
    """
    Represents a security finding or security-relevant observation.

    Severity and risk calculations are intentionally not performed here.
    Those responsibilities belong to the analysis layer.
    """

    assessment_id: str
    title: str
    description: str

    id: str = field(default_factory=_generate_id)
    target_id: Optional[str] = None

    severity: Optional[Severity] = None
    confidence: Optional[Confidence] = None
    category: Optional[str] = None

    status: FindingStatus = "open"


# ---------------------------------------------------------------------------
# Evidence
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Evidence:
    """
    Represents technical evidence supporting a security finding.
    """

    finding_id: str
    evidence_type: str
    title: str
    content: str

    id: str = field(default_factory=_generate_id)
    source: Optional[str] = None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

__all__ = [
    "Assessment",
    "Target",
    "Scan",
    "Service",
    "Endpoint",
    "Finding",
    "Evidence",
]