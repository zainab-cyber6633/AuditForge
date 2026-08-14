"""
AuditForge command-line entry point.

Usage:

    python -m src.auditforge
    python -m src.auditforge --target example.com --target-type domain

The CLI validates the target, runs the authorized assessment modules,
and displays a structured assessment summary.
"""

from __future__ import annotations

import argparse
import sys

from src.auditforge.core.engine import (
    ENGINE_VERSION,
    AssessmentEngine,
)

from src.auditforge.core.target import (
    create_target,
)

from src.auditforge.core.scope import (
    ScopeError,
)

from src.auditforge.modules.dns import (
    collect_dns_records,
)

from src.auditforge.modules.whois import (
    collect_whois,
)

from src.auditforge.modules.http import (
    request_url,
)

from src.auditforge.modules.headers import (
    analyze_security_headers,
)

from src.auditforge.modules.tls import (
    collect_tls,
)

from src.auditforge.modules.technology import (
    detect_technologies,
)

from src.auditforge.terminal_theme import (
    print_banner,
    print_startup_status,
    severity_text,
)


# ---------------------------------------------------------------------------
# Application Information
# ---------------------------------------------------------------------------

APP_NAME = "AUDITFORGE"

APP_DESCRIPTION = (
    "Automated Security Assessment & Reporting Platform"
)

APP_TAGLINE = "Assess. Analyze. Report."


# ---------------------------------------------------------------------------
# CLI Parser
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    """Build the AuditForge command-line parser."""

    parser = argparse.ArgumentParser(
        prog="auditforge",
        description=APP_DESCRIPTION,
    )

    parser.add_argument(
        "--version",
        action="store_true",
        help="Show AuditForge version.",
    )

    parser.add_argument(
        "--status",
        action="store_true",
        help="Show AuditForge system status.",
    )

    parser.add_argument(
        "--target",
        help="Authorized assessment target.",
    )

    parser.add_argument(
        "--target-type",
        choices=(
            "domain",
            "hostname",
            "ip",
            "url",
        ),
        default="domain",
        help="Target type. Default: domain.",
    )

    return parser


# ---------------------------------------------------------------------------
# Target Validation
# ---------------------------------------------------------------------------


def validate_target_for_cli(
    value: str,
    target_type: str,
) -> bool:
    """Validate a target before assessment."""

    try:
        create_target(
            assessment_id="cli-assessment",
            value=value,
            target_type=target_type,
        )

        return True

    except (
        ValueError,
        TypeError,
        ScopeError,
    ) as exc:

        print(
            f"{severity_text('critical')}: "
            f"Target validation failed: {exc}",
            file=sys.stderr,
        )

        return False


# ---------------------------------------------------------------------------
# Assessment Module Wrappers
# ---------------------------------------------------------------------------


def run_dns(target: str):
    """Run DNS collection."""

    return collect_dns_records(target)


def run_whois(target: str):
    """Run WHOIS collection."""

    return collect_whois(target)


def run_http(target: str):
    """Run HTTP collection."""

    url = target

    if not (
        url.startswith("http://")
        or url.startswith("https://")
    ):
        url = f"https://{target}"

    return request_url(url)


def run_headers(target: str):
    """Run security-header analysis."""

    url = target

    if not (
        url.startswith("http://")
        or url.startswith("https://")
    ):
        url = f"https://{target}"

    http_result = request_url(url)

    return analyze_security_headers(
        target,
        http_result.headers,
    )


def run_tls(target: str):
    """Run TLS certificate collection."""

    return collect_tls(target)


def run_technology(target: str):
    """Run technology detection using HTTP response data."""

    url = target

    if not (
        url.startswith("http://")
        or url.startswith("https://")
    ):
        url = f"https://{target}"

    http_result = request_url(url)

    return detect_technologies(
        target,
        headers=http_result.headers,
        content="",
    )


# ---------------------------------------------------------------------------
# Assessment Execution
# ---------------------------------------------------------------------------


def run_assessment(
    target: str,
) -> object:
    """
    Run the authorized assessment module pipeline.
    """

    engine = AssessmentEngine(
        assessment_id="cli-assessment",
        target=target,
    )

    engine.register_module(
        "dns",
        run_dns,
    )

    engine.register_module(
        "whois",
        run_whois,
    )

    engine.register_module(
        "http",
        run_http,
    )

    engine.register_module(
        "headers",
        run_headers,
    )

    engine.register_module(
        "tls",
        run_tls,
    )

    engine.register_module(
        "technology",
        run_technology,
    )

    return engine.run(
        stop_on_error=False,
    )


# ---------------------------------------------------------------------------
# Result Display
# ---------------------------------------------------------------------------


def display_assessment_result(
    result,
) -> None:
    """Display a concise assessment summary."""

    print()
    print("=" * 64)
    print("AUDITFORGE ASSESSMENT RESULTS")
    print("=" * 64)

    print(
        f"Assessment ID : {result.assessment_id}"
    )

    print(
        f"Target        : {result.target}"
    )

    print(
        f"State         : {result.state}"
    )

    print()

    print("MODULE RESULTS")
    print("-" * 64)

    for module in result.modules:

        status = (
            "PASSED"
            if module.success
            else "FAILED"
        )

        print(
            f"{module.name.upper():<16} {status}"
        )

    print()

    if result.errors:

        print("MODULE ERRORS")
        print("-" * 64)

        for error in result.errors:
            print(
                f"- {error}"
            )

    else:

        print(
            "All registered assessment modules completed."
        )

    print("=" * 64)


# ---------------------------------------------------------------------------
# Application Runner
# ---------------------------------------------------------------------------


def run(
    argv: list[str] | None = None,
) -> int:
    """Run the AuditForge CLI."""

    parser = build_parser()

    args = parser.parse_args(argv)

    # ---------------------------------------------------------------
    # Version
    # ---------------------------------------------------------------

    if args.version:

        print(
            f"{APP_NAME} — {ENGINE_VERSION}"
        )

        return 0

    # ---------------------------------------------------------------
    # Status
    # ---------------------------------------------------------------

    if args.status:

        print_banner()
        print_startup_status()

        return 0

    # ---------------------------------------------------------------
    # Startup
    # ---------------------------------------------------------------

    print_banner()
    print_startup_status()

    # ---------------------------------------------------------------
    # No Target
    # ---------------------------------------------------------------

    if args.target is None:

        print(
            "No target supplied."
        )

        print(
            "AuditForge is ready for an authorized assessment."
        )

        print(
            "Use --help for available options."
        )

        return 0

    # ---------------------------------------------------------------
    # Target Validation
    # ---------------------------------------------------------------

    if not validate_target_for_cli(
        args.target,
        args.target_type,
    ):

        return 2

    # ---------------------------------------------------------------
    # Assessment Initialization
    # ---------------------------------------------------------------

    print(
        f"Target accepted: {args.target}"
    )

    print(
        f"Target type: {args.target_type}"
    )

    print(
        "Target validation: PASSED"
    )

    print()

    print(
        "Assessment initialization successful."
    )

    print(
        "Starting authorized module orchestration..."
    )

    # ---------------------------------------------------------------
    # Assessment
    # ---------------------------------------------------------------

    try:

        result = run_assessment(
            args.target,
        )

    except KeyboardInterrupt:

        print(
            "\nAssessment interrupted."
        )

        return 130

    except Exception as exc:

        print(
            f"{severity_text('critical')}: "
            f"Assessment failed: "
            f"{type(exc).__name__}: {exc}",
            file=sys.stderr,
        )

        return 1

    # ---------------------------------------------------------------
    # Results
    # ---------------------------------------------------------------

    display_assessment_result(
        result,
    )

    if result.state == "failed":

        return 1

    if result.state == "completed_with_errors":

        return 1

    return 0


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    """Application entry point."""

    raise SystemExit(
        run()
    )


if __name__ == "__main__":
    main()