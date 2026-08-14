"""
AuditForge terminal branding and color theme.

Professional terminal interface for Kali/Linux, Windows Terminal,
PowerShell, and VS Code.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass


# ============================================================================
# ANSI COLORS
# ============================================================================

RESET = "\033[0m"

BOLD = "\033[1m"
DIM = "\033[2m"

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
WHITE = "\033[97m"
GRAY = "\033[90m"


# ============================================================================
# AUDITFORGE BRANDING
# ============================================================================

APP_NAME = "AUDITFORGE"

APP_DESCRIPTION = (
    "Automated Security Assessment & Reporting Platform"
)

APP_TAGLINE = "Assess. Analyze. Report."

DEVELOPER_NAME = "Zainab Ijaz"

DEVELOPER_ROLE = "Security Research & Development"

VERSION = "1.0.0"


# ============================================================================
# TERMINAL SUPPORT
# ============================================================================


def supports_color() -> bool:
    """Detect whether the current terminal supports ANSI colors."""

    if os.environ.get("NO_COLOR"):
        return False

    if os.environ.get("TERM") == "dumb":
        return False

    if os.name != "nt":
        return True

    if os.environ.get("WT_SESSION"):
        return True

    if os.environ.get("TERM_PROGRAM") == "vscode":
        return True

    if os.environ.get("ANSICON"):
        return True

    if os.environ.get("ConEmuANSI") == "ON":
        return True

    if os.environ.get("TERM"):
        return True

    return False


# ============================================================================
# COLOR ENGINE
# ============================================================================


def colorize(
    text: str,
    color: str,
    *,
    bold: bool = False,
    dim: bool = False,
) -> str:
    """Apply ANSI color when supported."""

    if not supports_color():
        return text

    prefix = ""

    if bold:
        prefix += BOLD

    if dim:
        prefix += DIM

    return f"{prefix}{color}{text}{RESET}"


def red(text: str, *, bold: bool = False) -> str:
    return colorize(text, RED, bold=bold)


def green(text: str, *, bold: bool = False) -> str:
    return colorize(text, GREEN, bold=bold)


def yellow(text: str, *, bold: bool = False) -> str:
    return colorize(text, YELLOW, bold=bold)


def cyan(text: str, *, bold: bool = False) -> str:
    return colorize(text, CYAN, bold=bold)


def white(text: str, *, bold: bool = False) -> str:
    return colorize(text, WHITE, bold=bold)


def gray(text: str) -> str:
    return colorize(text, GRAY)


# ============================================================================
# SEVERITY
# ============================================================================


SEVERITY_COLORS = {
    "critical": RED,
    "high": RED,
    "medium": YELLOW,
    "low": CYAN,
    "info": WHITE,
}


def severity_text(severity: str) -> str:
    """Return a colorized severity label."""

    normalized = severity.strip().lower()

    color = SEVERITY_COLORS.get(
        normalized,
        WHITE,
    )

    return colorize(
        normalized.upper(),
        color,
        bold=True,
    )


# ============================================================================
# STATUS
# ============================================================================


@dataclass(frozen=True, slots=True)
class StatusIndicator:
    """Represents a terminal status indicator."""

    label: str
    symbol: str
    color: str


STATUS_READY = StatusIndicator(
    label="READY",
    symbol="●",
    color=GREEN,
)

STATUS_WARNING = StatusIndicator(
    label="WARNING",
    symbol="●",
    color=YELLOW,
)

STATUS_ERROR = StatusIndicator(
    label="ERROR",
    symbol="●",
    color=RED,
)

STATUS_INFO = StatusIndicator(
    label="INFO",
    symbol="●",
    color=CYAN,
)


def status_text(
    label: str,
    *,
    status: StatusIndicator = STATUS_READY,
) -> str:
    """Create a formatted status line."""

    symbol = colorize(
        status.symbol,
        status.color,
        bold=True,
    )

    state = colorize(
        status.label,
        status.color,
        bold=True,
    )

    return f"{symbol} {label:<12} {state}"


# ============================================================================
# SAFE LOGO
# ============================================================================


def render_logo() -> str:
    """
    Return the compact AuditForge logo.

    Deliberately uses plain ASCII so it renders correctly across
    Windows CMD, PowerShell, VS Code, and Kali terminals.
    """

    return (
        "  ┌──────────────────────────────────────────┐\n"
        "  │              AUDITFORGE                  │\n"
        "  └──────────────────────────────────────────┘"
    )


# ============================================================================
# BANNER
# ============================================================================


def render_banner() -> str:
    """Render the complete AuditForge terminal banner."""

    width = 62

    top = "╔" + ("═" * width) + "╗"
    divider = "╠" + ("═" * width) + "╣"
    bottom = "╚" + ("═" * width) + "╝"

    def line(text: str = "") -> str:
        text = text[:width]
        return f"║{text.ljust(width)}║"

    output: list[str] = []

    output.append(top)

    # Logo
    for logo_line in render_logo().splitlines():
        output.append(
            line(
                logo_line.center(width)
            )
        )

    output.append(line())

    # Description
    output.append(
        line(
            APP_DESCRIPTION.center(width)
        )
    )

    output.append(
        line(
            APP_TAGLINE.center(width)
        )
    )

    output.append(divider)

    # Metadata
    output.append(
        line(
            f"  VERSION      {VERSION}"
        )
    )

    output.append(
        line(
            f"  DEVELOPER    {DEVELOPER_NAME}"
        )
    )

    output.append(
        line(
            f"  ROLE         {DEVELOPER_ROLE}"
        )
    )

    output.append(divider)

    output.append(
        line(
            "  SECURITY ASSESSMENT ENGINE"
        )
    )

    output.append(
        line(
            "  Authorized testing and security analysis"
        )
    )

    output.append(bottom)

    return "\n".join(output)


def print_banner() -> None:
    """Print the AuditForge startup banner."""

    banner = render_banner()

    if not supports_color():
        print(banner)
        return

    for line in banner.splitlines():

        if line.startswith(
            ("╔", "╠", "╚")
        ):
            print(
                colorize(
                    line,
                    RED,
                    bold=True,
                )
            )

        elif "AUDITFORGE" in line:
            print(
                colorize(
                    line,
                    RED,
                    bold=True,
                )
            )

        elif "DEVELOPER" in line:
            print(
                colorize(
                    line,
                    WHITE,
                    bold=True,
                )
            )

        elif "ROLE" in line:
            print(
                colorize(
                    line,
                    GRAY,
                )
            )

        elif "VERSION" in line:
            print(
                colorize(
                    line,
                    CYAN,
                )
            )

        elif "Assess." in line:
            print(
                colorize(
                    line,
                    WHITE,
                    bold=True,
                )
            )

        elif "SECURITY" in line:
            print(
                colorize(
                    line,
                    RED,
                    bold=True,
                )
            )

        else:
            print(
                colorize(
                    line,
                    RED,
                )
            )


# ============================================================================
# STARTUP STATUS
# ============================================================================


def print_startup_status() -> None:
    """Print AuditForge startup component status."""

    print()

    print(
        status_text(
            "ENGINE",
            status=STATUS_READY,
        )
    )

    print(
        status_text(
            "SCOPE",
            status=STATUS_READY,
        )
    )

    print(
        status_text(
            "REPORTING",
            status=STATUS_READY,
        )
    )

    print(
        status_text(
            "MODULES",
            status=STATUS_READY,
        )
    )

    print()


# ============================================================================
# PUBLIC API
# ============================================================================


__all__ = [
    "RESET",
    "BOLD",
    "DIM",
    "RED",
    "GREEN",
    "YELLOW",
    "CYAN",
    "WHITE",
    "GRAY",
    "APP_NAME",
    "APP_DESCRIPTION",
    "APP_TAGLINE",
    "DEVELOPER_NAME",
    "DEVELOPER_ROLE",
    "VERSION",
    "supports_color",
    "colorize",
    "red",
    "green",
    "yellow",
    "cyan",
    "white",
    "gray",
    "severity_text",
    "StatusIndicator",
    "STATUS_READY",
    "STATUS_WARNING",
    "STATUS_ERROR",
    "STATUS_INFO",
    "status_text",
    "render_logo",
    "render_banner",
    "print_banner",
    "print_startup_status",
]