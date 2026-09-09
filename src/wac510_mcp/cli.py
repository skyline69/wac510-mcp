"""Human-friendly command-line errors."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.traceback import Traceback

from wac510_mcp.errors import (
    AuthenticationError,
    ConfigurationError,
    DeviceConnectionError,
    ProtocolError,
    UnsafeOperationError,
    WAC510Error,
)


def _presentation(error: WAC510Error) -> tuple[str, str]:
    if isinstance(error, ConfigurationError):
        return (
            "Configuration error",
            "Set the missing WAC510_* environment variable. See .env.example for every option.",
        )
    if isinstance(error, AuthenticationError):
        return (
            "Authentication error",
            "Check WAC510_USERNAME and WAC510_PASSWORD, then verify that the AP allows another login session.",
        )
    if isinstance(error, DeviceConnectionError):
        return (
            "Connection error",
            "Check WAC510_URL, network reachability, and WAC510_TLS_VERIFY.",
        )
    if isinstance(error, ProtocolError):
        return (
            "Protocol error",
            "Check the AP firmware and local management state, then retry the operation.",
        )
    if isinstance(error, UnsafeOperationError):
        return (
            "Unsafe operation blocked",
            "Review the requested operation and provide its exact confirmation value.",
        )
    return (
        "WAC510 error",
        "Check the server configuration and the access point's local management interface.",
    )


def render_startup_error(error: WAC510Error, *, console: Console | None = None) -> None:
    """Render an expected startup error without a traceback."""

    title, hint = _presentation(error)
    output = console or Console(stderr=True, highlight=False)
    message = Text()
    message.append(str(error), style="bold")
    message.append("\n\n")
    message.append("How to fix it\n", style="bold cyan")
    message.append(hint)
    output.print(
        Panel.fit(
            message,
            title=f"[bold red]{title}[/bold red]",
            border_style="red",
            padding=(1, 2),
        )
    )


def render_unexpected_error(error: Exception, *, console: Console | None = None) -> None:
    """Render an unexpected exception with a compact Rich traceback."""

    output = console or Console(stderr=True, highlight=False)
    traceback = Traceback.from_exception(
        type(error),
        error,
        error.__traceback__,
        show_locals=False,
        suppress=["anyio", "fastmcp"],
        max_frames=12,
    )
    output.print(
        Panel(
            traceback,
            title="[bold red]Unexpected server error[/bold red]",
            border_style="red",
        )
    )
