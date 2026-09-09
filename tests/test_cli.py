from __future__ import annotations

from io import StringIO
from typing import Never

import pytest
from rich.console import Console

import wac510_mcp.server as server_module
from wac510_mcp.cli import render_startup_error, render_unexpected_error
from wac510_mcp.errors import ConfigurationError


def test_configuration_error_has_actionable_rich_output() -> None:
    buffer = StringIO()
    console = Console(file=buffer, color_system=None, width=100)

    render_startup_error(ConfigurationError("WAC510_URL is required"), console=console)

    output = buffer.getvalue()
    assert "Configuration error" in output
    assert "WAC510_URL is required" in output
    assert "OAuth" in output
    assert "setup page" in output
    assert "Traceback" not in output


def test_main_exits_cleanly_for_expected_startup_error(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def fail_to_start(
        *,
        transport: str,
        host: str,
        port: int,
        show_banner: bool | None = None,
    ) -> Never:
        del transport, host, port, show_banner
        raise ConfigurationError("WAC510_URL is required")

    monkeypatch.setattr(server_module.mcp, "run", fail_to_start)

    with pytest.raises(SystemExit) as raised:
        server_module.main()

    captured = capsys.readouterr()
    assert raised.value.code == 2
    assert "WAC510_URL is required" in captured.err
    assert "Traceback" not in captured.err


def test_unexpected_error_uses_compact_rich_traceback() -> None:
    buffer = StringIO()
    console = Console(file=buffer, color_system=None, width=100)
    try:
        raise RuntimeError("unexpected test failure")
    except RuntimeError as error:
        render_unexpected_error(error, console=console)

    output = buffer.getvalue()
    assert "Unexpected server error" in output
    assert "RuntimeError" in output
    assert "unexpected test failure" in output


def test_main_renders_unexpected_error_and_exits_one(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def crash(
        *,
        transport: str,
        host: str,
        port: int,
        show_banner: bool | None = None,
    ) -> Never:
        del transport, host, port, show_banner
        raise RuntimeError("server crashed")

    monkeypatch.setattr(server_module.mcp, "run", crash)

    with pytest.raises(SystemExit) as raised:
        server_module.main()

    captured = capsys.readouterr()
    assert raised.value.code == 1
    assert "Unexpected server error" in captured.err
    assert "RuntimeError" in captured.err
    assert "server crashed" in captured.err


def test_main_exits_silently_on_keyboard_interrupt(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def interrupt(
        *,
        transport: str,
        host: str,
        port: int,
        show_banner: bool | None = None,
    ) -> Never:
        del transport, host, port, show_banner
        raise KeyboardInterrupt

    monkeypatch.setattr(server_module.mcp, "run", interrupt)

    with pytest.raises(SystemExit) as raised:
        server_module.main()

    captured = capsys.readouterr()
    assert raised.value.code == 130
    assert captured.out == ""
    assert captured.err == ""
