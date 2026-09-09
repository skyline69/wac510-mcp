from __future__ import annotations

from io import StringIO
from typing import Never

import pytest
from rich.console import Console

import wac510_mcp.server as server_module
from wac510_mcp.cli import render_startup_error
from wac510_mcp.errors import ConfigurationError


def test_configuration_error_has_actionable_rich_output() -> None:
    buffer = StringIO()
    console = Console(file=buffer, color_system=None, width=100)

    render_startup_error(ConfigurationError("WAC510_URL is required"), console=console)

    output = buffer.getvalue()
    assert "Configuration error" in output
    assert "WAC510_URL is required" in output
    assert ".env.example" in output
    assert "Traceback" not in output


def test_main_exits_cleanly_for_expected_startup_error(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def fail_to_start(*, show_banner: bool | None = None) -> Never:
        del show_banner
        raise ConfigurationError("WAC510_URL is required")

    monkeypatch.setattr(server_module.mcp, "run", fail_to_start)

    with pytest.raises(SystemExit) as raised:
        server_module.main()

    captured = capsys.readouterr()
    assert raised.value.code == 2
    assert "WAC510_URL is required" in captured.err
    assert "Traceback" not in captured.err
