from __future__ import annotations

from pathlib import Path

import pytest

from wac510_mcp.config import Settings
from wac510_mcp.errors import ConfigurationError

VALID_ENV = {
    "WAC510_URL": "https://192.0.2.1/",
    "WAC510_USERNAME": "admin",
    "WAC510_PASSWORD": "do-not-show",
}


def test_settings_require_credentials() -> None:
    with pytest.raises(ConfigurationError, match="WAC510_USERNAME"):
        Settings.from_env({"WAC510_URL": "https://192.0.2.1"})


def test_settings_hide_password_and_normalize_url() -> None:
    settings = Settings.from_env(VALID_ENV)
    assert settings.url == "https://192.0.2.1"
    assert VALID_ENV["WAC510_PASSWORD"] not in repr(settings)


@pytest.mark.parametrize("value", ["maybe", "2", ""])
def test_settings_reject_invalid_tls_boolean(value: str) -> None:
    env = dict(VALID_ENV, WAC510_TLS_VERIFY=value)
    with pytest.raises(ConfigurationError, match="true or false"):
        Settings.from_env(env)


def test_ca_bundle_enables_ssl_context(tmp_path: Path) -> None:
    missing = tmp_path / "missing.pem"
    env = dict(VALID_ENV, WAC510_CA_BUNDLE=str(missing))
    with pytest.raises(ConfigurationError, match="readable file"):
        Settings.from_env(env)


def test_settings_accept_valid_website_values(tmp_path: Path) -> None:
    settings = Settings.from_values(
        url=" https://192.0.2.1/ ",
        username=" admin ",
        password="secret",
        tls_verify=False,
        timeout_seconds="12.5",
        download_directory=tmp_path,
    )
    assert settings.url == "https://192.0.2.1"
    assert settings.username == "admin"
    assert settings.timeout_seconds == 12.5
    assert settings.download_directory == tmp_path
