"""Environment-driven configuration."""

from __future__ import annotations

import os
import ssl
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from wac510_mcp.errors import ConfigurationError


def _required(environ: Mapping[str, str], name: str) -> str:
    value = environ.get(name, "").strip()
    if not value:
        raise ConfigurationError(f"{name} is required")
    return value


def _parse_bool(value: str, name: str) -> bool:
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ConfigurationError(f"{name} must be true or false")


@dataclass(frozen=True, slots=True)
class Settings:
    """Validated settings for one access point."""

    url: str
    username: str
    password: str = field(repr=False)
    tls_verify: bool = False
    ca_bundle: Path | None = None
    timeout_seconds: float = 10.0
    download_directory: Path = Path.cwd()

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> Settings:
        source = os.environ if environ is None else environ
        ca_text = source.get("WAC510_CA_BUNDLE", "").strip()
        return cls.from_values(
            url=_required(source, "WAC510_URL"),
            username=_required(source, "WAC510_USERNAME"),
            password=_required(source, "WAC510_PASSWORD"),
            tls_verify=_parse_bool(
                source.get("WAC510_TLS_VERIFY", "false"), "WAC510_TLS_VERIFY"
            ),
            ca_bundle=ca_text or None,
            timeout_seconds=source.get("WAC510_TIMEOUT_SECONDS", "10"),
            download_directory=source.get("WAC510_DOWNLOAD_DIRECTORY", "."),
        )

    @classmethod
    def from_values(
        cls,
        *,
        url: str,
        username: str,
        password: str,
        tls_verify: bool = False,
        ca_bundle: str | Path | None = None,
        timeout_seconds: str | float = 10,
        download_directory: str | Path = ".",
    ) -> Settings:
        """Validate values submitted by the setup site or another adapter."""

        url = url.strip().rstrip("/")
        parsed = urlsplit(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ConfigurationError("WAC510_URL must be an absolute HTTP or HTTPS URL")
        if parsed.username or parsed.password:
            raise ConfigurationError("WAC510_URL must not contain credentials")
        if parsed.query or parsed.fragment:
            raise ConfigurationError("WAC510_URL must not contain a query or fragment")

        username = username.strip()
        if not username:
            raise ConfigurationError("WAC510_USERNAME is required")
        if not password:
            raise ConfigurationError("WAC510_PASSWORD is required")

        try:
            timeout = float(timeout_seconds)
        except (TypeError, ValueError) as exc:
            raise ConfigurationError("WAC510_TIMEOUT_SECONDS must be a number") from exc
        if timeout <= 0:
            raise ConfigurationError("WAC510_TIMEOUT_SECONDS must be greater than zero")

        ca_path = Path(ca_bundle).expanduser() if ca_bundle else None
        if ca_path is not None and not ca_path.is_file():
            raise ConfigurationError("WAC510_CA_BUNDLE must name a readable file")

        download_path = Path(download_directory).expanduser().resolve()
        return cls(
            url=url,
            username=username,
            password=password,
            tls_verify=tls_verify,
            ca_bundle=ca_path,
            timeout_seconds=timeout,
            download_directory=download_path,
        )

    def httpx_verify(self) -> bool | ssl.SSLContext:
        if self.ca_bundle is not None:
            return ssl.create_default_context(cafile=str(self.ca_bundle))
        return self.tls_verify
